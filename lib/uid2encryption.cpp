// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "uid2encryption.h"

#include "aes.h"
#include "base64.h"
#include "bigendianprocessor.h"

#include <stdexcept>
#include <unordered_map>

#include <openssl/err.h>
#include <openssl/rand.h>

namespace uid2
{
	enum
	{
		BLOCK_SIZE = 16
	};

	enum class PayloadType : std::uint8_t
	{
		ENCRYPTED_DATA = 128,
	};

	static const std::uint8_t* GenerateIv(std::uint8_t* iv);
	static std::vector<std::uint8_t> AddPadding(const std::uint8_t* data, int size);
	static void Encrypt(const std::uint8_t* data, int size, const std::uint8_t* iv, const std::uint8_t* secret, std::uint8_t* out_encrypted);
	static void Decrypt(const std::uint8_t* data, int size, const std::uint8_t* iv, const std::uint8_t* secret, std::vector<std::uint8_t>& out_decrypted);

	DecryptionResult DecryptToken(const std::string& token, const KeyContainer& keys, Timestamp now, bool checkValidity)
	{
		try
		{
			std::vector<std::uint8_t> encodedId;
			macaron::Base64::Decode(token, encodedId);
			return DecryptToken(encodedId, keys, now, checkValidity);
		}
		catch (...)
		{
			return DecryptionResult::MakeError(DecryptionStatus::INVALID_PAYLOAD);
		}
	}

	DecryptionResult DecryptToken(const std::vector<std::uint8_t>& encryptedId, const KeyContainer& keys, Timestamp now, bool checkValidity)
	{
		BigEndianByteReader reader(encryptedId);

		const int version = (int)reader.ReadByte();
		if (version != 2)
		{
			return DecryptionResult::MakeError(DecryptionStatus::VERSION_NOT_SUPPORTED);
		}

		const std::int32_t masterKeyId = reader.ReadInt32();

		const auto masterKey = keys.Get(masterKeyId);
		if (masterKey == nullptr)
		{
			return DecryptionResult::MakeError(DecryptionStatus::NOT_AUTHORIZED_FOR_KEY);
		}

		std::uint8_t iv[BLOCK_SIZE];
		reader.ReadBytes(iv, 0, sizeof(iv));

		std::vector<std::uint8_t> masterDecrypted;
		Decrypt(&encryptedId[21], encryptedId.size() - 21, iv, masterKey->secret.data(), masterDecrypted);

		BigEndianByteReader masterPayloadReader(masterDecrypted);

		const Timestamp expires = Timestamp::FromEpochMilli(masterPayloadReader.ReadInt64());
		if (checkValidity)
		{
			if (expires < now)
			{
				return DecryptionResult::MakeError(DecryptionStatus::EXPIRED_TOKEN);
			}
		}

		const int siteKeyId = masterPayloadReader.ReadInt32();
		const auto siteKey = keys.Get(siteKeyId);
		if (siteKey == nullptr)
		{
			return DecryptionResult::MakeError(DecryptionStatus::NOT_AUTHORIZED_FOR_KEY);
		}

		masterPayloadReader.ReadBytes(iv, 0, BLOCK_SIZE);
		std::vector<std::uint8_t> identityDecrypted;
		Decrypt(&masterDecrypted[28], masterDecrypted.size() - 28, iv, siteKey->secret.data(), identityDecrypted);

		BigEndianByteReader identityPayloadReader(identityDecrypted);

		const int siteId = identityPayloadReader.ReadInt32();
		const std::int32_t idLength = identityPayloadReader.ReadInt32();

		std::string idString;
		idString.resize(idLength);
		identityPayloadReader.ReadBytes((std::uint8_t*)&idString[0], 0, idLength);

		const std::int32_t privacyBits = identityPayloadReader.ReadInt32();
		const Timestamp established = Timestamp::FromEpochMilli(identityPayloadReader.ReadInt64());

		return DecryptionResult::MakeSuccess(std::move(idString), established, siteId);
	}

	EncryptionDataResult EncryptData(const EncryptionDataRequest& req, const KeyContainer* keys)
	{
		if (req.GetData() == nullptr) throw std::invalid_argument("data to encrypt must not be null");

		const auto now = req.GetNow();
		const Key* key = req.GetKey();
		int siteId = -1;
		if (key == nullptr)
		{
			if (keys == nullptr)
			{
				return EncryptionDataResult::MakeError(EncryptionStatus::NOT_INITIALIZED);
			}
			else if (!keys->IsValid(now))
			{
				return EncryptionDataResult::MakeError(EncryptionStatus::KEYS_NOT_SYNCED);
            }
			else if (req.GetSiteId() > 0 && !req.GetAdvertisingToken().empty())
			{
				throw std::invalid_argument("only one of siteId or advertisingToken can be specified");
			}
			else if (req.GetSiteId() > 0)
			{
				siteId = req.GetSiteId();
			}
			else
			{
				const auto decryptedToken = DecryptToken(req.GetAdvertisingToken(), *keys, now, true);
				if (!decryptedToken.IsSuccess())
				{
					return EncryptionDataResult::MakeError(EncryptionStatus::TOKEN_DECRYPT_FAILURE);
				}
				siteId = decryptedToken.GetSiteId();
			}

			key = keys->GetActiveSiteKey(siteId, now);
			if (key == nullptr)
			{
				return EncryptionDataResult::MakeError(EncryptionStatus::NOT_AUTHORIZED_FOR_KEY);
			}
		}
		else if (!key->IsActive(now))
		{
			return EncryptionDataResult::MakeError(EncryptionStatus::KEY_INACTIVE);
		}
		else
		{
			siteId = key->siteId;
		}

		const std::uint8_t* iv = req.GetInitializationVector();
		std::uint8_t localIv[BLOCK_SIZE];
		if (iv == nullptr)
		{
			iv = GenerateIv(localIv);
		}
		else if (req.GetInitializationVectorSize() != BLOCK_SIZE)
		{
			throw std::invalid_argument("initialization vector size must be " + std::to_string(BLOCK_SIZE));
		}

		const auto paddedData = AddPadding(req.GetData(), req.GetDataSize());
		std::vector<std::uint8_t> encryptedBuffer(paddedData.size() + 34);
		BigEndianByteWriter writer(encryptedBuffer.data(), encryptedBuffer.size());
		writer.WriteByte((std::uint8_t)PayloadType::ENCRYPTED_DATA);
		writer.WriteByte(1); // version
		writer.WriteInt64(now.GetEpochMilli());
		writer.WriteInt32(siteId);
		writer.WriteInt32(key->id);
		writer.WriteBytes(iv, 0, BLOCK_SIZE);
		Encrypt(paddedData.data(), paddedData.size(), iv, key->secret.data(), &encryptedBuffer[writer.GetPosition()]);

		return EncryptionDataResult::MakeSuccess(macaron::Base64::Encode(encryptedBuffer));
	}

    DecryptionDataResult DecryptData(const std::vector<std::uint8_t>& encryptedBytes, const KeyContainer& keys)
	{
		BigEndianByteReader reader(encryptedBytes);

		if (reader.ReadByte() != (std::uint8_t)PayloadType::ENCRYPTED_DATA)
		{
			return DecryptionDataResult::MakeError(DecryptionStatus::INVALID_PAYLOAD_TYPE);
		}
		else if (reader.ReadByte() != 1)
		{
			return DecryptionDataResult::MakeError(DecryptionStatus::VERSION_NOT_SUPPORTED);
		}

		const auto encryptedAt = Timestamp::FromEpochMilli(reader.ReadInt64());
		const int siteId = reader.ReadInt32();
		const std::int64_t keyId = reader.ReadInt32();
		const auto key = keys.Get(keyId);
		if (key == nullptr)
		{
			return DecryptionDataResult::MakeError(DecryptionStatus::NOT_AUTHORIZED_FOR_KEY);
		}

		std::uint8_t iv[BLOCK_SIZE];
		reader.ReadBytes(iv, 0, sizeof(iv));
		std::vector<std::uint8_t> decryptedBytes;
		Decrypt(&encryptedBytes[34], encryptedBytes.size() - 34, iv, key->secret.data(), decryptedBytes);

		return DecryptionDataResult::MakeSuccess(std::move(decryptedBytes), encryptedAt);
	}

	const std::uint8_t* GenerateIv(std::uint8_t* iv)
	{
		const int rc = RAND_bytes(iv, BLOCK_SIZE);
		if (rc <= 0)
		{
			throw std::runtime_error("failed to generate secure random bytes: " + std::to_string(ERR_get_error()));
		}
		return iv;
	}

	std::vector<std::uint8_t> AddPadding(const std::uint8_t* data, int size)
	{
		const int padlen = BLOCK_SIZE - (size % BLOCK_SIZE);
		std::vector<std::uint8_t> result;
		result.reserve(size + padlen);
		result.insert(result.begin(), data, data + size);
		result.insert(result.end(), (std::size_t)padlen, (std::uint8_t)padlen);
		return result;
	}

	void Encrypt(const std::uint8_t* data, int size, const std::uint8_t* iv, const std::uint8_t* secret, std::uint8_t* out_encrypted)
	{
		AES256().EncryptCBC(data, size, secret, iv, out_encrypted);
	}

	void Decrypt(const std::uint8_t* data, int size, const std::uint8_t* iv, const std::uint8_t* secret, std::vector<std::uint8_t>& out_decrypted)
	{
		AES256 aes;
		const int paddedSize = (int)aes.GetPaddingLength(size);
		if (paddedSize != size || size < 16) throw "invalid input";
		out_decrypted.resize(paddedSize);
		aes.DecryptCBC(data, size, secret, iv, &out_decrypted[0]);
		// Remove PKCS7 padding
		const int padlen = out_decrypted[size-1];
		if (padlen < 1 || padlen > 16) throw "invalid pkcs7 padding";
		out_decrypted.resize(size - padlen);
	}

}
