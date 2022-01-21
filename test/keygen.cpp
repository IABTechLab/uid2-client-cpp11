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

#include "keygen.h"

#include "aes.h"
#include "base64.h"
#include "bigendianprocessor.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <random>
#include <vector>

using namespace uid2;

static void AddPkcs7Padding(std::vector<std::uint8_t>& data)
{
	const std::uint8_t padlen = 16 - (std::uint8_t)(data.size() % 16);
	for (std::uint8_t i = 0; i < padlen; ++i) data.push_back(padlen);
}

static std::vector<std::uint8_t> EncryptImpl(std::vector<std::uint8_t>& data, const std::uint8_t* iv, const std::vector<std::uint8_t>& secret)
{
	AddPkcs7Padding(data);
	std::vector<std::uint8_t> result(16 + data.size());
	std::memcpy(result.data(), iv, 16);
	AES256 aes;
	aes.EncryptCBC(data.data(), data.size(), secret.data(), iv, result.data() + 16);
	return result;
}

std::string EncryptToken(const std::string& identity, const Key& masterKey, int siteId, const Key& siteKey, EncryptTokenParams params)
{
	std::random_device rd;
	std::vector<std::uint8_t> identityBuffer(4 + 4 + identity.size() + 4 + 8);
	BigEndianByteWriter identityWriter(identityBuffer.data(), identityBuffer.size());
	identityWriter.WriteInt32(siteId);
	identityWriter.WriteInt32(identity.size());
	identityWriter.WriteBytes((const std::uint8_t*)identity.data(), 0, identity.size());
	identityWriter.WriteInt32(0);
	identityWriter.WriteInt64(Timestamp::Now().AddSeconds(-60).GetEpochMilli());
	std::uint8_t identityIv[16];
	std::generate(identityIv, identityIv + sizeof(identityIv), std::ref(rd));
	const auto encryptedIdentity = EncryptImpl(identityBuffer, identityIv, siteKey.secret);

	std::vector<std::uint8_t> masterBuffer(8 + 4 + encryptedIdentity.size());
	BigEndianByteWriter masterWriter(masterBuffer.data(), masterBuffer.size());
	masterWriter.WriteInt64(params.tokenExpiry.GetEpochMilli());
	masterWriter.WriteInt32((std::int32_t)siteKey.id);
	masterWriter.WriteBytes(encryptedIdentity.data(), 0, encryptedIdentity.size());

	std::uint8_t masterIv[16];
	std::generate(masterIv, masterIv + sizeof(masterIv), std::ref(rd));
	const auto encryptedMaster = EncryptImpl(masterBuffer, masterIv, masterKey.secret);

	std::vector<std::uint8_t> rootBuffer(1 + 4 + encryptedMaster.size());
	BigEndianByteWriter rootWriter(rootBuffer.data(), rootBuffer.size());
	rootWriter.WriteByte(2);
	rootWriter.WriteInt32((std::int32_t)masterKey.id);
	rootWriter.WriteBytes(encryptedMaster.data(), 0, encryptedMaster.size());

	return macaron::Base64::Encode(rootBuffer);
}
