#pragma once

#include <uid2/timestamp.h>

#include <cstdint>
#include <string>
#include <vector>

namespace uid2
{
	struct Key;

    enum class IdentityScope
    {
        UID2 = 0,
        EUID = 1,
    };

    enum class IdentityType
    {
        Email = 0,
        Phone = 1,
    };

    enum class AdvertisingTokenVersion
    {
        //showing as "AHA..." in the Base64 Encoding (Base64 'H' is 000111 and 112 is 01110000)
        V3 = 112,
        //showing as "AIA..." in the Base64URL Encoding ('H' is followed by 'I' hence
        //this choice for the next token version) (Base64 'I' is 001000 and 128 is 10000000)
        V4 = 128,
    };

	enum class DecryptionStatus
	{
		SUCCESS,
		NOT_AUTHORIZED_FOR_KEY,
		NOT_INITIALIZED,
		INVALID_PAYLOAD,
		EXPIRED_TOKEN,
		KEYS_NOT_SYNCED,
		VERSION_NOT_SUPPORTED,
		INVALID_PAYLOAD_TYPE,
        INVALID_IDENTITY_SCOPE,
	};

	enum class EncryptionStatus
	{
		SUCCESS,
		NOT_AUTHORIZED_FOR_KEY,
		NOT_INITIALIZED,
		KEYS_NOT_SYNCED,
		TOKEN_DECRYPT_FAILURE,
		KEY_INACTIVE,
		ENCRYPTION_FAILURE,
	};

	class RefreshResult
	{
	public:
		static RefreshResult MakeSuccess() { return RefreshResult(true, std::string()); }
		static RefreshResult MakeError(std::string&& reason) { return RefreshResult(false, std::move(reason)); }

		bool IsSuccess() const { return Success; }
		const std::string& GetReason() const { return Reason; }

	private:
		RefreshResult(bool success, std::string&& reason)
			: Success(success), Reason(reason) {}

		bool Success;
		std::string Reason;
	};

	class DecryptionResult
	{
	public:
		static DecryptionResult MakeSuccess(std::string&& identity, Timestamp established, int siteId, int siteKeySiteId)
		{
			return DecryptionResult(DecryptionStatus::SUCCESS, std::move(identity), established, siteId, siteKeySiteId);
		}
		static DecryptionResult MakeError(DecryptionStatus status)
		{
			return DecryptionResult(status, std::string(), Timestamp(), -1, -1);
		}
        static DecryptionResult MakeError(DecryptionStatus status, Timestamp established, int siteId, int siteKeySiteId)
        {
            return DecryptionResult(status, std::string(), established, siteId, siteKeySiteId);
        }

		bool IsSuccess() const { return Status == DecryptionStatus::SUCCESS; }
		DecryptionStatus GetStatus() const { return Status; }
		const std::string& GetUid() const { return Identity; }
		Timestamp GetEstablished() const { return Established; }
		int GetSiteId() const { return SiteId; }
        int GetSiteKeySiteId() const { return SiteKeySiteId; }

	private:
		DecryptionResult(DecryptionStatus status, std::string&& identity, Timestamp established, int siteId, int siteKeySiteId)
			: Status(status), Identity(std::move(identity)), Established(established), SiteId(siteId), SiteKeySiteId(siteKeySiteId) {}

		DecryptionStatus Status;
		std::string Identity;
		Timestamp Established;
		int SiteId;
        int SiteKeySiteId;
	};

	class EncryptionDataRequest
	{
	public:
		EncryptionDataRequest() = default;
		EncryptionDataRequest(const std::uint8_t* data, std::size_t size) : Data(data), DataSize(size) {}

		EncryptionDataRequest& WithSiteId(int siteId) { SiteId = siteId; return *this; }
		EncryptionDataRequest& WithKey(const Key& key) { ExplicitKey = &key; return *this; }
		template<typename T>
		EncryptionDataRequest& WithAdvertisingToken(T&& token) { AdvertisingToken = std::forward<T>(token); return *this; }
		EncryptionDataRequest& WithInitializationVector(const std::uint8_t* iv, std::size_t size) { InitializationVector = iv; InitializationVectorSize = size; return *this; }
		EncryptionDataRequest& WithNow(Timestamp now) { Now = now; return *this; }

		const std::uint8_t* GetData() const { return Data; }
		std::size_t GetDataSize() const { return DataSize; }
		int GetSiteId() const { return SiteId; }
		const Key* GetKey() const { return ExplicitKey; }
		const std::string& GetAdvertisingToken() const { return AdvertisingToken; }
		const std::uint8_t* GetInitializationVector() const { return InitializationVector; }
		std::size_t GetInitializationVectorSize() const { return InitializationVectorSize; }
		Timestamp GetNow() const { return Now.IsZero() ? Timestamp::Now() : Now; }

	private:
		const std::uint8_t* Data = nullptr;
		std::size_t DataSize = 0;
		int SiteId = 0;
		const Key* ExplicitKey = nullptr;
		std::string AdvertisingToken;
		const std::uint8_t* InitializationVector = nullptr;
		std::size_t InitializationVectorSize = 0;
		Timestamp Now;
	};

	class EncryptionDataResult
	{
	public:
		static EncryptionDataResult MakeSuccess(std::string&& encryptedData)
		{
			return EncryptionDataResult(EncryptionStatus::SUCCESS, std::move(encryptedData));
		}
		static EncryptionDataResult MakeError(EncryptionStatus status)
		{
			return EncryptionDataResult(status, std::string());
		}

		bool IsSuccess() const { return Status == EncryptionStatus::SUCCESS; }
		EncryptionStatus GetStatus() const { return Status; }
		const std::string& GetEncryptedData() const { return EncryptedData; }

	private:
		EncryptionDataResult(EncryptionStatus status, std::string&& encryptedData)
			: Status(status), EncryptedData(std::move(encryptedData)) {}

		EncryptionStatus Status;
		std::string EncryptedData;
	};

	class DecryptionDataResult
	{
	public:
		static DecryptionDataResult MakeSuccess(std::vector<std::uint8_t>&& decryptedData, Timestamp encryptedAt)
		{
			return DecryptionDataResult(DecryptionStatus::SUCCESS, std::move(decryptedData), encryptedAt);
		}
		static DecryptionDataResult MakeError(DecryptionStatus status)
		{
			return DecryptionDataResult(status, {}, Timestamp());
		}

		bool IsSuccess() const { return Status == DecryptionStatus::SUCCESS; }
		DecryptionStatus GetStatus() const { return Status; }
		const std::vector<std::uint8_t> GetDecryptedData() const { return DecryptedData; }
		Timestamp GetEncryptedAt() const { return EncryptedAt; }

	private:
		DecryptionDataResult(DecryptionStatus status, std::vector<std::uint8_t>&& data, Timestamp encryptedAt)
			: Status(status), DecryptedData(std::move(data)), EncryptedAt(encryptedAt) {}

		DecryptionStatus Status;
		std::vector<std::uint8_t> DecryptedData;
		Timestamp EncryptedAt;
	};
}
