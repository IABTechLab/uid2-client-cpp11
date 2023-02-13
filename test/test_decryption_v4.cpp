#include <uid2/uid2client.h>
#include "uid2base64urlcoder.h"
#include "base64.h"
#include "key.h"
#include "keygen.h"
#include "bigendianprocessor.h"

#include <gtest/gtest.h>

#include <sstream>

using namespace uid2;

#define TO_VECTOR(d) (std::vector<std::uint8_t>(d, d + sizeof(d)))
static std::vector<std::uint8_t> GetMasterSecret();
static std::vector<std::uint8_t> GetSiteSecret();
static std::vector<std::uint8_t> MakeKeySecret(std::uint8_t v);
static std::string KeySetToJson(const std::vector<Key>& keys);
static std::vector<std::uint8_t> Base64Decode(const std::string& str);

static const std::int64_t MASTER_KEY_ID = 164;
static const std::int64_t SITE_KEY_ID = 165;
static const int SITE_ID = 9000;
static const int SITE_ID2 = 2;
static const std::uint8_t MASTER_SECRET[] = { 139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40, 91, 173, 165, 221, 168, 16, 169, 164, 38, 139, 8, 155 };
static const std::uint8_t SITE_SECRET[] = { 32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108, 51, 254, 125, 65, 24, 23, 133 };
static const Timestamp NOW = Timestamp::Now();
static const Key MASTER_KEY{MASTER_KEY_ID, -1, NOW.AddDays(-1), NOW, NOW.AddDays(1), GetMasterSecret()};
static const Key SITE_KEY{SITE_KEY_ID, SITE_ID, NOW.AddDays(-10), NOW.AddDays(-9), NOW.AddDays(1), GetSiteSecret()};
static const std::string EXAMPLE_UID = "ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM=";
static const std::string CLIENT_SECRET = "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo=";

void crossPlatformConsistencyCheck_Base64UrlTest(const std::vector<std::uint8_t>& rawInput, const std::string& expectedBase64URLStr);

// unit tests to ensure the base64url encoding and decoding are identical in all supported
// uid2 client sdks in different programming languages
TEST(CrossPlatformConsistencyCheck, Base64UrlTest)
{
    //the Base64 equivalent is "/+CI/+6ZmQ=="
    //and we want the Base64URL encoded to remove 2 '=' paddings at the back
    std::vector<std::uint8_t> case1 = { 0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99, 0x99 };
    crossPlatformConsistencyCheck_Base64UrlTest(case1, "_-CI_-6ZmQ");

    //the Base64 equivalent is "/+CI/+6ZmZk=" to remove 1 padding
    std::vector<std::uint8_t> case2 = { 0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99, 0x99, 0x99};
    crossPlatformConsistencyCheck_Base64UrlTest(case2, "_-CI_-6ZmZk");

    //the Base64 equivalent is "/+CI/+6Z" which requires no padding removal
    std::vector<std::uint8_t> case3 = { 0xff, 0xE0, 0x88, 0xFF, 0xEE, 0x99};
    crossPlatformConsistencyCheck_Base64UrlTest(case3, "_-CI_-6Z");

}

void crossPlatformConsistencyCheck_Base64UrlTest(const std::vector<std::uint8_t>& rawInput, const std::string& expectedBase64URLStr)
{
    int rawInputLen = rawInput.size();
    //the Base64 equivalent is "/+CI/+6ZmQ=="
    //and we want the Base64URL encoded to remove the '=' padding
    std::vector<std::uint8_t> payload(rawInputLen);
    BigEndianByteWriter writer(payload.data(), payload.size());
    for (int i = 0; i < rawInputLen; i++)
    {
        writer.WriteByte(rawInput[i]);
    }
    std::string base64UrlEncodedStr = uid2::UID2Base64UrlCoder::Encode(payload);
    EXPECT_EQ(expectedBase64URLStr, base64UrlEncodedStr);

    std::vector<std::uint8_t> decoded;
    uid2::UID2Base64UrlCoder::Decode(base64UrlEncodedStr, decoded);
    EXPECT_EQ(rawInputLen, decoded.size());
    for (int i = 0; i < decoded.size(); i++)
    {
        EXPECT_EQ(rawInput[i], decoded[i]);
    }
}

TEST(DecryptionTestsV4, SmokeTest)
{
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams());
	const auto res = client.Decrypt(advertisingToken, Timestamp::Now());
	EXPECT_TRUE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, res.GetStatus());
	EXPECT_EQ(EXAMPLE_UID, res.GetUid());
}

TEST(DecryptionTestsV4, EmptyKeyContainer)
{
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams());
	const auto res = client.Decrypt(advertisingToken, Timestamp::Now());
	EXPECT_FALSE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::NOT_INITIALIZED, res.GetStatus());
}

TEST(DecryptionTestsV4, ExpiredKeyContainer)
{
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams());

	const Key masterKeyExpired{MASTER_KEY_ID, -1, NOW, NOW.AddDays(-2), NOW.AddDays(-1), GetMasterSecret()};
	const Key siteKeyExpired{SITE_KEY_ID, SITE_ID, NOW, NOW.AddDays(-2), NOW.AddDays(-1), GetSiteSecret()};
	client.RefreshJson(KeySetToJson({masterKeyExpired, siteKeyExpired}));

	const auto res = client.Decrypt(advertisingToken, Timestamp::Now());
	EXPECT_FALSE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::KEYS_NOT_SYNCED, res.GetStatus());
}

TEST(DecryptionTestsV4, NotAuthorizedForKey)
{
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams());

	const Key anotherMasterKey{MASTER_KEY_ID + SITE_KEY_ID + 1, -1, NOW, NOW, NOW.AddDays(1), GetMasterSecret()};
	const Key anotherSiteKey{MASTER_KEY_ID + SITE_KEY_ID + 2, SITE_ID, NOW, NOW, NOW.AddDays(1), GetSiteSecret()};
	client.RefreshJson(KeySetToJson({anotherMasterKey, anotherSiteKey}));

	const auto res = client.Decrypt(advertisingToken, Timestamp::Now());
	EXPECT_FALSE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::NOT_AUTHORIZED_FOR_KEY, res.GetStatus());
}

TEST(DecryptionTestsV4, InvalidPayload)
{
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	std::vector<uint8_t> payload;
    uid2::UID2Base64UrlCoder::Decode(GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams()), payload);
    payload.pop_back();
    const auto advertisingToken = uid2::UID2Base64UrlCoder::Encode(payload);
    client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
    EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD, client.Decrypt(advertisingToken, NOW).GetStatus());
}

TEST(DecryptionTestsV4, TokenExpiryAndCustomNow)
{
	const Timestamp expiry = NOW.AddDays(-6);
	const auto params = EncryptTokenParams().WithTokenExpiry(expiry);

	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, params);

	auto res = client.Decrypt(advertisingToken, expiry.AddSeconds(1));
	EXPECT_FALSE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::EXPIRED_TOKEN, res.GetStatus());

	res = client.Decrypt(advertisingToken, expiry.AddSeconds(-1));
	EXPECT_TRUE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, res.GetStatus());
	EXPECT_EQ(EXAMPLE_UID, res.GetUid());
}

TEST(EncryptDataTestsV4, SiteIdFromToken)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams());
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken(advertisingToken));
	EXPECT_TRUE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto decrypted = client.DecryptData(encrypted.GetEncryptedData());
	EXPECT_TRUE(decrypted.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, decrypted.GetStatus());
	EXPECT_EQ(TO_VECTOR(data), decrypted.GetDecryptedData());
}

TEST(EncryptDataTestsV4, SiteIdFromTokenCustomSiteKeySiteId)
{
    const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
    UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
    client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
    const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID2, SITE_KEY, EncryptTokenParams());
    const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken(advertisingToken));
    EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
    const auto decrypted = client.DecryptData(encrypted.GetEncryptedData());
    EXPECT_TRUE(decrypted.IsSuccess());
    EXPECT_EQ(DecryptionStatus::SUCCESS, decrypted.GetStatus());
    EXPECT_EQ(TO_VECTOR(data), decrypted.GetDecryptedData());
}

TEST(EncryptDataTestsV4, SiteIdAndTokenSet)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams());
	EXPECT_THROW(client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken(advertisingToken).WithSiteId(SITE_ID)), std::invalid_argument);
}

TEST(EncryptDataTestsV4, TokenDecryptKeyExpired)
{
    const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
    UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
    const Key key{SITE_KEY_ID, SITE_ID2, NOW, NOW, NOW.AddDays(-1), GetSiteSecret()};
    client.RefreshJson(KeySetToJson({MASTER_KEY, key}));
    const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, key);
    const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken(advertisingToken));
    EXPECT_FALSE(encrypted.IsSuccess());
    EXPECT_EQ(EncryptionStatus::NOT_AUTHORIZED_FOR_KEY, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, TokenExpired)
{
	const Timestamp expiry = NOW.AddDays(-6);
	const auto params = EncryptTokenParams().WithTokenExpiry(expiry);

	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUid2TokenV4(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, params);
	auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken(advertisingToken));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::TOKEN_DECRYPT_FAILURE, encrypted.GetStatus());

	const auto now = expiry.AddSeconds(-1);
	encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken(advertisingToken).WithNow(now));
	EXPECT_TRUE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	const auto decrypted = client.DecryptData(encrypted.GetEncryptedData());
	EXPECT_TRUE(decrypted.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, decrypted.GetStatus());
	EXPECT_EQ(TO_VECTOR(data), decrypted.GetDecryptedData());
}

std::string KeySetToJson(const std::vector<Key>& keys)
{
	std::stringstream ss;
	ss << "{\"body\": [";
	bool needComma = false;
	for (const auto& k : keys)
	{
		if (!needComma) needComma = true;
		else ss << ", ";

		ss << "{\"id\": " << k.id
			<< ", \"site_id\": " << k.siteId
			<< ", \"created\": " << k.created.GetEpochSecond()
			<< ", \"activates\": " << k.activates.GetEpochSecond()
			<< ", \"expires\": " << k.expires.GetEpochSecond()
			<< ", \"secret\": \"" << macaron::Base64::Encode(k.secret) << "\""
			<< "}";
	}
	ss << "]}";
	return ss.str();
}

std::vector<std::uint8_t> GetMasterSecret()
{
	return std::vector<std::uint8_t>(MASTER_SECRET, MASTER_SECRET + sizeof(MASTER_SECRET));
}

std::vector<std::uint8_t> GetSiteSecret()
{
	return std::vector<std::uint8_t>(SITE_SECRET, SITE_SECRET + sizeof(SITE_SECRET));
}

std::vector<std::uint8_t> MakeKeySecret(std::uint8_t v)
{
	return std::vector<std::uint8_t>(sizeof(SITE_SECRET), v);
}

std::vector<std::uint8_t> Base64Decode(const std::string& str)
{
	std::vector<std::uint8_t> result;
	macaron::Base64::Decode(str, result);
	return result;
}
