#include <uid2/uid2client.h>

#include "base64.h"
#include "key.h"
#include "keygen.h"

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

TEST(DecryptionTestsV4, SmokeTest)
{
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams(), true);
	const auto res = client.Decrypt(advertisingToken, Timestamp::Now());
	EXPECT_TRUE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, res.GetStatus());
	EXPECT_EQ(EXAMPLE_UID, res.GetUid());
}

TEST(DecryptionTestsV4, EmptyKeyContainer)
{
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams(), true);
	const auto res = client.Decrypt(advertisingToken, Timestamp::Now());
	EXPECT_FALSE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::NOT_INITIALIZED, res.GetStatus());
}

TEST(DecryptionTestsV4, ExpiredKeyContainer)
{
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams(), true);

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
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams(), true);

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
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams(), true);
	EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD, client.Decrypt(advertisingToken.substr(0, advertisingToken.size()-1), NOW).GetStatus());
	EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD, client.Decrypt(advertisingToken.substr(0, advertisingToken.size()-4), NOW).GetStatus());
	EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD, client.Decrypt(advertisingToken.substr(0, 4), NOW).GetStatus());
}

TEST(DecryptionTestsV4, TokenExpiryAndCustomNow)
{
	const Timestamp expiry = NOW.AddDays(-6);
	const auto params = EncryptTokenParams().WithTokenExpiry(expiry);

	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, params, true);

	auto res = client.Decrypt(advertisingToken, expiry.AddSeconds(1));
	EXPECT_FALSE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::EXPIRED_TOKEN, res.GetStatus());

	res = client.Decrypt(advertisingToken, expiry.AddSeconds(-1));
	EXPECT_TRUE(res.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, res.GetStatus());
	EXPECT_EQ(EXAMPLE_UID, res.GetUid());
}

TEST(EncryptDataTestsV4, SpecificKeyAndIv)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	const std::uint8_t iv[12] = {0};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(SITE_KEY).WithInitializationVector(iv, sizeof(iv)));
	EXPECT_TRUE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto decrypted = client.DecryptData(encrypted.GetEncryptedData());
	EXPECT_TRUE(decrypted.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, decrypted.GetStatus());
	EXPECT_EQ(TO_VECTOR(data), decrypted.GetDecryptedData());
}

TEST(EncryptDataTestsV4, SpecificKeyAndGeneratedIv)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(SITE_KEY));
	EXPECT_TRUE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto decrypted = client.DecryptData(encrypted.GetEncryptedData());
	EXPECT_TRUE(decrypted.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, decrypted.GetStatus());
	EXPECT_EQ(TO_VECTOR(data), decrypted.GetDecryptedData());
}

TEST(EncryptDataTestsV4, SpecificSiteId)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithSiteId(SITE_KEY.siteId));
	EXPECT_TRUE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto decrypted = client.DecryptData(encrypted.GetEncryptedData());
	EXPECT_TRUE(decrypted.IsSuccess());
	EXPECT_EQ(DecryptionStatus::SUCCESS, decrypted.GetStatus());
	EXPECT_EQ(TO_VECTOR(data), decrypted.GetDecryptedData());
}

TEST(EncryptDataTestsV4, SiteIdFromToken)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams(), true);
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
    const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID2, SITE_KEY, EncryptTokenParams(), true);
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
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, EncryptTokenParams(), true);
	EXPECT_THROW(client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken(advertisingToken).WithSiteId(SITE_ID)), std::invalid_argument);
}

TEST(EncryptDataTestsV4, MultipleSiteKeys)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const std::vector<Key> keys = {
		Key{0, SITE_ID, NOW, NOW.AddDays(3), NOW.AddDays(10), MakeKeySecret(0)},
		Key{1, SITE_ID, NOW, NOW.AddDays(-4), NOW.AddDays(10), MakeKeySecret(1)},
		Key{2, SITE_ID, NOW, NOW.AddDays(-2), NOW.AddDays(10), MakeKeySecret(2)},
		Key{3, SITE_ID, NOW, NOW.AddDays(-4), NOW.AddDays(-3), MakeKeySecret(3)},
		Key{4, SITE_ID, NOW, NOW.AddDays(-4), NOW.AddDays(1), MakeKeySecret(4)},
		Key{5, SITE_ID, NOW, NOW.AddDays(-5), NOW.AddDays(2), MakeKeySecret(5)},
		Key{6, SITE_ID, NOW, NOW.AddDays(-1), NOW.AddDays(2), MakeKeySecret(6)}
	};

	const auto checkSiteKey = [&](Timestamp now, const Key& expectedSiteKey)
	{
		client.RefreshJson(KeySetToJson(keys));
		const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithSiteId(SITE_ID).WithNow(now));
		EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
		client.RefreshJson(KeySetToJson({expectedSiteKey}));
		const auto decrypted = client.DecryptData(encrypted.GetEncryptedData());
		EXPECT_EQ(DecryptionStatus::SUCCESS, decrypted.GetStatus());
		EXPECT_EQ(TO_VECTOR(data), decrypted.GetDecryptedData());
	};

	checkSiteKey(NOW.AddDays(-5), keys[5]);
	checkSiteKey(NOW.AddDays(-4), keys[4]);
	checkSiteKey(NOW.AddDays(-3), keys[4]);
	checkSiteKey(NOW.AddDays(-2), keys[2]);
	checkSiteKey(NOW.AddDays(-1), keys[6]);
	checkSiteKey(NOW.AddDays( 0), keys[6]);
	checkSiteKey(NOW.AddDays( 1), keys[6]);
	checkSiteKey(NOW.AddDays( 2), keys[2]);
	checkSiteKey(NOW.AddDays( 3), keys[0]);
}

TEST(EncryptDataTestsV4, TokenDecryptFailed)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken("bogus-token"));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::TOKEN_DECRYPT_FAILURE, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, KeyExpired)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const Key key{SITE_KEY_ID, SITE_ID, NOW, NOW, NOW.AddDays(-1), GetSiteSecret()};
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(key));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::KEY_INACTIVE, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, TokenDecryptKeyExpired)
{
    const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
    UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
    const Key key{SITE_KEY_ID, SITE_ID2, NOW, NOW, NOW.AddDays(-1), GetSiteSecret()};
    client.RefreshJson(KeySetToJson({MASTER_KEY, key}));
    const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, key);
    const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithAdvertisingToken(advertisingToken));
    EXPECT_FALSE(encrypted.IsSuccess());
    EXPECT_EQ(EncryptionStatus::NOT_AUTHORIZED_FOR_KEY, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, KeyInactive)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const Key key{SITE_KEY_ID, SITE_ID, NOW, NOW.AddDays(1), NOW.AddDays(2), GetSiteSecret()};
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(key));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::KEY_INACTIVE, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, KeyExpiredCustomNow)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(SITE_KEY).WithNow(SITE_KEY.expires));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::KEY_INACTIVE, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, KeyInactiveCustomNow)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(SITE_KEY).WithNow(SITE_KEY.activates.AddSeconds(-1)));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::KEY_INACTIVE, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, NoSiteKey)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithSiteId(SITE_ID2));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::NOT_AUTHORIZED_FOR_KEY, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, SiteKeyExpired)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	auto key = SITE_KEY;
	key.expires = NOW.AddDays(-1);
	client.RefreshJson(KeySetToJson({MASTER_KEY, key}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithSiteId(key.siteId));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::NOT_AUTHORIZED_FOR_KEY, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, SiteKeyInactive)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	auto key = SITE_KEY;
	key.activates = NOW.AddDays(1);
	client.RefreshJson(KeySetToJson({MASTER_KEY, key}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithSiteId(key.siteId));
	EXPECT_FALSE(encrypted.IsSuccess());
	EXPECT_EQ(EncryptionStatus::NOT_AUTHORIZED_FOR_KEY, encrypted.GetStatus());
}

TEST(EncryptDataTestsV4, SiteKeyInactiveCustomNow)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({MASTER_KEY, SITE_KEY}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithSiteId(SITE_KEY.siteId).WithNow(SITE_KEY.activates.AddSeconds(-1)));
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
	const auto advertisingToken = GenerateUID2TokenWithDebugInfo(EXAMPLE_UID, MASTER_KEY, SITE_ID, SITE_KEY, params);
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

TEST(DecryptDataTestsV4, BadPayloadType)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(SITE_KEY));
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	auto encryptedBytes = Base64Decode(encrypted.GetEncryptedData());
	encryptedBytes[0] = 0;
	const auto decrypted = client.DecryptData(macaron::Base64::Encode(encryptedBytes));
	EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD_TYPE, decrypted.GetStatus());
}

TEST(DecryptDataTestsV4, BadVersion)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(SITE_KEY));
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	auto encryptedBytes = Base64Decode(encrypted.GetEncryptedData());
	encryptedBytes[1] = 0;
	const auto decrypted = client.DecryptData(macaron::Base64::Encode(encryptedBytes));
	EXPECT_EQ(DecryptionStatus::VERSION_NOT_SUPPORTED, decrypted.GetStatus());
}

TEST(DecryptDataTestsV4, BadPayload)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(SITE_KEY));
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	const auto encryptedBytes = Base64Decode(encrypted.GetEncryptedData());

	auto encryptedBytesLarger = encryptedBytes;
	encryptedBytesLarger.push_back(1);
	auto decrypted = client.DecryptData(macaron::Base64::Encode(encryptedBytesLarger));
	EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD, decrypted.GetStatus());

	auto encryptedBytesSmaller = encryptedBytes;
	encryptedBytesSmaller.pop_back();
	decrypted = client.DecryptData(macaron::Base64::Encode(encryptedBytesSmaller));
	EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD, decrypted.GetStatus());

	decrypted = client.DecryptData(encrypted.GetEncryptedData().substr(0, 4));
	EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD, decrypted.GetStatus());

	decrypted = client.DecryptData(encrypted.GetEncryptedData() + "0");
	EXPECT_EQ(DecryptionStatus::INVALID_PAYLOAD, decrypted.GetStatus());
}

TEST(DecryptDataTestsV4, NoDecryptionKey)
{
	const std::uint8_t data[] = {1, 2, 3, 4, 5, 6};
	UID2Client client("ep", "ak", CLIENT_SECRET, IdentityScope::UID2);
	client.RefreshJson(KeySetToJson({SITE_KEY}));
	const auto encrypted = client.EncryptData(EncryptionDataRequest(data, sizeof(data)).WithKey(SITE_KEY));
	EXPECT_EQ(EncryptionStatus::SUCCESS, encrypted.GetStatus());
	client.RefreshJson(KeySetToJson({MASTER_KEY}));
	const auto decrypted = client.DecryptData(encrypted.GetEncryptedData());
	EXPECT_EQ(DecryptionStatus::NOT_AUTHORIZED_FOR_KEY, decrypted.GetStatus());
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
