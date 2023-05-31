#pragma once

#include "uid2/types.h"

#include "key.h"

#include <string>

namespace uid2 {

    struct EncryptTokenParams {
        EncryptTokenParams() = default;

        EncryptTokenParams &WithTokenExpiry(uid2::Timestamp expiry) {
            tokenExpiry = expiry;
            return *this;
        }

        uid2::Timestamp tokenExpiry = uid2::Timestamp::Now().AddSeconds(60);
        uid2::IdentityScope identityScope = uid2::IdentityScope::UID2;
    };

    std::string
    GenerateUid2TokenV2(const std::string &identity, const uid2::Key &masterKey, int siteId, const uid2::Key &siteKey,
                        EncryptTokenParams params = EncryptTokenParams());

    std::string
    GenerateUid2TokenV3(const std::string &identity, const uid2::Key &masterKey, int siteId, const uid2::Key &siteKey,
                        EncryptTokenParams params = EncryptTokenParams());

    std::string
    GenerateUid2TokenV4(const std::string &identity, const uid2::Key &masterKey, int siteId, const uid2::Key &siteKey,
                        EncryptTokenParams params = EncryptTokenParams());

    std::string GenerateUID2TokenWithDebugInfo(const std::string &uid, const uid2::Key &masterKey, int siteId,
                                               const uid2::Key &siteKey, EncryptTokenParams params,
                                               uid2::AdvertisingTokenVersion adTokenVersion);

    std::string
    EncryptDataV2(const std::vector<std::uint8_t> &data, const uid2::Key &key, int siteId, uid2::Timestamp now);

}
