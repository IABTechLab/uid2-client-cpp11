#pragma once

#include "key.h"

#include <algorithm>
#include <unordered_map>
#include <vector>

namespace uid2 {
    class KeyContainer
    {
    public:
        KeyContainer() = default;

        KeyContainer(int _callerSiteId, int _masterKeysetId, int _defaultKeysetId, long _tokenExpirySeconds)
        {
            callerSiteId = _callerSiteId;
            masterKeySetId = _masterKeysetId;
            defaultKeySetId = _defaultKeysetId;
            tokenExpirySeconds = _tokenExpirySeconds;
        }

        void Add(Key &&key)
        {
            auto &k = idMap[key.id];
            k = std::move(key);
            if (k.siteId > 0)
                keysBySite[k.siteId].push_back(&k);
            if (k.keysetId != NO_KEYSET)
                keysByKeyset[k.keysetId].push_back(&k);
            if (latestKeyExpiry < k.expires)
                latestKeyExpiry = k.expires;
        }

        void Sort()
        {
            const auto end = keysBySite.end();
            for (auto it = keysBySite.begin(); it != end; ++it) {
                auto &siteKeys = it->second;
                std::sort(siteKeys.begin(), siteKeys.end(),
                          [](const Key *a, const Key *b) { return a->activates < b->activates; });
            }
        }

        const Key *Get(std::int64_t id) const
        {
            const auto it = idMap.find(id);
            return it == idMap.end() ? nullptr : &it->second;
        }


        const Key *GetActiveSiteKey(int siteId, Timestamp now) const
        {
            const auto itK = keysBySite.find(siteId);
            if (itK == keysBySite.end() || itK->second.empty()) return nullptr;
            const auto &siteKeys = itK->second;
            auto it = std::upper_bound(siteKeys.begin(), siteKeys.end(), now,
                                       [](Timestamp ts, const Key *k) { return ts < k->activates; });
            while (it != siteKeys.begin()) {
                --it;
                const auto key = *it;
                if (key->IsActive(now)) return key;
            }
            return nullptr;
        }

        const Key *GetActiveKeysetKey(int keysetId, Timestamp now) const
        {
            const auto itK = keysByKeyset.find(keysetId);
            if (itK == keysByKeyset.end() || itK->second.empty()) return nullptr;
            const auto &siteKeys = itK->second;
            auto it = std::upper_bound(siteKeys.begin(), siteKeys.end(), now,
                                       [](Timestamp ts, const Key *k) { return ts < k->activates; });
            while (it != siteKeys.begin()) {
                --it;
                const auto key = *it;
                if (key->IsActive(now)) return key;
            }
            return nullptr;

        }

        inline bool IsValid(Timestamp now) const
        {
            return latestKeyExpiry > now;
        }

        int getCallerSiteId() const
        {
            return callerSiteId;
        }

        void setCallerSiteId(int callerSiteId)
        {
            KeyContainer::callerSiteId = callerSiteId;
        }

        int getMasterKeySetId() const
        {
            return masterKeySetId;
        }

        const Key *getMasterKey(Timestamp now) const
        {
            return GetActiveKeysetKey(masterKeySetId, now);
        }

        void setMasterKeySetId(int masterKeySetId)
        {
            KeyContainer::masterKeySetId = masterKeySetId;
        }

        int getDefaultKeySetId() const
        {
            return defaultKeySetId;
        }

        void setDefaultKeySetId(int defaultKeySetId)
        {
            KeyContainer::defaultKeySetId = defaultKeySetId;
        }

        const Key *getDefaultKey(Timestamp now) const
        {
            return GetActiveKeysetKey(defaultKeySetId, now);
        }


        int getTokenExpirySeconds() const
        {
            return tokenExpirySeconds;
        }

        void setTokenExpirySeconds(int64_t tokenExpirySeconds)
        {
            KeyContainer::tokenExpirySeconds = tokenExpirySeconds;
        }

    private:
        std::unordered_map<std::int64_t, Key> idMap;
        std::unordered_map<int, std::vector<const Key *>> keysBySite;
        std::unordered_map<int, std::vector<const Key *>> keysByKeyset;
        Timestamp latestKeyExpiry;
        int callerSiteId = -1;
        int masterKeySetId = -1;
        int defaultKeySetId = -1;
        int64_t tokenExpirySeconds = -1;

    private:
        KeyContainer(const KeyContainer &) = delete;

        KeyContainer &operator=(const KeyContainer &) = delete;
    };
}
