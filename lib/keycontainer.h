#pragma once

#include "key.h"

#include <algorithm>
#include <unordered_map>
#include <vector>

namespace uid2
{
	class KeyContainer
	{
	public:
		KeyContainer() = default;

		void Add(Key&& key)
		{
			auto& k = idMap[key.id];
			k = std::move(key);
			if (k.siteId > 0)
				keysBySite[k.siteId].push_back(&k);
			if (latestKeyExpiry < k.expires)
				latestKeyExpiry = k.expires;
		}

		void Sort()
		{
			const auto end = keysBySite.end();
			for (auto it = keysBySite.begin(); it != end; ++it)
			{
				auto& siteKeys = it->second;
				std::sort(siteKeys.begin(), siteKeys.end(), [](const Key* a, const Key* b) { return a->activates < b->activates; });
			}
		}

		const Key* Get(std::int64_t id) const
		{
			const auto it = idMap.find(id);
			return it == idMap.end() ? nullptr : &it->second;
		}

		const Key* GetActiveSiteKey(int siteId, Timestamp now) const
		{
			const auto itK = keysBySite.find(siteId);
			if (itK == keysBySite.end() || itK->second.empty()) return nullptr;
			const auto& siteKeys = itK->second;
			auto it = std::upper_bound(siteKeys.begin(), siteKeys.end(), now,
				[](Timestamp ts, const Key* k) { return ts < k->activates; });
			while (it != siteKeys.begin())
			{
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

	private:
		std::unordered_map<std::int64_t, Key> idMap;
		std::unordered_map<int, std::vector<const Key*>> keysBySite;
		Timestamp latestKeyExpiry;

	private:
		KeyContainer(const KeyContainer&) = delete;
		KeyContainer& operator=(const KeyContainer&) = delete;
	};
}
