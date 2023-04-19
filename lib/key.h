#pragma once

#include <uid2/timestamp.h>

#include <cstdint>
#include <vector>
#include <optional>

namespace uid2
{
	struct Key
	{
		std::int64_t id;
		int siteId;
        int keysetId;
		Timestamp created;
		Timestamp activates;
		Timestamp expires;
		std::vector<std::uint8_t> secret;

		bool IsActive(Timestamp asOf) const
		{
			return activates <= asOf && asOf < expires;
		}
	};
}
