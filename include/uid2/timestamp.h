#pragma once

#include <cstdint>
#include <ostream>

namespace uid2
{
	class Timestamp
	{
	public:
		Timestamp() {}

		static Timestamp Now();
		static Timestamp FromEpochSecond(std::int64_t epochSeconds) { return FromEpochMilli(epochSeconds * 1000); }
		static Timestamp FromEpochMilli(std::int64_t epochMilli) { return Timestamp(epochMilli); }

		std::int64_t GetEpochSecond() const { return EpochMilli / 1000; }
		std::int64_t GetEpochMilli() const { return EpochMilli; }
		bool IsZero() const { return EpochMilli == 0; }

		Timestamp AddSeconds(std::int64_t seconds) const { return Timestamp(EpochMilli + seconds * 1000); }
		Timestamp AddDays(int days) const { return AddSeconds(days * 24 * 60 * 60); }

		bool operator==(Timestamp other) const { return EpochMilli == other.EpochMilli; }
		bool operator!=(Timestamp other) const { return !operator==(other); }
		bool operator< (Timestamp other) const { return EpochMilli < other.EpochMilli; }
		bool operator<=(Timestamp other) const { return !other.operator<(*this); }
		bool operator> (Timestamp other) const { return other.operator<(*this); }
		bool operator>=(Timestamp other) const { return !operator<(other); }

	private:
		explicit Timestamp(std::int64_t epochMilli) : EpochMilli(epochMilli) {}

		std::int64_t EpochMilli = 0;

		inline friend std::ostream& operator<<(std::ostream& os, Timestamp ts) { return (os << ts.EpochMilli); }
	};
}
