#pragma once

#include <chrono>
#include <cstdint>
#include <ostream>

namespace uid2 {
class Timestamp {
public:
    Timestamp() = default;

    static Timestamp Now();
    static Timestamp FromEpochSecond(std::int64_t epochSeconds) { return FromEpochMilli(epochSeconds * 1000); }
    static Timestamp FromEpochMilli(std::int64_t epochMilli)
    {
        return Timestamp(std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(epochMilli)));
    }

    std::int64_t GetEpochSecond() const { return std::chrono::duration_cast<std::chrono::seconds>(epoch_).count(); }
    std::int64_t GetEpochMilli() const { return std::chrono::duration_cast<std::chrono::milliseconds>(epoch_).count(); }
    bool IsZero() const { return epoch_ == std::chrono::system_clock::duration::zero(); }

    Timestamp AddSeconds(std::int64_t seconds) const { return Timestamp(std::chrono::duration_cast<Clock::duration>(epoch_ + std::chrono::seconds(seconds))); }
    Timestamp AddDays(int days) const { return AddSeconds(static_cast<std::int64_t>(days) * 24 * 60 * 60); }

    bool operator==(Timestamp other) const { return GetEpochMilli() == other.GetEpochMilli(); }
    bool operator!=(Timestamp other) const { return !operator==(other); }
    bool operator<(Timestamp other) const { return GetEpochMilli() < other.GetEpochMilli(); }
    bool operator<=(Timestamp other) const { return !other.operator<(*this); }
    bool operator>(Timestamp other) const { return other.operator<(*this); }
    bool operator>=(Timestamp other) const { return !operator<(other); }

private:
    using Clock = std::chrono::system_clock;
    explicit Timestamp(Clock::duration epoch) : epoch_(epoch) {}

    std::chrono::system_clock::duration epoch_ = {};

    friend std::ostream& operator<<(std::ostream& os, Timestamp ts) { return (os << ts.GetEpochMilli()); }
};
}  // namespace uid2
