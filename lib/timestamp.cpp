#include <uid2/timestamp.h>

#include <chrono>

namespace uid2 {
Timestamp Timestamp::Now()
{
    return Timestamp(Clock::now().time_since_epoch());
}
}  // namespace uid2
