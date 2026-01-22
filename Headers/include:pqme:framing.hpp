#pragma once
#include "pqme.hpp"
#include <cstdint>

namespace pqme {

// Length-prefix framing (u32 big-endian)
static constexpr std::uint32_t kMaxFrameSize = 16 * 1024 * 1024;

class ITransport;

// Sends one message: [u32_be len][bytes...]
void send_msg(ITransport& t, const Bytes& msg);

// Receives one message
Bytes recv_msg(ITransport& t);

} // namespace pqme
