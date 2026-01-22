#include "pqme/framing.hpp"
#include "pqme/transport.hpp"
#include "pqme/util.hpp"
#include <cstring>

namespace pqme {

static void write_u32_be(std::uint8_t out[4], std::uint32_t v) {
  out[0] = (v >> 24) & 0xFF;
  out[1] = (v >> 16) & 0xFF;
  out[2] = (v >> 8) & 0xFF;
  out[3] = (v) & 0xFF;
}
static std::uint32_t read_u32_be(const std::uint8_t in[4]) {
  return ((std::uint32_t)in[0] << 24) |
         ((std::uint32_t)in[1] << 16) |
         ((std::uint32_t)in[2] << 8)  |
         ((std::uint32_t)in[3]);
}

void send_msg(ITransport& t, const Bytes& msg) {
  ensure(msg.size() <= kMaxFrameSize, "frame too large");
  std::uint8_t hdr[4];
  write_u32_be(hdr, (std::uint32_t)msg.size());
  t.send_all(hdr, 4);
  if (!msg.empty()) t.send_all(msg.data(), msg.size());
}

Bytes recv_msg(ITransport& t) {
  std::uint8_t hdr[4];
  t.recv_all(hdr, 4);
  std::uint32_t n = read_u32_be(hdr);
  ensure(n <= kMaxFrameSize, "incoming frame too large");
  Bytes msg(n);
  if (n) t.recv_all(msg.data(), n);
  return msg;
}

} // namespace pqme
