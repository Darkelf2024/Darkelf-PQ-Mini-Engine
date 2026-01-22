#include "pqme/transport.hpp"
#include "pqme/util.hpp"
#include <vector>

namespace pqme {

void Socks5Transport::connect(const std::string& host, std::uint16_t port) {
  tcp_.connect(proxy_host_, proxy_port_);

  // Greeting: VER=5, NMETHODS=1, METHODS=0x00 (no auth)
  const std::uint8_t greeting[] = {0x05, 0x01, 0x00};
  tcp_.send_all(greeting, sizeof(greeting));

  std::uint8_t choice[2];
  tcp_.recv_all(choice, 2);
  ensure(choice[0] == 0x05, "SOCKS5 bad version");
  ensure(choice[1] == 0x00, "SOCKS5 auth method unsupported");

  ensure(!host.empty() && host.size() <= 255, "SOCKS5 host invalid");

  // CONNECT request (domain)
  std::vector<std::uint8_t> req;
  req.reserve(4 + 1 + host.size() + 2);
  req.push_back(0x05); // VER
  req.push_back(0x01); // CMD=CONNECT
  req.push_back(0x00); // RSV
  req.push_back(0x03); // ATYP=DOMAIN
  req.push_back((std::uint8_t)host.size());
  req.insert(req.end(), host.begin(), host.end());
  req.push_back((std::uint8_t)((port >> 8) & 0xFF));
  req.push_back((std::uint8_t)(port & 0xFF));

  tcp_.send_all(req.data(), req.size());

  // Reply: VER REP RSV ATYP ...
  std::uint8_t rep_hdr[4];
  tcp_.recv_all(rep_hdr, 4);
  ensure(rep_hdr[0] == 0x05, "SOCKS5 reply bad version");
  ensure(rep_hdr[1] == 0x00, "SOCKS5 connect failed");

  std::uint8_t atyp = rep_hdr[3];
  if (atyp == 0x01) {
    std::uint8_t skip[4 + 2];
    tcp_.recv_all(skip, sizeof(skip));
  } else if (atyp == 0x03) {
    std::uint8_t len = 0;
    tcp_.recv_all(&len, 1);
    std::vector<std::uint8_t> skip((std::size_t)len + 2);
    tcp_.recv_all(skip.data(), skip.size());
  } else if (atyp == 0x04) {
    std::uint8_t skip[16 + 2];
    tcp_.recv_all(skip, sizeof(skip));
  } else {
    ensure(false, "SOCKS5 unknown ATYP");
  }
}

} // namespace pqme
