#pragma once
#include "pqme.hpp"
#include <cstdint>
#include <string>
#include <cstddef>

namespace pqme {

class ITransport {
public:
  virtual ~ITransport() = default;

  // Client-side connect
  virtual void connect(const std::string& host, std::uint16_t port) = 0;

  // Server-side: bind/listen/accept one client
  virtual void listen_and_accept(const std::string& bind_host, std::uint16_t port) = 0;

  // Blocking exact send/recv
  virtual void send_all(const std::uint8_t* data, std::size_t n) = 0;
  virtual void recv_all(std::uint8_t* out, std::size_t n) = 0;

  virtual void close() noexcept = 0;
};

// POSIX TCP transport (Linux/macOS)
class TcpTransport final : public ITransport {
public:
  TcpTransport();
  ~TcpTransport() override;

  void connect(const std::string& host, std::uint16_t port) override;
  void listen_and_accept(const std::string& bind_host, std::uint16_t port) override;

  void send_all(const std::uint8_t* data, std::size_t n) override;
  void recv_all(std::uint8_t* out, std::size_t n) override;

  void close() noexcept override;

private:
  int fd_{-1};
  int listen_fd_{-1};
};

// SOCKS5 CONNECT wrapper (Tor). Client-only.
class Socks5Transport final : public ITransport {
public:
  Socks5Transport(std::string proxy_host, std::uint16_t proxy_port);
  ~Socks5Transport() override;

  void connect(const std::string& host, std::uint16_t port) override;

  void listen_and_accept(const std::string&, std::uint16_t) override;

  void send_all(const std::uint8_t* data, std::size_t n) override;
  void recv_all(std::uint8_t* out, std::size_t n) override;

  void close() noexcept override;

private:
  TcpTransport tcp_;
  std::string proxy_host_;
  std::uint16_t proxy_port_;
};

} // namespace pqme
