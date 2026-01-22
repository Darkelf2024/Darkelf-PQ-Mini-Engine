#include "pqme/transport.hpp"
#include "pqme/util.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

namespace pqme {

TcpTransport::TcpTransport() = default;
TcpTransport::~TcpTransport() { close(); }

static int connect_tcp(const std::string& host, std::uint16_t port) {
  struct addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;

  struct addrinfo* res = nullptr;
  const std::string port_str = std::to_string(port);
  int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
  ensure(rc == 0 && res, "getaddrinfo failed");

  int fd = -1;
  for (auto* p = res; p; p = p->ai_next) {
    fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(res);
  ensure(fd >= 0, "TCP connect failed");
  return fd;
}

static int listen_tcp(const std::string& bind_host, std::uint16_t port) {
  struct addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE;

  struct addrinfo* res = nullptr;
  const std::string port_str = std::to_string(port);
  int rc = ::getaddrinfo(bind_host.empty() ? nullptr : bind_host.c_str(),
                         port_str.c_str(), &hints, &res);
  ensure(rc == 0 && res, "getaddrinfo(bind) failed");

  int lfd = -1;
  for (auto* p = res; p; p = p->ai_next) {
    lfd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (lfd < 0) continue;

    int yes = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (::bind(lfd, p->ai_addr, p->ai_addrlen) != 0) { ::close(lfd); lfd = -1; continue; }
    if (::listen(lfd, 16) != 0) { ::close(lfd); lfd = -1; continue; }
    break;
  }
  ::freeaddrinfo(res);
  ensure(lfd >= 0, "TCP listen failed");
  return lfd;
}

void TcpTransport::connect(const std::string& host, std::uint16_t port) {
  close();
  fd_ = connect_tcp(host, port);
}

void TcpTransport::listen_and_accept(const std::string& bind_host, std::uint16_t port) {
  close();
  listen_fd_ = listen_tcp(bind_host, port);
  int cfd = ::accept(listen_fd_, nullptr, nullptr);
  ensure(cfd >= 0, "accept failed");
  fd_ = cfd;
  ::close(listen_fd_);
  listen_fd_ = -1;
}

void TcpTransport::send_all(const std::uint8_t* data, std::size_t n) {
  ensure(fd_ >= 0, "send on closed socket");
  std::size_t off = 0;
  while (off < n) {
    ssize_t w = ::send(fd_, data + off, n - off, 0);
    ensure(w > 0, "send failed");
    off += (std::size_t)w;
  }
}

void TcpTransport::recv_all(std::uint8_t* out, std::size_t n) {
  ensure(fd_ >= 0, "recv on closed socket");
  std::size_t off = 0;
  while (off < n) {
    ssize_t r = ::recv(fd_, out + off, n - off, MSG_WAITALL);
    ensure(r > 0, "recv failed/EOF");
    off += (std::size_t)r;
  }
}

void TcpTransport::close() noexcept {
  if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
  if (listen_fd_ >= 0) { ::close(listen_fd_); listen_fd_ = -1; }
}

Socks5Transport::Socks5Transport(std::string proxy_host, std::uint16_t proxy_port)
  : proxy_host_(std::move(proxy_host)), proxy_port_(proxy_port) {}
Socks5Transport::~Socks5Transport() { close(); }

void Socks5Transport::listen_and_accept(const std::string&, std::uint16_t) {
  throw std::runtime_error("SOCKS5 transport does not support listen/accept");
}

void Socks5Transport::send_all(const std::uint8_t* data, std::size_t n) { tcp_.send_all(data, n); }
void Socks5Transport::recv_all(std::uint8_t* out, std::size_t n) { tcp_.recv_all(out, n); }
void Socks5Transport::close() noexcept { tcp_.close(); }

} // namespace pqme
