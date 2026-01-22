#pragma once
#include "pqme.hpp"
#include <string>
#include <cstddef>
#include <cstdint>

namespace pqme {

struct SecureBytes {
  Bytes b;
  SecureBytes() = default;
  explicit SecureBytes(std::size_t n);
  ~SecureBytes();
  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;
  SecureBytes(SecureBytes&&) noexcept;
  SecureBytes& operator=(SecureBytes&&) noexcept;
};

void secure_bzero(void* p, std::size_t n);
void ensure(bool ok, const char* msg);

void rand_bytes(std::uint8_t* out, std::size_t n);

Bytes sha256(const Bytes& data);

Bytes hkdf_extract_sha256(const Bytes& salt, const Bytes& ikm);
Bytes hkdf_expand_sha256(const Bytes& prk, const std::string& info, std::size_t out_len);

bool read_file(const std::string& path, Bytes& out);
bool write_file(const std::string& path, const Bytes& data);

} // namespace pqme
