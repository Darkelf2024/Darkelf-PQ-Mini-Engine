#include "pqme/util.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <fstream>
#include <stdexcept>

namespace pqme {

void secure_bzero(void* p, std::size_t n) {
  if (p && n) OPENSSL_cleanse(p, n);
}

void ensure(bool ok, const char* msg) {
  if (!ok) throw std::runtime_error(msg);
}

SecureBytes::SecureBytes(std::size_t n) : b(n) {}
SecureBytes::~SecureBytes() { secure_bzero(b.data(), b.size()); }
SecureBytes::SecureBytes(SecureBytes&& o) noexcept : b(std::move(o.b)) {}
SecureBytes& SecureBytes::operator=(SecureBytes&& o) noexcept {
  if (this != &o) {
    secure_bzero(b.data(), b.size());
    b = std::move(o.b);
  }
  return *this;
}

void rand_bytes(std::uint8_t* out, std::size_t n) {
  ensure(RAND_bytes(out, (int)n) == 1, "RAND_bytes failed");
}

Bytes sha256(const Bytes& data) {
  Bytes out(32);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  ensure(ctx != nullptr, "EVP_MD_CTX_new failed");
  unsigned int len = 0;
  ensure(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1, "DigestInit failed");
  ensure(EVP_DigestUpdate(ctx, data.data(), data.size()) == 1, "DigestUpdate failed");
  ensure(EVP_DigestFinal_ex(ctx, out.data(), &len) == 1, "DigestFinal failed");
  EVP_MD_CTX_free(ctx);
  ensure(len == 32, "sha256 length mismatch");
  return out;
}

Bytes hkdf_extract_sha256(const Bytes& salt, const Bytes& ikm) {
  Bytes prk(32);
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  ensure(pctx != nullptr, "HKDF ctx alloc failed");
  ensure(EVP_PKEY_derive_init(pctx) == 1, "HKDF derive_init failed");
  ensure(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1, "HKDF set md failed");
  ensure(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int)salt.size()) == 1, "HKDF set salt failed");
  ensure(EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size()) == 1, "HKDF set ikm failed");

  size_t outlen = prk.size();
  ensure(EVP_PKEY_derive(pctx, prk.data(), &outlen) == 1, "HKDF extract derive failed");
  EVP_PKEY_CTX_free(pctx);
  ensure(outlen == prk.size(), "HKDF extract length mismatch");
  return prk;
}

Bytes hkdf_expand_sha256(const Bytes& prk, const std::string& info, std::size_t out_len) {
  Bytes out(out_len);
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  ensure(pctx != nullptr, "HKDF ctx alloc failed");
  ensure(EVP_PKEY_derive_init(pctx) == 1, "HKDF derive_init failed");
  ensure(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) == 1, "HKDF set md failed");
  ensure(EVP_PKEY_CTX_set1_hkdf_key(pctx, prk.data(), (int)prk.size()) == 1, "HKDF set prk failed");
  ensure(EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size()) == 1, "HKDF set info failed");

  size_t len = out.size();
  ensure(EVP_PKEY_derive(pctx, out.data(), &len) == 1, "HKDF expand derive failed");
  EVP_PKEY_CTX_free(pctx);
  ensure(len == out.size(), "HKDF expand length mismatch");
  return out;
}

bool read_file(const std::string& path, Bytes& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  f.seekg(0, std::ios::end);
  std::streamsize n = f.tellg();
  if (n < 0) return false;
  f.seekg(0, std::ios::beg);
  out.resize((std::size_t)n);
  if (n > 0) f.read((char*)out.data(), n);
  return (bool)f;
}

bool write_file(const std::string& path, const Bytes& data) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) return false;
  if (!data.empty()) f.write((const char*)data.data(), (std::streamsize)data.size());
  return (bool)f;
}

} // namespace pqme
