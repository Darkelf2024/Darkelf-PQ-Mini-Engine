#pragma once
#include "pqme.hpp"
#include "util.hpp"
#include <array>
#include <string>
#include <cstdint>

namespace pqme {

static constexpr std::size_t kNonceLen = 32;
static constexpr std::size_t kKeyLen = 32;        // AES-256
static constexpr std::size_t kAeadNonceLen = 12;  // GCM nonce
static constexpr std::size_t kTagLen = 16;

enum class MsgType : std::uint8_t {
  ClientHello = 1,
  ServerHello = 2,
  ClientKey   = 3,
  AppData     = 4
};

struct ServerIdentity {
  std::string sig_alg;
  Bytes sig_pk;
  SecureBytes sig_sk;
};

ServerIdentity generate_server_identity(const std::string& sig_alg);

struct ClientHello {
  std::array<std::uint8_t, kNonceLen> client_nonce{};
  Bytes serialize() const;
  static ClientHello parse(const Bytes& in);
};

struct ServerHello {
  std::array<std::uint8_t, kNonceLen> server_nonce{};
  std::string kem_alg;
  std::string sig_alg;
  Bytes kem_pk;
  Bytes signature;

  Bytes serialize(bool include_signature = true) const;
  static ServerHello parse(const Bytes& in);
};

struct ClientKey {
  Bytes kem_ct;
  Bytes serialize() const;
  static ClientKey parse(const Bytes& in);
};

struct TrafficKeys {
  std::array<std::uint8_t, kKeyLen> c2s_key{};
  std::array<std::uint8_t, kKeyLen> s2c_key{};
  std::array<std::uint8_t, kAeadNonceLen> c2s_base_nonce{};
  std::array<std::uint8_t, kAeadNonceLen> s2c_base_nonce{};
};

class Session {
public:
  enum class Role { Client, Server };

  Session() = default;
  Session(Role r, TrafficKeys tk);

  // Returns a full AppData record (header + ciphertext)
  Bytes encrypt_record(const Bytes& plaintext);

  // Takes a full AppData record and returns plaintext
  Bytes decrypt_record(const Bytes& record);

private:
  Role role_{Role::Client};
  TrafficKeys keys_{};
  std::uint64_t next_send_seq_{0};
  std::uint64_t next_recv_seq_{0};

  const std::array<std::uint8_t, kKeyLen>& send_key() const;
  const std::array<std::uint8_t, kKeyLen>& recv_key() const;
  const std::array<std::uint8_t, kAeadNonceLen>& send_base_nonce() const;
  const std::array<std::uint8_t, kAeadNonceLen>& recv_base_nonce() const;
};

ClientHello make_client_hello();

struct ServerHandshakeState {
  ClientHello ch;
  Bytes ch_wire;

  ServerHello sh;
  Bytes sh_wire;

  Bytes transcript_hash;

  SecureBytes ephemeral_kem_sk; // stored for finalize
  Session session;
};

ServerHandshakeState server_start(const Bytes& client_hello_wire,
                                  const ServerIdentity& server_id,
                                  const std::string& kem_alg);

Session server_finalize(ServerHandshakeState& st, const Bytes& client_key_wire);

struct ClientHandshakeResult {
  ClientHello ch;
  ServerHello sh;
  ClientKey ck;
  Session session;
};

ClientHandshakeResult client_handshake(const std::string& kem_alg,
                                       const std::string& sig_alg_expected,
                                       const Bytes& pinned_server_sig_pk,
                                       const Bytes& server_hello_wire,
                                       const Bytes& client_hello_wire);

} // namespace pqme
