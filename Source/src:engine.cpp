// Darkelf PQ Mini Engine
// Author: Darkelf
//
// Post-quantum secure channel (reference implementation)
// Dependencies: liboqs, OpenSSL (libcrypto)
//
// IMPORTANT: This is NOT audited and is not a TLS replacement.
// Use at your own risk.

#include "pqme/engine.hpp"
#include "pqme/util.hpp"

#include <oqs/oqs.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pqme {

// ------------------------------ Parsing utils ------------------------------

static void append_u16(Bytes& out, std::uint16_t v) {
  out.push_back((std::uint8_t)((v >> 8) & 0xFF));
  out.push_back((std::uint8_t)(v & 0xFF));
}
static void append_u32(Bytes& out, std::uint32_t v) {
  out.push_back((std::uint8_t)((v >> 24) & 0xFF));
  out.push_back((std::uint8_t)((v >> 16) & 0xFF));
  out.push_back((std::uint8_t)((v >> 8) & 0xFF));
  out.push_back((std::uint8_t)(v & 0xFF));
}
static void append_u64(Bytes& out, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) out.push_back((std::uint8_t)((v >> (8 * i)) & 0xFF));
}

static std::uint16_t read_u16(const std::uint8_t*& p, const std::uint8_t* end) {
  ensure(p + 2 <= end, "parse overflow (u16)");
  std::uint16_t v = (std::uint16_t(p[0]) << 8) | std::uint16_t(p[1]);
  p += 2;
  return v;
}
static std::uint32_t read_u32(const std::uint8_t*& p, const std::uint8_t* end) {
  ensure(p + 4 <= end, "parse overflow (u32)");
  std::uint32_t v = (std::uint32_t(p[0]) << 24) |
                    (std::uint32_t(p[1]) << 16) |
                    (std::uint32_t(p[2]) << 8) |
                    (std::uint32_t(p[3]));
  p += 4;
  return v;
}
static std::uint64_t read_u64(const std::uint8_t*& p, const std::uint8_t* end) {
  ensure(p + 8 <= end, "parse overflow (u64)");
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  p += 8;
  return v;
}

static Bytes read_vec(const std::uint8_t*& p, const std::uint8_t* end, std::size_t n) {
  ensure(p + n <= end, "parse overflow (vec)");
  Bytes out(p, p + n);
  p += n;
  return out;
}

static void append_blob(Bytes& out, const Bytes& b) {
  ensure(b.size() <= (std::numeric_limits<std::uint32_t>::max)(), "blob too large");
  append_u32(out, (std::uint32_t)b.size());
  out.insert(out.end(), b.begin(), b.end());
}
static Bytes read_blob(const std::uint8_t*& p, const std::uint8_t* end) {
  std::uint32_t n = read_u32(p, end);
  ensure(p + n <= end, "parse overflow (blob)");
  Bytes out(p, p + n);
  p += n;
  return out;
}

// ------------------------------ OQS wrappers ------------------------------

static void ensure_oqs(OQS_STATUS s, const char* msg) {
  if (s != OQS_SUCCESS) throw std::runtime_error(msg);
}

struct KemKeypair {
  Bytes pk;
  SecureBytes sk;
};

static KemKeypair kem_generate(const std::string& kem_alg) {
  OQS_KEM* kem = OQS_KEM_new(kem_alg.c_str());
  ensure(kem != nullptr, "Unsupported KEM alg");
  KemKeypair kp;
  kp.pk.resize(kem->length_public_key);
  kp.sk = SecureBytes(kem->length_secret_key);
  ensure_oqs(OQS_KEM_keypair(kem, kp.pk.data(), kp.sk.b.data()), "OQS_KEM_keypair failed");
  OQS_KEM_free(kem);
  return kp;
}

static std::pair<Bytes, SecureBytes> kem_encapsulate(const std::string& kem_alg, const Bytes& recipient_pk) {
  OQS_KEM* kem = OQS_KEM_new(kem_alg.c_str());
  ensure(kem != nullptr, "Unsupported KEM alg");
  ensure(recipient_pk.size() == kem->length_public_key, "KEM pk length mismatch");
  Bytes ct(kem->length_ciphertext);
  SecureBytes ss(kem->length_shared_secret);
  ensure_oqs(OQS_KEM_encaps(kem, ct.data(), ss.b.data(), recipient_pk.data()), "OQS_KEM_encaps failed");
  OQS_KEM_free(kem);
  return {ct, std::move(ss)};
}

static SecureBytes kem_decapsulate(const std::string& kem_alg, const SecureBytes& sk, const Bytes& ct) {
  OQS_KEM* kem = OQS_KEM_new(kem_alg.c_str());
  ensure(kem != nullptr, "Unsupported KEM alg");
  ensure(ct.size() == kem->length_ciphertext, "KEM ct length mismatch");
  ensure(sk.b.size() == kem->length_secret_key, "KEM sk length mismatch");
  SecureBytes ss(kem->length_shared_secret);
  ensure_oqs(OQS_KEM_decaps(kem, ss.b.data(), ct.data(), sk.b.data()), "OQS_KEM_decaps failed");
  OQS_KEM_free(kem);
  return ss;
}

static Bytes sig_sign(const std::string& sig_alg, const SecureBytes& sk, const Bytes& msg) {
  OQS_SIG* sig = OQS_SIG_new(sig_alg.c_str());
  ensure(sig != nullptr, "Unsupported SIG alg");
  ensure(sk.b.size() == sig->length_secret_key, "SIG sk length mismatch");

  Bytes sigbuf(sig->length_signature);
  size_t siglen = 0;
  ensure_oqs(OQS_SIG_sign(sig, sigbuf.data(), &siglen,
                         msg.data(), msg.size(),
                         sk.b.data()),
             "OQS_SIG_sign failed");
  sigbuf.resize(siglen);
  OQS_SIG_free(sig);
  return sigbuf;
}

static bool sig_verify(const std::string& sig_alg, const Bytes& pk, const Bytes& msg, const Bytes& signature) {
  OQS_SIG* sig = OQS_SIG_new(sig_alg.c_str());
  ensure(sig != nullptr, "Unsupported SIG alg");
  ensure(pk.size() == sig->length_public_key, "SIG pk length mismatch");
  OQS_STATUS s = OQS_SIG_verify(sig, msg.data(), msg.size(),
                                signature.data(), signature.size(),
                                pk.data());
  OQS_SIG_free(sig);
  return s == OQS_SUCCESS;
}

// ------------------------------ AEAD helpers ------------------------------

static std::array<std::uint8_t, kAeadNonceLen> make_record_nonce(
    const std::array<std::uint8_t, kAeadNonceLen>& base,
    std::uint64_t seq) {
  std::array<std::uint8_t, kAeadNonceLen> n = base;

  // XOR seq into last 8 bytes (big-endian interpretation)
  for (int i = 0; i < 8; i++) {
    std::uint8_t b = (std::uint8_t)((seq >> (56 - 8 * i)) & 0xFF);
    n[kAeadNonceLen - 8 + i] ^= b;
  }
  return n;
}

static Bytes aead_encrypt_aes256gcm(
    const std::uint8_t key[kKeyLen],
    const std::uint8_t nonce[kAeadNonceLen],
    const std::uint8_t* aad, std::size_t aad_len,
    const std::uint8_t* pt, std::size_t pt_len) {

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  ensure(ctx != nullptr, "EVP_CIPHER_CTX_new failed");

  ensure(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1, "EncryptInit failed");
  ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)kAeadNonceLen, nullptr) == 1, "Set IV len failed");
  ensure(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1, "EncryptInit key/nonce failed");

  int tmp = 0;
  if (aad_len) {
    ensure(EVP_EncryptUpdate(ctx, nullptr, &tmp, aad, (int)aad_len) == 1, "EncryptUpdate AAD failed");
  }

  Bytes ct(pt_len + kTagLen);
  int len1 = 0;
  ensure(EVP_EncryptUpdate(ctx, ct.data(), &len1, pt, (int)pt_len) == 1, "EncryptUpdate PT failed");

  int len2 = 0;
  ensure(EVP_EncryptFinal_ex(ctx, ct.data() + len1, &len2) == 1, "EncryptFinal failed");

  std::uint8_t tag[kTagLen];
  ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)kTagLen, tag) == 1, "GET_TAG failed");

  ct.resize((std::size_t)len1 + (std::size_t)len2 + kTagLen);
  std::memcpy(ct.data() + len1 + len2, tag, kTagLen);

  EVP_CIPHER_CTX_free(ctx);
  return ct;
}

static Bytes aead_decrypt_aes256gcm(
    const std::uint8_t key[kKeyLen],
    const std::uint8_t nonce[kAeadNonceLen],
    const std::uint8_t* aad, std::size_t aad_len,
    const std::uint8_t* ct, std::size_t ct_len) {

  ensure(ct_len >= kTagLen, "ciphertext too short");
  const std::size_t msg_len = ct_len - kTagLen;
  const std::uint8_t* tag = ct + msg_len;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  ensure(ctx != nullptr, "EVP_CIPHER_CTX_new failed");

  ensure(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1, "DecryptInit failed");
  ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)kAeadNonceLen, nullptr) == 1, "Set IV len failed");
  ensure(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1, "DecryptInit key/nonce failed");

  int tmp = 0;
  if (aad_len) {
    ensure(EVP_DecryptUpdate(ctx, nullptr, &tmp, aad, (int)aad_len) == 1, "DecryptUpdate AAD failed");
  }

  Bytes pt(msg_len);
  int len1 = 0;
  ensure(EVP_DecryptUpdate(ctx, pt.data(), &len1, ct, (int)msg_len) == 1, "DecryptUpdate CT failed");

  ensure(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)kTagLen, (void*)tag) == 1, "SET_TAG failed");

  int len2 = 0;
  int ok = EVP_DecryptFinal_ex(ctx, pt.data() + len1, &len2);
  EVP_CIPHER_CTX_free(ctx);

  ensure(ok == 1, "AEAD auth failed");
  pt.resize((std::size_t)len1 + (std::size_t)len2);
  return pt;
}

// ------------------------------ Handshake messages ------------------------------

Bytes ClientHello::serialize() const {
  Bytes out;
  append_u16(out, kVersion);
  out.push_back((std::uint8_t)MsgType::ClientHello);
  out.insert(out.end(), client_nonce.begin(), client_nonce.end());
  return out;
}

ClientHello ClientHello::parse(const Bytes& in) {
  const std::uint8_t* p = in.data();
  const std::uint8_t* end = in.data() + in.size();

  ClientHello ch;
  ensure(read_u16(p, end) == kVersion, "version mismatch");
  ensure(p < end && *p++ == (std::uint8_t)MsgType::ClientHello, "type mismatch");
  auto cn = read_vec(p, end, kNonceLen);
  std::memcpy(ch.client_nonce.data(), cn.data(), kNonceLen);
  ensure(p == end, "trailing bytes");
  return ch;
}

Bytes ServerHello::serialize(bool include_signature) const {
  Bytes out;
  append_u16(out, kVersion);
  out.push_back((std::uint8_t)MsgType::ServerHello);

  out.insert(out.end(), server_nonce.begin(), server_nonce.end());

  append_u32(out, (std::uint32_t)kem_alg.size());
  out.insert(out.end(), kem_alg.begin(), kem_alg.end());

  append_u32(out, (std::uint32_t)sig_alg.size());
  out.insert(out.end(), sig_alg.begin(), sig_alg.end());

  append_blob(out, kem_pk);

  if (include_signature) {
    append_blob(out, signature);
  }
  return out;
}

ServerHello ServerHello::parse(const Bytes& in) {
  const std::uint8_t* p = in.data();
  const std::uint8_t* end = in.data() + in.size();

  ServerHello sh;
  ensure(read_u16(p, end) == kVersion, "version mismatch");
  ensure(p < end && *p++ == (std::uint8_t)MsgType::ServerHello, "type mismatch");

  auto sn = read_vec(p, end, kNonceLen);
  std::memcpy(sh.server_nonce.data(), sn.data(), kNonceLen);

  std::uint32_t kem_len = read_u32(p, end);
  ensure(p + kem_len <= end, "kem_alg overflow");
  sh.kem_alg.assign((const char*)p, (const char*)p + kem_len);
  p += kem_len;

  std::uint32_t sig_len = read_u32(p, end);
  ensure(p + sig_len <= end, "sig_alg overflow");
  sh.sig_alg.assign((const char*)p, (const char*)p + sig_len);
  p += sig_len;

  sh.kem_pk = read_blob(p, end);
  sh.signature = read_blob(p, end);

  ensure(p == end, "trailing bytes");
  return sh;
}

Bytes ClientKey::serialize() const {
  Bytes out;
  append_u16(out, kVersion);
  out.push_back((std::uint8_t)MsgType::ClientKey);
  append_blob(out, kem_ct);
  return out;
}

ClientKey ClientKey::parse(const Bytes& in) {
  const std::uint8_t* p = in.data();
  const std::uint8_t* end = in.data() + in.size();

  ClientKey ck;
  ensure(read_u16(p, end) == kVersion, "version mismatch");
  ensure(p < end && *p++ == (std::uint8_t)MsgType::ClientKey, "type mismatch");
  ck.kem_ct = read_blob(p, end);
  ensure(p == end, "trailing bytes");
  return ck;
}

// ------------------------------ AppData record framing ------------------------------
//
// Record format:
//   u16 version
//   u8  type=AppData
//   u64 seq
//   u32 ciphertext_len
//   bytes ciphertext (includes 16-byte GCM tag)
//
// AAD = header bytes up to ciphertext_len field end (inclusive of clen)

struct AppRecordView {
  std::uint64_t seq{};
  const std::uint8_t* ct{nullptr};
  std::size_t ct_len{0};
  Bytes aad;
};

static Bytes serialize_app_record(std::uint64_t seq, const Bytes& ciphertext) {
  Bytes out;
  append_u16(out, kVersion);
  out.push_back((std::uint8_t)MsgType::AppData);
  append_u64(out, seq);
  append_u32(out, (std::uint32_t)ciphertext.size());
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  return out;
}

static AppRecordView parse_app_record(const Bytes& in) {
  const std::uint8_t* p = in.data();
  const std::uint8_t* end = in.data() + in.size();
  const std::uint8_t* start = p;

  ensure(read_u16(p, end) == kVersion, "version mismatch");
  ensure(p < end && *p++ == (std::uint8_t)MsgType::AppData, "type mismatch");
  std::uint64_t seq = read_u64(p, end);

  std::uint32_t clen = read_u32(p, end);
  ensure(p + clen <= end, "ciphertext overflow");

  const std::uint8_t* aad_end = p; // right after clen field
  AppRecordView rv;
  rv.seq = seq;
  rv.ct = p;
  rv.ct_len = clen;
  rv.aad.assign(start, aad_end);

  p += clen;
  ensure(p == end, "trailing bytes");
  return rv;
}

// ------------------------------ Session ------------------------------

Session::Session(Role r, TrafficKeys tk) : role_(r), keys_(tk) {}

const std::array<std::uint8_t, kKeyLen>& Session::send_key() const {
  return (role_ == Role::Client) ? keys_.c2s_key : keys_.s2c_key;
}
const std::array<std::uint8_t, kKeyLen>& Session::recv_key() const {
  return (role_ == Role::Client) ? keys_.s2c_key : keys_.c2s_key;
}
const std::array<std::uint8_t, kAeadNonceLen>& Session::send_base_nonce() const {
  return (role_ == Role::Client) ? keys_.c2s_base_nonce : keys_.s2c_base_nonce;
}
const std::array<std::uint8_t, kAeadNonceLen>& Session::recv_base_nonce() const {
  return (role_ == Role::Client) ? keys_.s2c_base_nonce : keys_.c2s_base_nonce;
}

Bytes Session::encrypt_record(const Bytes& plaintext) {
  std::uint64_t seq = next_send_seq_++;
  auto nonce = make_record_nonce(send_base_nonce(), seq);

  // Build AAD header: version|type|seq|ciphertext_len
  Bytes aad;
  append_u16(aad, kVersion);
  aad.push_back((std::uint8_t)MsgType::AppData);
  append_u64(aad, seq);

  std::uint32_t clen = (std::uint32_t)(plaintext.size() + kTagLen);
  append_u32(aad, clen);

  Bytes ct = aead_encrypt_aes256gcm(
      send_key().data(), nonce.data(),
      aad.data(), aad.size(),
      plaintext.data(), plaintext.size());

  ensure(ct.size() == clen, "ciphertext length mismatch");
  return serialize_app_record(seq, ct);
}

Bytes Session::decrypt_record(const Bytes& record) {
  AppRecordView rv = parse_app_record(record);

  // simple strict in-order protection
  ensure(rv.seq == next_recv_seq_, "unexpected seq (replay/out-of-order)");
  next_recv_seq_++;

  auto nonce = make_record_nonce(recv_base_nonce(), rv.seq);
  return aead_decrypt_aes256gcm(
      recv_key().data(), nonce.data(),
      rv.aad.data(), rv.aad.size(),
      rv.ct, rv.ct_len);
}

// ------------------------------ Handshake ------------------------------

ServerIdentity generate_server_identity(const std::string& sig_alg) {
  OQS_SIG* sig = OQS_SIG_new(sig_alg.c_str());
  ensure(sig != nullptr, "Unsupported SIG alg");

  ServerIdentity id;
  id.sig_alg = sig_alg;
  id.sig_pk.resize(sig->length_public_key);
  id.sig_sk = SecureBytes(sig->length_secret_key);

  ensure_oqs(OQS_SIG_keypair(sig, id.sig_pk.data(), id.sig_sk.b.data()), "OQS_SIG_keypair failed");
  OQS_SIG_free(sig);
  return id;
}

ClientHello make_client_hello() {
  ClientHello ch;
  rand_bytes(ch.client_nonce.data(), kNonceLen);
  return ch;
}

static Bytes transcript_hash_v1(const Bytes& client_hello_wire, const Bytes& server_hello_wo_sig_wire) {
  Bytes transcript;
  const char domain[] = "pqme-v1";
  transcript.insert(transcript.end(), domain, domain + std::strlen(domain));
  transcript.insert(transcript.end(), client_hello_wire.begin(), client_hello_wire.end());
  transcript.insert(transcript.end(), server_hello_wo_sig_wire.begin(), server_hello_wo_sig_wire.end());
  return sha256(transcript);
}

static TrafficKeys derive_traffic_keys_v1(const Bytes& kem_shared_secret,
                                         const Bytes& client_nonce,
                                         const Bytes& server_nonce,
                                         const Bytes& transcript_hash) {
  // salt = SHA256("pqme-v1-salt" || client_nonce || server_nonce || transcript_hash)
  Bytes salt;
  const char salt_dom[] = "pqme-v1-salt";
  salt.insert(salt.end(), salt_dom, salt_dom + std::strlen(salt_dom));
  salt.insert(salt.end(), client_nonce.begin(), client_nonce.end());
  salt.insert(salt.end(), server_nonce.begin(), server_nonce.end());
  salt.insert(salt.end(), transcript_hash.begin(), transcript_hash.end());
  Bytes salt_hash = sha256(salt);

  Bytes prk = hkdf_extract_sha256(salt_hash, kem_shared_secret);

  auto c2s_key   = hkdf_expand_sha256(prk, "pqme-v1 c2s key",   kKeyLen);
  auto s2c_key   = hkdf_expand_sha256(prk, "pqme-v1 s2c key",   kKeyLen);
  auto c2s_nonce = hkdf_expand_sha256(prk, "pqme-v1 c2s nonce", kAeadNonceLen);
  auto s2c_nonce = hkdf_expand_sha256(prk, "pqme-v1 s2c nonce", kAeadNonceLen);

  TrafficKeys tk{};
  std::memcpy(tk.c2s_key.data(), c2s_key.data(), kKeyLen);
  std::memcpy(tk.s2c_key.data(), s2c_key.data(), kKeyLen);
  std::memcpy(tk.c2s_base_nonce.data(), c2s_nonce.data(), kAeadNonceLen);
  std::memcpy(tk.s2c_base_nonce.data(), s2c_nonce.data(), kAeadNonceLen);
  return tk;
}

ServerHandshakeState server_start(const Bytes& client_hello_wire,
                                  const ServerIdentity& server_id,
                                  const std::string& kem_alg) {
  ClientHello ch = ClientHello::parse(client_hello_wire);

  // ephemeral KEM keypair
  KemKeypair ekem = kem_generate(kem_alg);

  ServerHello sh;
  rand_bytes(sh.server_nonce.data(), kNonceLen);
  sh.kem_alg = kem_alg;
  sh.sig_alg = server_id.sig_alg;
  sh.kem_pk  = ekem.pk;

  // sign transcript hash over SH_without_signature
  Bytes sh_wo_sig = sh.serialize(false);
  Bytes th = transcript_hash_v1(client_hello_wire, sh_wo_sig);
  sh.signature = sig_sign(server_id.sig_alg, server_id.sig_sk, th);

  Bytes sh_wire = sh.serialize(true);

  ServerHandshakeState st;
  st.ch = ch;
  st.ch_wire = client_hello_wire;
  st.sh = sh;
  st.sh_wire = sh_wire;
  st.transcript_hash = th;
  st.ephemeral_kem_sk = std::move(ekem.sk);
  // session created in finalize
  return st;
}

Session server_finalize(ServerHandshakeState& st, const Bytes& client_key_wire) {
  ClientKey ck = ClientKey::parse(client_key_wire);

  // decapsulate
  SecureBytes ss = kem_decapsulate(st.sh.kem_alg, st.ephemeral_kem_sk, ck.kem_ct);

  TrafficKeys tk = derive_traffic_keys_v1(
      ss.b,
      Bytes(st.ch.client_nonce.begin(), st.ch.client_nonce.end()),
      Bytes(st.sh.server_nonce.begin(), st.sh.server_nonce.end()),
      st.transcript_hash);

  st.session = Session(Session::Role::Server, tk);
  return st.session;
}

ClientHandshakeResult client_handshake(const std::string& kem_alg,
                                       const std::string& sig_alg_expected,
                                       const Bytes& pinned_server_sig_pk,
                                       const Bytes& server_hello_wire,
                                       const Bytes& client_hello_wire) {
  ClientHello ch = ClientHello::parse(client_hello_wire);
  ServerHello sh = ServerHello::parse(server_hello_wire);

  ensure(sh.kem_alg == kem_alg, "server kem alg mismatch");
  ensure(sh.sig_alg == sig_alg_expected, "server sig alg mismatch");

  Bytes sh_wo_sig = sh.serialize(false);
  Bytes th = transcript_hash_v1(client_hello_wire, sh_wo_sig);

  ensure(sig_verify(sh.sig_alg, pinned_server_sig_pk, th, sh.signature), "server signature invalid");

  auto [ct, ss] = kem_encapsulate(sh.kem_alg, sh.kem_pk);
  ClientKey ck{ct};

  TrafficKeys tk = derive_traffic_keys_v1(
      ss.b,
      Bytes(ch.client_nonce.begin(), ch.client_nonce.end()),
      Bytes(sh.server_nonce.begin(), sh.server_nonce.end()),
      th);

  ClientHandshakeResult res;
  res.ch = ch;
  res.sh = sh;
  res.ck = ck;
  res.session = Session(Session::Role::Client, tk);
  return res;
}

} // namespace pqme
