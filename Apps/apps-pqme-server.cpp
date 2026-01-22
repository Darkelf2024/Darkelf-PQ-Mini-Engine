#include "pqme/engine.hpp"
#include "pqme/framing.hpp"
#include "pqme/transport.hpp"
#include "pqme/util.hpp"

#include <iostream>
#include <string>

using namespace pqme;

int main(int argc, char** argv) {
  if (argc != 6) {
    std::cerr << "Usage: pqme-server <bind_host> <port> <kem_alg> <sig_alg> <keys_dir>\n";
    std::cerr << "Where keys_dir contains:\n";
    std::cerr << "  server_sig_pk.bin\n";
    std::cerr << "  server_sig_sk.bin\n\n";
    std::cerr << "Example:\n";
    std::cerr << "  pqme-server 0.0.0.0 4444 Kyber768 Dilithium3 server_keys\n";
    return 1;
  }

  const std::string bind_host = argv[1];
  const std::uint16_t port = (std::uint16_t)std::stoi(argv[2]);
  const std::string kem_alg = argv[3];
  const std::string sig_alg = argv[4];
  const std::string keys_dir = argv[5];

  const std::string pk_path = keys_dir + "/server_sig_pk.bin";
  const std::string sk_path = keys_dir + "/server_sig_sk.bin";

  try {
    Bytes pk, sk;
    ensure(read_file(pk_path, pk), "failed to read server_sig_pk.bin");
    ensure(read_file(sk_path, sk), "failed to read server_sig_sk.bin");

    ServerIdentity server_id;
    server_id.sig_alg = sig_alg;
    server_id.sig_pk = std::move(pk);
    server_id.sig_sk = SecureBytes(sk.size());
    server_id.sig_sk.b = std::move(sk);

    TcpTransport t;
    t.listen_and_accept(bind_host, port);
    std::cerr << "[server] accepted connection\n";

    // Handshake
    Bytes ch_wire = recv_msg(t);
    auto st = server_start(ch_wire, server_id, kem_alg);
    send_msg(t, st.sh_wire);

    Bytes ck_wire = recv_msg(t);
    Session sess = server_finalize(st, ck_wire);

    std::cerr << "[server] handshake complete\n";

    // Encrypted echo loop (record framing is handled by send_msg/recv_msg)
    for (;;) {
      Bytes rec = recv_msg(t);
      Bytes pt = sess.decrypt_record(rec);

      std::string s(pt.begin(), pt.end());
      std::cout << s << std::endl;

      Bytes reply = sess.encrypt_record(pt);
      send_msg(t, reply);
    }

  } catch (const std::exception& e) {
    std::cerr << "[server] error: " << e.what() << "\n";
    return 1;
  }
}
