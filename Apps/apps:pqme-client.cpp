#include "pqme/engine.hpp"
#include "pqme/framing.hpp"
#include "pqme/transport.hpp"
#include "pqme/util.hpp"

#include <iostream>
#include <string>

using namespace pqme;

static void usage() {
  std::cerr << "Usage:\n";
  std::cerr << "  pqme-client <host> <port> <kem_alg> <sig_alg> <pinned_server_pk.bin> <tor_mode>\n\n";
  std::cerr << "tor_mode:\n";
  std::cerr << "  0  = direct TCP\n";
  std::cerr << "  1  = Tor via SOCKS5 127.0.0.1:9050\n";
  std::cerr << "  2  = Tor via SOCKS5 127.0.0.1:9150 (Tor Browser)\n\n";
  std::cerr << "Example:\n";
  std::cerr << "  pqme-client 127.0.0.1 4444 Kyber768 Dilithium3 pinned_pk.bin 0\n";
  std::cerr << "  pqme-client abcdefg.onion 4444 Kyber768 Dilithium3 pinned_pk.bin 1\n";
}

int main(int argc, char** argv) {
  if (argc != 7) {
    usage();
    return 1;
  }

  const std::string host = argv[1];
  const std::uint16_t port = (std::uint16_t)std::stoi(argv[2]);
  const std::string kem_alg = argv[3];
  const std::string sig_alg = argv[4];
  const std::string pin_path = argv[5];
  const int tor_mode = std::stoi(argv[6]);

  try {
    Bytes pinned_pk;
    ensure(read_file(pin_path, pinned_pk), "failed to read pinned_server_pk.bin");

    // Choose transport
    std::unique_ptr<ITransport> tp;
    if (tor_mode == 0) {
      tp = std::make_unique<TcpTransport>();
    } else if (tor_mode == 1) {
      tp = std::make_unique<Socks5Transport>("127.0.0.1", 9050);
    } else if (tor_mode == 2) {
      tp = std::make_unique<Socks5Transport>("127.0.0.1", 9150);
    } else {
      ensure(false, "invalid tor_mode");
    }

    tp->connect(host, port);
    std::cerr << "[client] connected\n";

    // Handshake
    ClientHello ch = make_client_hello();
    Bytes ch_wire = ch.serialize();
    send_msg(*tp, ch_wire);

    Bytes sh_wire = recv_msg(*tp);

    auto res = client_handshake(
      kem_alg,
      sig_alg,
      pinned_pk,
      sh_wire,
      ch_wire
    );

    send_msg(*tp, res.ck.serialize());
    Session sess = std::move(res.session);

    std::cerr << "[client] handshake complete\n";
    std::cerr << "Type a line and press Enter (Ctrl+D to quit):\n";

    // Interactive loop
    std::string line;
    while (std::getline(std::cin, line)) {
      Bytes msg(line.begin(), line.end());
      Bytes rec = sess.encrypt_record(msg);
      send_msg(*tp, rec);

      Bytes reply_rec = recv_msg(*tp);
      Bytes reply_pt = sess.decrypt_record(reply_rec);

      std::cout << "reply: " << std::string(reply_pt.begin(), reply_pt.end()) << "\n";
    }

    tp->close();
    return 0;

  } catch (const std::exception& e) {
    std::cerr << "[client] error: " << e.what() << "\n";
    return 1;
  }
}
