#include "pqme/engine.hpp"
#include "pqme/util.hpp"

#include <iostream>
#include <string>

using namespace pqme;

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "Usage: pqme-keygen <sig_alg> <pubkey.bin> <seckey.bin>\n";
    std::cerr << "Example: pqme-keygen Dilithium3 server_sig_pk.bin server_sig_sk.bin\n";
    return 1;
  }

  const std::string sig_alg = argv[1];
  const std::string pk_out  = argv[2];
  const std::string sk_out  = argv[3];

  try {
    ServerIdentity id = generate_server_identity(sig_alg);

    ensure(write_file(pk_out, id.sig_pk), "failed to write pubkey");
    ensure(write_file(sk_out, id.sig_sk.b), "failed to write seckey");

    std::cout << "OK\n";
    std::cout << "sig_alg: " << sig_alg << "\n";
    std::cout << "pubkey : " << pk_out << "\n";
    std::cout << "seckey : " << sk_out << "\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }
}
