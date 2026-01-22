# Darkelf PQ Mini Engine  
Community Post-Quantum Secure Channel (Reference Implementation)

Darkelf PQ Mini Engine is a small, self-contained post-quantum (PQ) secure channel designed for experimentation, research, and learning. It demonstrates how modern post-quantum cryptography primitives can be combined into a working encrypted transport without relying on TLS.

The design is intentionally minimal, explicit, and readable so developers and researchers can clearly see how the protocol works end to end.

This project supports both direct TCP connections and Tor (.onion) connections via SOCKS5.

SECURITY WARNING: This project is a reference implementation and prototype. It is NOT audited, NOT hardened, and NOT a replacement for TLS. Do not rely on it to protect real secrets without independent professional review.

Features:
- Post-quantum key exchange using liboqs (e.g., Kyber)
- Post-quantum authentication using liboqs (e.g., Dilithium)
- Key derivation using HKDF-SHA256 (OpenSSL)
- Authenticated encryption using AES-256-GCM (OpenSSL)
- TCP transport
- Tor SOCKS5 transport (supports .onion services)
- Explicit protocol design with clear handshake and record framing
- No TLS dependency

Project Layout:

.
├── CMakeLists.txt
├── README.md
├── include/
│   └── pqme/
│       ├── engine.hpp
│       ├── framing.hpp
│       ├── transport.hpp
│       └── util.hpp
├── src/
│   ├── engine.cpp
│   ├── framing.cpp
│   ├── util.cpp
│   ├── transport_tcp_posix.cpp
│   └── transport_socks5.cpp
└── apps/
    ├── pqme-keygen.cpp
    ├── pqme-server.cpp
    └── pqme-client.cpp

Dependencies:
- liboqs (headers and library must be installed)
- OpenSSL (libcrypto)

On most systems, liboqs must be built from source.

Build Instructions:

mkdir -p build
cd build
cmake ..
cmake --build . --config Release

If liboqs is installed in a non-standard location:

cmake -S . -B build -DOQS_ROOT=/path/to/liboqs
cmake --build build

Applications:

Key Generation:
Generate a long-term server identity keypair used to authenticate the handshake.

./pqme-keygen Dilithium3 server_sig_pk.bin server_sig_sk.bin

Server:
Run a server that performs a post-quantum handshake and encrypted echo.

./pqme-server 0.0.0.0 4444 Kyber768 Dilithium3 server_keys

The server_keys directory must contain:
- server_sig_pk.bin
- server_sig_sk.bin

Client (Direct TCP):

./pqme-client 127.0.0.1 4444 Kyber768 Dilithium3 server_sig_pk.bin 0

Client (Tor via SOCKS5):

Tor daemon (SOCKS5 on port 9050):
./pqme-client exampleonion.onion 4444 Kyber768 Dilithium3 server_sig_pk.bin 1

Tor Browser (SOCKS5 on port 9150):
./pqme-client exampleonion.onion 4444 Kyber768 Dilithium3 server_sig_pk.bin 2

High-Level Protocol Overview:

1. ClientHello
   - Protocol version
   - Client nonce

2. ServerHello
   - Protocol version
   - Server nonce
   - Selected KEM algorithm
   - Selected signature algorithm
   - Ephemeral KEM public key
   - Signature over transcript

3. ClientKey
   - KEM ciphertext

4. Key Derivation
   - HKDF-SHA256 over the KEM shared secret and handshake transcript

5. Transport
   - AES-256-GCM encrypted records
   - Sequence-number-based nonces
   - Explicit length-prefixed framing

Design Goals:
- Explicit and readable protocol logic
- No TLS dependency
- Easy to audit and reason about
- Easy to modify and experiment with
- Tor-friendly by design

License:
Choose a license before publishing (MIT or BSD-2-Clause recommended).

Acknowledgements:
- Open Quantum Safe (liboqs)
- OpenSSL
- Post-quantum cryptography research community
- Darkelf ecosystem (inspiration)

