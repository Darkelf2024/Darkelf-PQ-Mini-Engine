# Darkelf PQ Mini Engine (community reference implementation)

This project provides a small post-quantum (PQ) secure channel:
- KEM + signatures via liboqs (e.g., Kyber + Dilithium)
- Key derivation via HKDF-SHA256 (OpenSSL)
- Transport encryption via AES-256-GCM (OpenSSL)
- TCP transport + Tor SOCKS5 transport (connect to .onion)

## Security status (IMPORTANT)
This is a reference implementation / prototype engine.
It is NOT audited and NOT a replacement for TLS.
Do not rely on it to protect real secrets without independent review.

## Build
Dependencies:
- liboqs installed (headers + lib)
- OpenSSL (libcrypto)

```bash
mkdir -p build && cd build
cmake ..
cmake --build . --config Release
