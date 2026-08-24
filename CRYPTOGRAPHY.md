# Cryptography

All primitives are standard: Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305, BLAKE3, HMAC-SHA256.

Policy is isolated behind `dd_crypto::CryptoProvider` (`DefaultProvider`).

Session construction: ephemeral DH + HKDF + transcript signatures (DDP-0004). Not a re-implementation of TLS.

After the handshake, the TCP session currently sends **CBOR frames in the clear**. Drop **payloads** are encrypted with the wrapped CEK before they ever hit the wire or a `.ddrop` stick. Inventory and routing metadata are not hidden from a LAN observer.

QUIC TLS certificates are **transport-only** (ephemeral self-signed, custom verifier). They MUST NOT be treated as DeadDrop identities.

`unsafe` is limited to the C ABI (`dd-ffi`). Each block is documented.
