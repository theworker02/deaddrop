# DDP-0008 Security

Primitives: Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305, BLAKE3, HMAC-SHA256. Custom algorithms MUST NOT be used.

Payload CEK is random; wrapped per recipient (`ddp-wrap-v2`). Public Drops are signed-only.

Compression, if any, MUST occur before encryption and be recorded in authenticated metadata (application/extension). Blind compression of already-compressed media SHOULD be skipped by applications.

DeadDrop does **not** claim anonymity. Size, timing, peer graphs, and destination-set cardinality leak. See DDP-0013.
