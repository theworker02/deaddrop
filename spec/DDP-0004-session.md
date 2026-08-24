# DDP-0004 Session

After a reliable byte stream exists:

1. ClientHello: protocol, identity, ephemeral X25519, nonce, capabilities, Ed25519 proof over `ddp-ch-v2` || eph_pk || nonce.
2. ServerHello: same plus transcript signature over `ddp-hs-v2` transcript (both identities, both eph keys, both nonces).
3. Session keys: HKDF-SHA256(X25519(eph_sk, eph_pk), transcript) info `ddp-session-v2`. Initiator send key is the first 32 bytes.

Transport encryption (e.g. QUIC TLS) is DISTINCT from session keys and from payload CEK wrapping.

Replay: handshake nonces + transcript bind. Duplicate object_id ingest is idempotent.
