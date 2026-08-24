# DDP-0013 Threat Model

**Status:** Accepted (DDP/2)

DeadDrop is a delay-tolerant object network. It is **not** an anonymity system. Size, timing, peer graphs, destination-set cardinality, and hop metadata leak.

## Attacks

| Attack | Mitigation | Test | Remaining risk |
| --- | --- | --- | --- |
| Drop flooding | quotas, max size, unknown-peer caps | store quota errors | new identities are cheap |
| Identity churn | trust states, blocklist | contacts | Sybil |
| Invalid signatures | verify before trusted store | envelope test | implementation bugs |
| Chunk corruption | content ids | chunk verify | bitrot until `dd store verify` |
| Replay | unique object_id, idempotent put | ingest | metadata leak of ids |
| Routing manipulation | hop_limit, strategy, quotas | routing decide | selfish / lying peers |
| Receipt forgery | Ed25519 | receipt test | stolen keys |
| Storage exhaustion | quotas, GC (non-local) | DDS2001 | local DoS |
| CPU exhaustion | frame / collection limits | max frame | slow CBOR |
| Oversized manifests | MAX_CHUNKS | limit | |
| Compression bombs | skip blind recompress; decode limits PLANNED | | residual zstd risk |
| Impersonation | handshake proofs | handshake | stolen keys |
| Inventory poisoning | verify envelopes independently | | bloom false positives delay transfer |
| Peer impersonation after discovery | discovery ≠ trust | DDP-0003 | |

Every listed threat maps to a mitigation. Residual risk MUST be documented rather than advertised away.

Parser hardening: all lengths bounded; attacker-controlled collections MUST NOT unbounded-allocate. Clock skew MUST NOT be the sole correctness condition (DDP-0002 expiration uses creation+TTL with local now; expired objects MUST NOT become active again).
