# DeadDrop Protocol (DDP) v0.1

**Status:** draft, implementable
**Version:** 1
**Wire encoding:** CBOR ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html))
**This document** is the open specification. **DeadDrop** is the official Rust reference implementation. Independent implementations (Go, Swift, C++, …) that follow this document MUST interoperate with DeadDrop.

DeadDrop is an encrypted, delay-tolerant peer-to-peer networking protocol for moving data between devices without requiring continuous internet connectivity.

The central idea is **store → carry → forward**.

A node does not ask “Can I reach the DeadDrop server?” There is no required server. It asks: **what peers can I currently reach, and which objects are they missing?**

```
                    DEAD DROP NETWORK
   ┌──────────┐      Wi-Fi/LAN       ┌──────────┐
   │ Device A │ ◄──────────────────► │ Device B │
   │  ONLINE  │                      │ OFFLINE  │
   └────┬─────┘                      └────┬─────┘
        │                                │
        │ encrypted objects              │ Bluetooth
        │                                │
   ┌────▼─────┐                      ┌────▼─────┐
   │ Device C │ ◄──────────────────► │ Device D │
   │ OFFLINE  │      Wi-Fi Direct    │ OFFLINE  │
   └──────────┘                      └──────────┘
        Store → Carry → Discover → Exchange → Forward
```

Physical movement is part of the network topology. Alice can address a Drop to Diana; Bob and Charlie may carry it without being able to read it.

---

## 1. Design rules

1. **Core knows nothing about transports.** TCP, QUIC, Bluetooth LE, Wi-Fi Direct, LAN, USB, NFC, WebRTC, and internet relays are transports. They move bytes. They do not define objects or routing.
2. **Security is not a later phase.** Nodes MUST authenticate, encrypt, hash, expire, and size-limit objects from v0.1.
3. **Intermediaries see metadata, not content.** Typical visible fields: object id, size, expiry, valid signature. Not filenames, not message bodies, not a cleartext recipient name.
4. **Drops are immutable.** Once `object_id` is bound, the envelope MUST NOT change. Updates are new Drops.

---

## 2. Identities

Each node has:

| Key | Role |
| --- | --- |
| Ed25519 | Signatures (identity + Drop envelopes) |
| X25519 | Key agreement for payload encryption |

A **public identity** is:

```
IdentityV1 = {
  version: 1,
  ed25519_pk: bstr .size 32,
  x25519_pk:  bstr .size 32,
  signature:  bstr .size 64   ; Ed25519 over the identity preimage
}
```

**Identity preimage** (bytewise, no CBOR):

```
b"ddp-id-v1" || ed25519_pk || x25519_pk
```

`signature` is `Ed25519.Sign(ed25519_sk, identity_preimage)`.

**Node ID** (`node_id`, 32 bytes):

```
node_id = SHA-256(b"ddp-nid-v1" || ed25519_pk || x25519_pk)
```

**Text form:** `dd:` followed by 64 lowercase hex characters of `node_id`. Implementations MAY accept unique prefixes of at least 8 hex characters when resolving local contacts.

Nodes SHOULD exchange public identities in `hello` and MAY persist them as contacts. Addressing a Drop to a node requires that node’s X25519 public key.

---

## 3. The Drop

The fundamental unit is a **Drop**: an immutable, content-addressed encrypted object.

A Drop MAY contain a message, file, image, package, web page, JSON document, software update, Git object, sensor reading, public bulletin, or any other binary blob. Large objects are chunked (Section 6).

### 3.1 Outer envelope (what intermediaries store)

CBOR map, string keys, v0.1:

```
DropV1 = {
  "v": 1,
  "object_id":     bstr .size 32,
  "content_hash":  bstr .size 32,   ; SHA-256 of encrypted_payload
  "created_at":    uint,            ; Unix seconds
  "expires_at":    uint,            ; Unix seconds, exclusive
  "content_type":  tstr,            ; MUST be "ddp.inner.v1" for this inner format
  "size":          uint,            ; encrypted_payload length in bytes
  "priority":      uint .le 255,    ; higher is more urgent; default 128
  "routing":       uint,            ; 0 = epidemic (v0.1 required)
  "author_pk":     bstr .size 32,   ; Ed25519 verifying key
  "enc":           EncryptionMetaV1,
  "sig":           bstr .size 64,
  "encrypted_payload": bstr
}
```

Intermediaries MUST treat `encrypted_payload` as opaque. They MUST NOT require a filename or recipient field.

### 3.2 Signature preimage

Signatures are **not** over raw CBOR (map key order is not relied upon).

```
preimage =
    b"ddp-drop-v1"
    || created_at     ; u64 BE
    || expires_at     ; u64 BE
    || priority       ; u8
    || routing        ; u8
    || content_type   ; UTF-8, length-prefixed u16 BE
    || size           ; u64 BE
    || content_hash   ; 32 bytes
    || author_pk      ; 32 bytes
    || enc_canonical  ; see 3.4
```

`sig = Ed25519.Sign(author_sk, preimage)`.

Verifiers MUST recompute `preimage` from fields, verify `sig` with `author_pk`, then check `object_id` (3.3). Invalid Drops MUST be discarded.

### 3.3 Object ID

```
object_id = SHA-256(
    b"ddp-oid-v1" || preimage || sig || encrypted_payload
)
```

A stored envelope whose `object_id` does not match this hash MUST be rejected.

### 3.4 Encryption metadata

```
EncryptionMetaV1 = {
  "scheme": "x25519-hkdf-chacha20poly1305-v1",
  "eph_pk": bstr .size 32,   ; ephemeral X25519 public key
  "nonce":  bstr .size 12,   ; ChaCha20-Poly1305 nonce
  "tag":    bstr .size 16    ; recipient recognition tag (not a routing identifier)
}
```

`enc_canonical` for the signature preimage:

```
b"ddp-enc-v1"
|| scheme as UTF-8, length-prefixed u16 BE
|| eph_pk || nonce || tag
```

### 3.5 Payload encryption

Let `recipient_x25519_pk` be the intended recipient’s X25519 public key.

1. Generate ephemeral X25519 keypair `(eph_sk, eph_pk)`.
2. `shared = X25519(eph_sk, recipient_x25519_pk)`.
3. `HKDF-SHA256` with `ikm = shared`, `salt = eph_pk`, then:
   - `payload_key = expand(info="ddp-payload-v1", L=32)`
   - `tag_key     = expand(info="ddp-recipient-tag-v1", L=32)`
4. `tag = HMAC-SHA256(tag_key, b"ddp-to" || recipient_node_id)[0..16]`.
5. Inner plaintext `P` is CBOR `InnerV1` (3.6).
6. `encrypted_payload = ChaCha20-Poly1305-Encrypt(payload_key, nonce, AAD, P)`
   where `AAD = b"ddp-aad-v1" || author_pk || content_hash` and `content_hash` is computed after encryption… **Implementation order:** encrypt with AAD using a 32-byte placeholder of zeros, then set `content_hash = SHA-256(encrypted_payload)`, then this would break AAD.

**Normative order (implement this):**

1. Encrypt with `AAD = b"ddp-aad-v1" || author_pk` (no content hash in AAD).
2. `content_hash = SHA-256(encrypted_payload)`.
3. Build preimage and `object_id` as above.

Only the intended recipient can derive `payload_key`. Other nodes can still verify `sig` and `object_id`.

**Recipient check:** a node that believes it may be the recipient derives `tag_key` from `eph_pk` and its own X25519 secret. If `tag` matches, it decrypts. Non-recipients fail the tag check (except negligible HMAC collisions) and MUST NOT attempt to interpret plaintext. Nodes MAY skip decryption when the tag does not match.

The tag is **not** a global recipient identifier: it is bound to this Drop’s ephemeral key. Intermediaries cannot index “all Drops for Diana.”

### 3.6 Inner plaintext

```
InnerV1 = {
  "filename": tstr / null,
  "media_type": tstr,     ; e.g. "text/plain"
  "body": bstr
}
```

Filenames live **only** inside the encrypted inner object.

### 3.7 Limits (v0.1)

| Limit | Value |
| --- | --- |
| Max `encrypted_payload` size | 16 777 216 bytes (16 MiB) |
| Max `expires_at - created_at` | 2 592 000 seconds (30 days) |
| Default TTL | 172 800 seconds (48 hours) |
| Min TTL | 60 seconds |
| Max `content_type` length | 128 bytes |
| Max inner `filename` length | 255 bytes |

Nodes MUST reject Drops that violate these limits. Nodes SHOULD apply store quotas (reference default: 512 MiB total).

---

## 4. Transports

A transport provides a bidirectional reliable byte stream (or an adapter that makes it so) between two nodes that can currently reach each other.

v0.1 reference transport: **LAN** — UDP discovery beacons + TCP streams.

Recommended future transports: Bluetooth LE, Wi-Fi Direct, USB, NFC, QUIC, WebRTC, internet relays.

**Discovery beacon** (UDP, not CBOR):

```
magic      : b"DDP1"           ; 4 bytes
version    : u8                ; 1
tcp_port   : u16 BE            ; stream port
node_id    : 32 bytes
```

Default discovery port: **7946**. Default stream port: **7947**. Both MUST be configurable so multiple nodes can run on one host.

Static peers (configured `host:port`) MUST be supported so store-carry-forward can be demonstrated without multicast.

---

## 5. Synchronization

Do not begin by dumping “here are 600 000 object IDs” as the only strategy forever. v0.1 uses a compact **inventory of IDs** (up to 4096 per frame; multiple frames if needed). Later revisions MAY use bloom filters, Merkle sketches, or set-reconciliation algorithms; the session flow stays the same:

```
Peer discovered
      ↓
Authenticate (hello)
      ↓
Exchange capabilities
      ↓
Exchange inventory summaries
      ↓
Determine missing Drops
      ↓
Calculate transfer priority (higher priority, sooner expiry first)
      ↓
Exchange chunks / envelopes
      ↓
Verify hashes and signatures
      ↓
Store
      ↓
Forward later
```

### 5.1 Framing

On the byte stream:

```
frame = length || cbor_message
length = uint32 BE, not including the 4 length bytes
```

Maximum frame size: **8 388 608** bytes. Larger Drops use chunk frames (Section 6).

### 5.2 Messages

CBOR maps with a `type` field:

**`hello`**

```
{
  "type": "hello",
  "protocol": 1,
  "node_id": bstr .size 32,
  "identity": IdentityV1,
  "caps": {
    "max_frame": uint,
    "max_drop": uint,
    "chunk": true
  }
}
```

The first message each way MUST be `hello`. `identity.signature` MUST verify. `node_id` MUST match the identity. Nodes SHOULD store the identity as a contact. Nodes MAY disconnect on protocol mismatch.

**`inventory`**

```
{
  "type": "inventory",
  "object_ids": [* bstr .size 32]
}
```

IDs of Drops the sender is willing to offer (not expired, passing local routing policy).

**`want`**

```
{
  "type": "want",
  "object_ids": [* bstr .size 32]
}
```

**`drop`** — full envelope as `DropV1` nested in `"envelope"`.

**`chunk`** — see Section 6.

**`have`** — acknowledgement that `object_id` is stored.

**`error`** — `{ "type": "error", "code": tstr, "message": tstr }`.

**`done`** — inventory + transfers for this session are complete; peer MAY close or idle.

### 5.3 Offer / request rules

After both hellos:

1. Each side sends `inventory`.
2. Each side computes `want = peer_inventory − local_store` filtered by routing policy and quotas.
3. Each side sends `want`.
4. For each wanted id, the holder sends `drop` or `chunk` sequence.
5. Receiver verifies, stores, sends `have`.
6. Either side sends `done` when it has no more data to send. The session ends when both have sent `done` or the transport closes.

Epidemic routing (v0.1): a node offers every non-expired Drop it stores, subject to quotas.

---

## 6. Chunking

If `size <= 65536`, a single `drop` frame MAY carry the full envelope.

Otherwise:

```
{
  "type": "chunk",
  "object_id": bstr .size 32,
  "index": uint,
  "count": uint,
  "hash": bstr .size 32,          ; SHA-256 of this chunk’s ciphertext bytes
  "data": bstr
}
```

Chunks are consecutive slices of `encrypted_payload` of 65536 bytes, last chunk shorter. `count = ceil(size / 65536)`.

A `drop_header` message MAY precede chunks:

```
{
  "type": "drop_header",
  "envelope": DropV1-without-encrypted_payload,
  "chunk_hashes": [* bstr .size 32]
}
```

`DropV1-without-encrypted_payload` includes all fields except `encrypted_payload` (use `size` and `content_hash` instead). After all chunks arrive, the receiver concatenates, checks `content_hash`, reconstructs the full envelope, and verifies as in Section 3.

A receiver that already has chunks `0..n` SHOULD `want` only the remainder. v0.1 reference MAY re-transfer all chunks; it MUST still verify the full object.

---

## 7. Routing observations (non-normative for v0.1)

Nodes MAY record:

- peer encountered
- when
- how frequently
- coarse success of previous transfers

They MUST NOT store or export a person’s real-world movement history in clear, long-lived form. Routing metadata SHOULD be minimal, aggregated, and disposable.

v0.1 reference implementation uses **epidemic** forwarding only: if a Drop is valid, unexpired, and fits the quota, carry it. Smarter carrier selection is a later revision and MUST remain privacy-preserving.

---

## 8. Security requirements

Implementations MUST provide:

- Ed25519 identities and signatures
- X25519 key agreement
- ChaCha20-Poly1305 authenticated encryption
- SHA-256 content addressing
- Expiration / TTL
- Strict object-size limits
- Store quotas
- Cryptographic verification **before** accepting a Drop into the store

Implementations SHOULD provide:

- Replay resistance via `object_id` uniqueness (store once)
- Rate limiting of inbound frames
- Peer blocking
- Extra verification before executing or installing package content (out of scope for the core protocol; applications MUST NOT treat a valid Drop as permission to execute)

**Executable content:** a valid signature means the envelope is intact, not that the payload is safe to run.

---

## 9. v0.1 milestone

Two computers on the same LAN (or two processes with static peers):

```
dd init
dd peers
dd send ./hello.txt --to dd:…
```

The recipient sees a verified incoming Drop. Then disconnect the first two machines, introduce a third: **computer B carries Alice’s encrypted Drop to C and cannot read it.** That milestone distinguishes DeadDrop from LAN file-transfer apps.

---

## 10. Naming

| Name | Meaning |
| --- | --- |
| **DeadDrop Protocol (DDP)** | This specification |
| **DeadDrop** | Official Rust implementation |

A complete independent implementation of DDP-SPEC is a DeadDrop-compatible node even if it shares no code with this repository.
