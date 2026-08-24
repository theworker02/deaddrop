# DDP-0001 Identities

A node MUST hold an Ed25519 signing key and an X25519 agreement key. Private material MUST NOT be transmitted.

**Identity preimage:** `b"ddp-id-v2" || ed25519_pk || x25519_pk`  
**Signature:** Ed25519 over the preimage.  
**PeerId:** BLAKE3(`b"ddp-nid-v2" || ed25519_pk || x25519_pk`) text-encoded `dd:` + 64 hex chars.

Trust states: unknown | observed | known | verified | blocked. Discovery MUST NOT imply known or verified.

Rotation MUST emit a signed `IdentityTransition` (`ddp-rotate-v2`) so old keys can attest replacements. Implementations MUST NOT silently destroy reachability.

Contact cards: JSON `.ddcontact` (normative) and UTF-8 text (display). QR encoding is OPTIONAL.
