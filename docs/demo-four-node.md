# Four-node disconnected delivery

**Engineering demo** on one machine (or four). Sequential TCP contact, not a claim of radio mesh.

Topology: ALPHA ↔ BRAVO, then BRAVO ↔ CHARLIE, then CHARLIE ↔ DELTA. ALPHA never talks to DELTA.

1. `dd init` four data dirs; import DELTA’s `.ddcontact` into ALPHA (known), and each neighbor pair as needed for routing policy.
2. ALPHA: `dd send payload.bin --to <DELTA peer id>` — Drop is stored encrypted.
3. BRAVO: `dd serve --listen 127.0.0.1:7948`
4. ALPHA: `dd sync --peer 127.0.0.1:7948` — chunks move; stop ALPHA.
5. CHARLIE serving; BRAVO `dd sync --peer CHARLIE`.
6. DELTA serving; CHARLIE `dd sync --peer DELTA`.
7. DELTA `dd inbox` reconstructs, verifies chunks/manifest, decrypts, authenticates Alice.
8. DELTA can `dd` issue a delivered receipt (CLI `ack` is via daemon `ack_delivery`; use inspect/trace for local history). Receipts travel back the same opportunistic way.

BRAVO and CHARLIE MUST NOT decrypt the payload (`dd inbox` empty for them).

## Adversarial variant

Insert MALICIOUS between ALPHA and CHARLIE. Mutated chunks fail `ChunkId` verification (DDS2002). Forged receipts fail Ed25519. Malformed frames return DDP1001. The daemon MUST stay up.

A 500 MB payload is a storage/time exercise, not a CI fixture. The cryptographic carry path is tested with small payloads in `dd-sync::multi_hop_encrypted_carry`.
