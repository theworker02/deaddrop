# DDP-0010 Receipts

**Status:** Accepted (DDP/2)

A receipt is a signed statement about an object. Receipts MAY themselves travel as Drops (`application = dd.receipt`). Sender and recipient NEED NOT be online simultaneously.

## Kinds

| Kind | Meaning |
| --- | --- |
| accepted | envelope accepted for consideration |
| stored | durable local copy of all required chunks |
| forwarded | transferred to another peer (does not imply destination delivery) |
| delivered | destination reconstructed and verified the payload |
| opened | application decrypted/presented plaintext — MUST be opt-in |
| rejected | refused (policy, signature, quota) |
| expired | object lifetime ended before delivery |

Do not confuse: received, stored, forwarded, delivered, acknowledged. Each is a distinct state.

## Signature

Preimage label `ddp-receipt-v2`. Sign with the issuer’s Ed25519 key. Verifiers MUST reject receipts whose issuer does not match the claimed identity.

## Custody (OPTIONAL)

A carrier MAY issue `stored` as a custody receipt after verifying durable storage. The previous holder MAY then delete its copy if policy allows. Custody is not required for epidemic or spray-and-wait forwarding.
