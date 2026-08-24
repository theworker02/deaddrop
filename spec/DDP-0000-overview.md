# DDP-0000 — Overview

**Status:** Accepted (DDP/2)
**Normative:** this document and DDP-0001 through DDP-0015.

DeadDrop Protocol (DDP) is an encrypted, delay-tolerant, peer-to-peer object networking protocol.

The Rust tree named **DeadDrop** is the reference implementation used for testing. **This specification family defines interoperability.** Accidental Rust details are not protocol.

## Principle

Connectivity is an opportunity, not a prerequisite. A node MUST remain useful while disconnected: store objects, discover peers when a path appears, decide what to exchange, forward ciphertext, and deliver without a continuously reachable central service.

There is no required `api.deaddrop.com`.

## Terminology (RFC 2119)

MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, MAY, OPTIONAL.

## Protocol vs application version

| Axis | Current |
| --- | --- |
| Protocol | DDP/2 |
| Storage schema | 2 |
| Cargo package | independent |

Nodes MUST negotiate `protocol` in capabilities. Application semver MUST NOT be used as a wire version.

## Document map

| ID | Topic |
| --- | --- |
| 0001 | Identities |
| 0002 | Envelope |
| 0003 | Discovery |
| 0004 | Session |
| 0005 | Inventory |
| 0006 | Transfer |
| 0007 | Routing |
| 0008 | Security |
| 0009 | Storage |
| 0010 | Receipts |
| 0011 | Capabilities |
| 0012 | Extensions |
| 0013 | Threat model |
| 0014 | Interoperability / DTN relationship |
| 0015 | Conformance |

Historical DDP/1 (inline payload, SHA-256 object ids) is not wire-compatible. See `protocol/DDP-SPEC.md` as archive only.

## Object lifecycle

```
CREATE → ENCRYPT → CHUNK → STORE → ADVERTISE → FORWARD → VERIFY → DELIVER → RECEIPT → GC
```

## Session states

Disconnected → TransportConnected → Negotiating → Authenticated → InventorySync → Transferring → Idle → Closing

Invalid transitions MUST close the transport. Implementations MUST NOT panic on malformed frames (DDP1001).
