# DDP-0014 Interoperability and DTN standards

**Status:** Accepted (DDP/2)

## Adopt

Store-carry-forward; hop limits; optional custody-like receipts; CBOR; content addressing; QUIC as **one** transport; opportunistic contacts.

## Adapt

Bundle-like envelopes without BPv7 EID/block complexity. Developer-facing `dd:` / `ddo:` / `ddc:` / `ddk:` / `ddm:` identifiers. Simpler session than BPSec+TLS stacks.

## Extend

Multi-recipient CEK wrapping, bloom inventory, explainable utility routing, application namespaces, chunk resume by id, operating modes.

## Avoid

Requiring BPSec, BPv7 primary-block canonicalization, a mandatory internet convergence layer, or cloning BPv7 wholesale.

## Optional adapter

`dd-bpv7` is PLANNED. Core MUST NOT depend on it. Mapping bundles ↔ Drops is a gateway concern. Independently deployed nodes MUST keep working if any internet relay or bootstrap list disappears.

Bootstrap endpoints, if present, are replaceable TOML `[[bootstrap]]` lists. Community, private, or empty bootstrap are all valid.
