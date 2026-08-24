# DDP-0015 Conformance

**Status:** Accepted (DDP/2)

The written specification defines interoperability. The Rust tree is authoritative for **testing**, not for inventing silent wire behavior.

## Vectors

Canonical files live in `test-vectors/`. Unexpected changes MUST fail CI.

`dd-conformance vectors ./test-vectors` MUST:

1. require identity, envelope, and handshake JSON files
2. verify the committed BLAKE3 digest of the envelope input
3. exercise encode/decode and identity verification locally

## Independent implementations

Another implementation SHOULD be able to:

* decode/encode envelopes
* verify signatures
* reject bad chunks
* complete a DDP/2 session with `dd serve`

Speaking DDP to a third-party process (`dd-conformance test host:port`) is EXPERIMENTAL.

## Versioning

| Axis | Independent of |
| --- | --- |
| Protocol DDP/n | Cargo package version |
| Extension versions | protocol major |
| Storage schema | protocol major (migrations required between stable releases) |

Stable DDP versions require backward compatibility. Experimental extensions do not.
