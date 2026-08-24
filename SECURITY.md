# Security

See also `spec/DDP-0008-security.md` and `spec/DDP-0013-threat-model.md`.

## Reporting

Please report vulnerabilities privately. Do not file public issues with exploit details.

Use GitHub's [private vulnerability reporting](https://github.com/theworker02/deaddrop/security/advisories/new) for this repository.

## What we protect

End-to-end confidentiality of private payloads (CEK wrap). Integrity of envelopes and chunks. Authentication of peers in the DDP handshake. Forward secrecy of **session** keys (ephemeral X25519), not of stored payload CEKs (those last until expiration).

## Remaining wire gaps

The DDP handshake authenticates peers and derives session keys. Many **post-handshake TCP frames are still plaintext CBOR** (inventory, want, chunk bodies are content-addressed and payload-encrypted at rest, but the session does not wrap every control frame in TLS). Treat LAN and sneakernet as honest-but-curious carriers. See `CRYPTOGRAPHY.md`.

Releases: GitHub Release archives include SHA-256 checksums, a SPDX SBOM, and Sigstore keyless signatures (`*.cosign.bundle`). They are not GPG-signed.

Anonymity, location privacy of encounter graphs, protection against a global passive observer correlating sizes and times, or safety of executing Drop payloads.
