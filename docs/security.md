# Security and privacy

See [`SECURITY.md`](../SECURITY.md), [`CRYPTOGRAPHY.md`](../CRYPTOGRAPHY.md), [`AUDIT_SCOPE.md`](../AUDIT_SCOPE.md), and [`spec/DDP-0008-security.md`](../spec/DDP-0008-security.md).

## What private mode does (`dd mode private`)

* disable unsolicited relay
* skip LAN discovery advertisement
* restrict unknown peers at the routing layer
* do not retain encounter history

It does **not** hide object sizes, hide that you spoke to a peer, or provide anonymity.

## Relay mode (`dd mode relay`)

Dedicate storage/bandwidth as a carrier. Still no plaintext access to private payloads.

## Internet relays

`dd-relay` is another carrier with a stable TCP/QUIC address. It is not `api.deaddrop.com`. Federation is ordinary DDP. EXPERIMENTAL binary exists; do not treat it as required infrastructure.
