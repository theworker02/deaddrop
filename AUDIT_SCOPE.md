# Audit scope

In scope: framing, handshake, envelope signatures, CEK wrap, chunk addressing, store ingest, routing decisions, receipt signatures.

Out of scope until marked stable: visual simulator UI, Wireshark dissector, BPv7 gateway, language SDKs beyond C ABI, IBLT inventory.

Trust boundaries: user data dir; local control (CLI talks to on-disk store / in-process node — Unix socket/named pipe daemon control is PLANNED); peer byte streams.

Key material: `identities/identity.json` (hex secrets). MUST be file-permission restricted on Unix; Windows ACL is the operator’s responsibility.
