# DDP-0002 Envelope

The envelope and payload are logically separate. Intermediaries MUST store the envelope plus content-addressed chunks. They MUST NOT require plaintext.

`DropEnvelope` fields: protocol_version (2), object_id (`ddo:b3:…`), source, destination (one | many | group | public), creation_time, expiration, priority, hop_limit, hop_count, payload_descriptor, routing_policy, security_descriptor, application, topic, extensions, author_pk, signature.

**Signature preimage** is defined by `envelope_preimage` in the reference codec (`ddp-env-v2` || fields listed in `crates/dd-protocol/src/envelope.rs`). Implementations MUST hash that exact byte string.

`object_id = BLAKE3(preimage || signature)`.

Payload descriptors: inline, blob, chunked (REQUIRED in v2 reference), manifest, stream_manifest (EXPERIMENTAL), collection.

Priorities: bulk, normal, important, urgent. Urgent MUST NOT bypass per-peer quotas (slot weights).
