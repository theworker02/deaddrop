# DDP-0009 Storage

**Status:** Accepted (DDP/2)

The object store is a local, crash-tolerant repository of envelopes, manifests, chunks, receipts, identities, and routing metadata. It is **not** a network service.

## Layout (implementation recommendation)

```
objects/          # envelope metadata (SQLite)
manifests/        # content-addressed manifests
chunks/           # files named by hex digest
receipts/
identities/
routing/
peer-state/
```

A crash MUST NOT leave the store unrecoverable. Implementations SHOULD use WAL (or equivalent) for metadata and idempotent chunk inserts (content-addressed files).

## Deduplication

Identical chunk bytes MUST occupy storage once. Logical size is the sum of referenced chunk lengths; physical size is unique chunk files plus metadata.

`dd store stats` reports objects, payloads, chunks, logical size, physical size, and deduplication ratio.

## Quotas

Configurable limits MUST distinguish:

| Class | Meaning |
| --- | --- |
| local | created by this node |
| incoming | addressed to this node, not yet complete |
| relay | carried for others |
| temporary | unverified or in-flight chunks |
| metadata | envelopes, indexes |

When relay space is exhausted, the node MUST refuse additional relay objects (DDS2001) and MUST NOT delete `ownership=local` content to make room.

## Integrity

`dd store verify` MUST check:

* chunk hashes against `ChunkId`
* manifest references
* missing chunk files
* orphaned chunks (MAY report; repair is OPTIONAL)
* envelope signatures at ingest time (re-verify SHOULD be available)

Corrupted chunks MUST never enter trusted storage (DDS2002).
