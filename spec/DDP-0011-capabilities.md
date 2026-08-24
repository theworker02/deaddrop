# DDP-0011 Capabilities

**Status:** Accepted (DDP/2)

Nodes MUST exchange a compact capability document during the session handshake.

## Fields

| Field | Notes |
| --- | --- |
| protocol | major DDP version (2) |
| max_frame | bytes; MUST NOT exceed 4 MiB in DDP/2 |
| max_drop | logical payload bound |
| chunking | `fixed`, `cdc-v1` |
| compression | `none`, `zstd` |
| inventory | `sorted-v1`, `bloom-v1` (`iblt-v1` EXPERIMENTAL) |
| routing | `direct`, `epidemic`, `spray`, `encounter` |
| receipts | boolean |
| extensions | namespaced strings |
| relay_capacity | `full`, `low`, `none` |

Unknown **optional** capabilities MUST be ignored. Unknown **mandatory** capabilities (protocol mismatch, unknown critical extension) MUST fail with a coded error (DDP1002 / DDP1003).

`RELAY_CAPACITY=LOW` is backpressure. Peers SHOULD reduce offers and skip expensive discovery if their mode allows.

Operating modes (performance, balanced, battery, offline, relay-only, private) are local policy that MAY change advertised capabilities. See DDP-0008 privacy notes for `private`.
