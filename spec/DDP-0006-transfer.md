# DDP-0006 Transfer

Frames: u32 BE length + CBOR `Message`. Max frame 4 MiB.

Chunks are independently content-addressed (`ddk:b3:…`). Receivers MUST verify before trusted storage. Corrupt chunks MUST be rejected (DDS2002).

Transfers MUST be resumable via `object_chunks.present` bitmaps, not TCP byte offsets.

Parallel/multi-source acquisition: a node MAY accept the same chunk id from multiple peers (dedup by content id).
