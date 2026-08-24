# DDP-0005 Inventory

Phase A (REQUIRED): sorted object-id lists, max 4096 ids per frame.

Phase B (OPTIONAL): Bloom filter of the have-set. False positives MUST be tolerated; false negatives MUST NOT occur for inserted ids.

Phase C IBLT: EXPERIMENTAL / not in the v0.2 wire enum.

After inventory, peers send `want` then transfer envelopes and chunks. Senders MAY push all present chunks for objects they decided to forward.
