# FAQ

**Is DeadDrop anonymous?** No.

**Does it need the internet?** No. Relays and bootstrap lists are optional.

**Is Bluetooth implemented?** No. PLANNED. There is no Bluetooth (or Wi-Fi Direct) transport in this tree.

**Can two independent implementations interoperate?** That is the goal of `/spec`. Today the Rust node is the testing authority; `dd-conformance test` against a foreign binary is EXPERIMENTAL.

**Why DDP/2 vs DDP/1?** Content-addressed chunks, envelope/payload split, BLAKE3 ids, session proofs. Not wire-compatible.

**Where is the GUI?** There is none. The product surface is the `dd` CLI and `deaddrop-sdk`.
