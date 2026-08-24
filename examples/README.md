# Examples

## Two computers (the main story)

[two-computers.md](two-computers.md) — home PC ↔ laptop over LAN TCP or USB.

## LAN carry notes

[lan-carry.md](lan-carry.md)

## Small SDK binaries

```bash
cargo run -p deaddrop-app --bin dd-file -- --data-dir ./alice --to dd:… ./file.bin
cargo run -p deaddrop-app --bin dd-chat -- --data-dir ./alice --to dd:… "hello"
```

They call `deaddrop-sdk` only. Delivery still uses `dd daemon start` / `dd sync` or a `.ddrop` import.
