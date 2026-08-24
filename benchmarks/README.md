# Benchmarks

Do not fabricate numbers. Suggested local commands:

```bash
cargo test -p dd-chunk --release -- --ignored
cargo test -p dd-crypto --release -- --ignored
```

Tracked in CI: compile + unit tests, not regression dashboards. Hashing, chunking, encryption, inventory, and routing benches as Criterion jobs are PLANNED.
