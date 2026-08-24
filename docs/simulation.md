# Simulation

`dd-sim` runs many virtual nodes in-process with a deterministic `--seed`.

```bash
cargo run -p deaddrop-app --bin dd-sim -- --seed 48291 --nodes 50 --drops 80 --hours 12 --strategy spray
cargo run -p deaddrop-app --bin dd-sim -- --scenario scenarios/campus.toml --seed 48291
```

Models (engineering tests, not demographic science): random encounters, and scenario TOML knobs. Community / hub-and-spoke / commuter models beyond random pairing are PLANNED.

Metrics: delivery-related counts, encounters, drops created. Strategy comparison at 1,000 nodes / 100,000 drops / 72h is **not** a CI job; run locally and do not fabricate results.

Visual simulator UI: PLANNED.

Chaos: `dd-chaos` prints expected recovery behavior; automated fault injection is EXPERIMENTAL.
