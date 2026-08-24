# Contributing

Default branch is **main**.

Wire behavior belongs in [`spec/`](spec/DDP-0000-overview.md). Implementation lives in four crates only.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo run -p deaddrop-app --bin dd-conformance -- vectors ./test-vectors
```

Fuzz (nightly, 30s): `cd fuzz && cargo fuzz run cbor_message -- -max_total_time=30`.

GitHub Releases (product binaries `dd`, `dd-daemon`, `dd-relay`, `dd-sim`, checksums, SPDX SBOM, Sigstore bundles, Homebrew formula, winget manifests) build when you push a tag matching `v*.*.*` (for example `v2.6.0`). Default branch is **main**.
