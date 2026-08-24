# Changelog

## 2.6.0

Developer experience and the two-computer path.

- CLI: `dd send` / `dd receive`, `dd daemon start|stop|status`, `dd sync` (`dd connect`), `--json`, shell completions, `dd doctor --repair`.
- Contacts resolve by **name** (`--name laptop`) as well as `dd:` id prefixes.
- LAN: daemon advertises UDP beacons; `dd peer list` shows live locators; `dd connect` / `dd connect --to home` can omit the IP when a single other node is visible.
- USB: `dd export pending` / `dd import` for `.ddrop` bundles (no private keys).
- Optional XOR / Reed–Solomon chunk erasure, sealed-until policy extensions, witness forward receipts.
- Loopback control API (`127.0.0.1` + token file; Unix socket when available).
- GitHub Release workflow on `v*.*.*` tags ships `dd`, `dd-daemon`, `dd-relay`, `dd-sim`, SHA-256 checksums, SPDX SBOM, Sigstore signatures, a Homebrew formula, and winget manifests.
- `dd daemon start` detaches; `dd daemon install` registers a user service (systemd --user, LaunchAgent, or a Windows logon task).
- CI: clippy `-D warnings`, `cargo deny`, 30s CBOR fuzz on nightly. Research CLI commands are hidden from `--help`.

Wire protocol remains **DDP/2**. Bluetooth, Wi-Fi Direct, and a public management API are not included.

## 2.0.0

Four-crate consolidation (`deaddrop-app` → `sdk` → `net` → `core`).
