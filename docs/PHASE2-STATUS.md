# v2.x status (honest)

## Works (tests or CLI)

- Four-crate layout (`deaddrop-core`, `deaddrop-net`, `deaddrop-sdk`, `deaddrop-app`)
- DDP/2 encrypt/chunk/carry (`deaddrop-net` multi-hop test)
- Adaptive routing + explain confidence
- Transfer scheduler (priority / window scoring)
- Spaces, channels, messages, boards, package Drops
- USB `.ddcarrier` / `.ddrop` export/import (no private keys)
- LAN beacons: `dd radar`, locators on `dd peer list`, `dd connect` / `dd connect --to`
- Deterministic `dd-sim` + `--strategy tournament`
- SDK builder API + C ABI
- Loopback control API (`127.0.0.1` + token; Unix socket on Unix)
- Background `dd daemon start`, plus `dd daemon install` (systemd user / LaunchAgent / Windows logon task)
- Tag releases: binaries, checksums, SPDX SBOM, Sigstore signatures, Homebrew formula, winget manifests

## EXPERIMENTAL

- QUIC in default serve (TCP listens)
- Web pack without sandbox viewer
- Chaos injector (prints expected behavior)
- Independent `dd-conformance test`

## PLANNED

- BLE, Wi-Fi Direct, WebRTC, NFC, multipath
- Git sneakernet remote
- WASM extensions
- Demographic-quality mobility models (we only ship engineering scenarios)

## Not claimed

Anonymity. Cryptographic timed-release. Remote guaranteed deletion. Bluetooth working. A required `api.deaddrop.com`.
