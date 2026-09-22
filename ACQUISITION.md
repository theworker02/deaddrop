# Acquisition Brief â€” DeadDrop

**Date:** 2026-09-22  
**Repository:** https://github.com/theworker02/deaddrop  
**Default branch:** `main`  
**Primary language:** Rust  
**Status:** Diligence briefing only. **No acquisition has occurred** by virtue of this file.  
**License:** Proprietary â€” sale, written commercial license, or completed asset transfer required (see root `LICENSE`).  
**Valuation:** Not stated.  
**Contact:** GitHub [@theworker02](https://github.com/theworker02) Â· [thanks.dev/u/gh/theworker02](https://thanks.dev/u/gh/theworker02)

> Cloning or forking this repository does **not** grant production, redistribution, SaaS, OEM, or commercial rights.

---

## 1. Executive thesis

This project is **proprietary**. Production use, redistribution, and commercial deployment require a written commercial license or completed acquisition. See [LICENSE](./LICENSE) and [ACQUISITION.md](./ACQUISITION.md). Contact [@theworker02](https://github.com/theworker02). **Encrypted delay-tolerant networking for computers that are not always online at the same time.** Install it on a machine at home. Install it on a laptop. Send a file. When the two machines can reach each other Ã¢â‚¬â€ same WiÃ¢â‚¬â€˜Fi, a USB stick, a visit later Ã¢â‚¬â€ the file moves. Neither side has to stay connected.

**Why a buyer cares:** DeadDrop packages transferable product IP â€” source, docs, in-repo brand assets, and a diligence room under `docs/acquisition/` â€” under a clear proprietary posture so diligence can proceed without mistaking the repo for open source.

---

## 2. Product snapshot

| Item | Detail |
|------|--------|
| Product | DeadDrop |
| Repo | `theworker02/deaddrop` |
| Language | Rust |
| Open source? | **No** â€” proprietary |
| Rightsholder | theworker02 |
| Diligence pack | `docs/acquisition/` |

### Capability highlights (from current materials)

- [Getting started](docs/getting-started.md)
- [Two computers](examples/two-computers.md)
- [Protocol](spec/DDP-0000-overview.md)
- [Security](SECURITY.md) Ã‚Â· [Threat model](THREAT_MODEL.md)
- [Contributing](CONTRIBUTING.md) Ã‚Â· [Roadmap](ROADMAP.md)
- [GitHub](https://github.com/theworker02/deaddrop) Ã‚Â· [Releases](https://github.com/theworker02/deaddrop/releases/latest) Ã‚Â· [CI](https://github.com/theworker02/deaddrop/actions/workflows/ci.yml)
- [deaddrop-sdk](https://crates.io/crates/deaddrop-sdk) Ã‚Â· [docs.rs](https://docs.rs/deaddrop-sdk)
- [deaddrop-app](https://crates.io/crates/deaddrop-app) Ã‚Â· [docs.rs](https://docs.rs/deaddrop-app)
- [deaddrop-core](https://crates.io/crates/deaddrop-core) Ã‚Â· [docs.rs](https://docs.rs/deaddrop-core)
- [deaddrop-net](https://crates.io/crates/deaddrop-net) Ã‚Â· [docs.rs](https://docs.rs/deaddrop-net)

---

## 3. Problem / opportunity

Teams evaluating DeadDrop typically need either (a) a commercial right to run or embed it, or (b) outright ownership of the Product IP for strategic build-out. Public GitHub visibility without a proprietary license creates false assumptions about free production use. This brief and the linked data room make the commercial path explicit.

---

## 4. What ships today

Honest maturity: treat repository contents, README claims, tests, and release tags as the source of truth. Do not assume production customers, ARR, filed patents, or SLAs unless separately evidenced in diligence.

Typical transferable surfaces:

- Source tree and build/test scripts present in-repo
- Documentation and design notes
- Acquisition / diligence markdown under `docs/acquisition/`
- Branding assets committed to the repository (if any)

---

## 5. Demo / evaluation path (buyer)

Minimal path (no secrets required unless README says otherwise):

```
```
Store it.  Carry it.  Discover.  Exchange.  Forward.
```
```mermaid
flowchart LR
  subgraph home [Home PC]
    A[dd send]
  end
  subgraph path [Existing path]
    L[LAN TCP]
    U[USB stick]
  end
  subgraph other [Laptop]
    B[dd receive]
  end
  A --> L --> B
  A --> U --> B
```
```bash
cargo install deaddrop-app --locked
```
```bash
# from a release (needs cargo-binstall)
cargo binstall --git https://github.com/theworker02/deaddrop deaddrop-app

# Homebrew formula attached to the release (not homebrew-core)
brew install --formula https://github.com/theworker02/deaddrop/releases/latest/download/deaddrop.rb
```
```bash
git clone https://github.com/theworker02/deaddrop
cd deaddrop
cargo install --path crates/deaddrop-app --locked
```
```bash
cargo run -p deaddrop-app --bin dd -- --help
```
```bash
dd --data-dir ./home init
dd --data-dir ./home daemon start --listen 0.0.0.0:7947
dd --data-dir ./home daemon install   # optional: start at login (systemd user / LaunchAgent / Windows logon task)
```

Extended evaluation: `docs/acquisition/BUYER_EVALUATION.md`. Written NDA / evaluation grants may be required for private materials.

---

## 6. What a transaction typically includes

Subject to definitive schedules:

| Included (typical) | Excluded (typical) |
|--------------------|--------------------|
| Repo materials + asserted original IP | Seller personal accounts / unrelated repos |
| Docs + diligence room at closing | Third-party dependency source under separate licenses |
| In-repo brand marks as assigned | Secrets without rotation plan |
| Know-how captured in docs | Fabricated revenue, user, or adoption metrics |

---

## 7. Suggested deal structures

| Structure | When it fits |
|-----------|--------------|
| Non-exclusive commercial license | Deploy/run under seat or environment terms |
| Exclusive field-of-use license | Buyer wants exclusivity; seller may retain entity |
| Asset / IP assignment | Buyer wants ownership of Materials outright |
| OEM / redistribution | Separate agreement â€” not implied here |

Commercial terms (price, earnouts, escrow) are negotiated under NDA with counsel.

---

## 8. Buyer diligence checklist

- [ ] Confirm Rightsholder identity and authority to sell/license
- [ ] Inventory Materials (`docs/acquisition/ASSET_INVENTORY.md`)
- [ ] Review IP posture (`IP_PROVENANCE.md`) and dependencies (`DEPENDENCY_INVENTORY.md`)
- [ ] Run evaluation script (`BUYER_EVALUATION.md`)
- [ ] Review risks (`RISK_REGISTER.md`)
- [ ] Agree transfer scope (`TRANSFER_MANIFEST.md`) and handoff (`HANDOFF_CHECKLIST.md`)
- [ ] Supersede root `LICENSE` at closing via definitive agreement

---

## 9. Related documents

| Document | Purpose |
|----------|---------|
| `LICENSE` | Proprietary â€” no default grant |
| `docs/acquisition/README.md` | Data-room index |
| `docs/acquisition/EXECUTIVE_SUMMARY.md` | One-page thesis |
| `README.md` | Product overview |
| `SECURITY.md` | Vulnerability reporting |
| `COMMERCIAL.md` | Licensing contact path |
| `.github/FUNDING.yml` | Sponsors / thanks.dev |

---

## 10. Disclaimer

This package is informational and **does not** create a binding offer, grant of rights, or investment advice. Engage counsel for any transaction.

---

*Document version: 2.0.0 / 2026-09-22 Â· Classification: acquisition briefing*
