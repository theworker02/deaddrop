# Roadmap

Crate version is **2.6.0**. Wire protocol is **DDP/2**.

## Now (two computers)

Install on two machines. Pair with `.ddcontact`. Send encrypted Drops. Deliver over LAN TCP (`dd connect`) or a USB `.ddrop` file. `dd peer list` shows live LAN locators while a daemon is advertising. That path is implemented and tested (`two_computers_over_tcp`).

## Next

- Optional QUIC listener on the same serve loop (types exist; default is TCP)
- Formal DDP 3 *generation* spec without breaking DDP/2 on the wire until a real major bump

## Not scheduled as “works in README”

Bluetooth, Wi-Fi Direct, WebRTC, WASM extensions, 10k-node CI simulations.
