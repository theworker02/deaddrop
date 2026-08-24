# Getting started

Install DeadDrop on **two computers you already have**. They talk over your LAN (TCP) or a USB stick. There is no cloud.

Download a [release archive](https://github.com/theworker02/deaddrop/releases), or:

```bash
cargo install --path crates/deaddrop-app --locked
```

On each machine:

```bash
dd --data-dir ./node init
dd --data-dir ./node doctor
dd --data-dir ./node identity show
```

`init` writes `identity.pub.ddcontact`. Copy that file to the other computer and:

```bash
dd --data-dir ./node import ./identity.pub.ddcontact --name other
```

Queue a file (encrypted locally, even if the other PC is asleep):

```bash
dd --data-dir ./node send ./file.bin --to other
```

Deliver:

```bash
# LAN — other computer must be listening
dd --data-dir ./node daemon start --listen 0.0.0.0:7947

# sender (uses LAN beacons; pass --peer HOST:7947 if discovery is blocked)
dd --data-dir ./node connect --to other

# or USB
dd --data-dir ./node export pending --output E:/pending.ddrop
dd --data-dir ./node import E:/pending.ddrop
```

Receive:

```bash
dd --data-dir ./node receive
```

`dd peer list` shows contacts and any reachable LAN address. Full walkthrough: [two computers](../examples/two-computers.md).

Configuration lives in `deaddrop.toml` inside the data dir (`dd config`).
