# Two computers

This is the intended use: DeadDrop on a home PC and on another machine, transferring files with **TCP on the LAN** or a **USB stick**. Both work with the same encrypted Drops.

## 1. Initialize each node

Home PC:

```bash
dd --data-dir ./home init
```

Laptop:

```bash
dd --data-dir ./laptop init
```

Each data directory holds that machine's identity and SQLite store. There is no central server.

## 2. Introduce the machines

Copy `home/identity.pub.ddcontact` to the laptop (USB, network share, whatever you already use).

```bash
dd --data-dir ./laptop import ./identity.pub.ddcontact --name home
```

`--name home` is a local alias. Send with `--to home` instead of the long `dd:` id.

Optional: import the laptop contact on the home PC if the home PC will send too.

## 3a. Deliver over the existing LAN

Home PC (leave this running):

```bash
dd --data-dir ./home daemon start --listen 0.0.0.0:7947
```

Laptop:

```bash
dd --data-dir ./laptop send ./document.pdf --to home
dd --data-dir ./laptop connect --to home
```

If UDP beacons cannot be seen, pass the home PC address: `dd connect --peer 192.168.1.20:7947`.

`dd peer list` on either machine shows imported names plus a **REACHABLE** column when a daemon is advertising on the LAN.

Home PC:

```bash
dd --data-dir ./home receive
```

If the daemon is not running, `dd serve --listen 0.0.0.0:7947` is the same listener.

## 3b. Deliver on a USB stick

Laptop, after `dd send`:

```bash
dd --data-dir ./laptop export pending --output /media/usb/pending.ddrop
```

On Windows, use a drive letter (`E:/pending.ddrop`).

Home PC:

```bash
dd --data-dir ./home import E:/pending.ddrop
dd --data-dir ./home receive
```

Private keys are never packed into the bundle.

## What "delay-tolerant" means here

You can `dd send` while the other computer is off. The Drop sits in the local store. Later, when you `dd sync` or import a stick, chunks move. Interrupted copies resume from missing chunks, not from byte zero.

## Firewall

Allow inbound TCP **7947** on the listening machine (Windows Defender Firewall / `ufw`). LAN beacons use UDP **7946** when the daemon is running. `dd peer list`, `dd radar`, and `dd connect` (without `--peer`) listen for those beacons. Sync itself is still TCP.
