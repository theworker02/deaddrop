# Store → carry → forward (three nodes, one computer)

DDP/2 proof that DeadDrop is not a LAN file-transfer app. Contacts are `.ddcontact` files.

```bash
cargo run -p deaddrop-app --bin dd -- --data-dir ./.alice init
cargo run -p deaddrop-app --bin dd -- --data-dir ./.bob init
cargo run -p deaddrop-app --bin dd -- --data-dir ./.charlie init
cargo run -p deaddrop-app --bin dd -- --data-dir ./.alice import ./.charlie/identity.pub.ddcontact
```

Terminal 2 — Bob listens:

```bash
cargo run -p deaddrop-app --bin dd -- --data-dir ./.bob serve --listen 127.0.0.1:7948
```

Alice queues a Drop, then syncs once with Bob (Charlie still offline):

```bash
echo hello from alice > hello.txt
# Charlie's id: cargo run -p deaddrop-app --bin dd -- --data-dir ./.charlie identity show
cargo run -p deaddrop-app --bin dd -- --data-dir ./.alice send ./hello.txt --to dd:<charlie hex>
cargo run -p deaddrop-app --bin dd -- --data-dir ./.alice sync --peer 127.0.0.1:7948
```

Stop Alice. Charlie comes into range of Bob:

```bash
cargo run -p deaddrop-app --bin dd -- --data-dir ./.charlie serve --listen 127.0.0.1:7949
cargo run -p deaddrop-app --bin dd -- --data-dir ./.bob sync --peer 127.0.0.1:7949
cargo run -p deaddrop-app --bin dd -- --data-dir ./.bob inbox      # empty — Bob cannot decrypt
cargo run -p deaddrop-app --bin dd -- --data-dir ./.charlie inbox  # verified plaintext
```

Four-node (ALPHA…DELTA) procedure: [`docs/demo-four-node.md`](../docs/demo-four-node.md).
