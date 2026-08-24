# SDK

```rust
let node = deaddrop_sdk::DeadDrop::builder()
    .mode(deaddrop_core::NodeMode::Balanced)
    .build()?;
node.send_file("research.zip", deaddrop_sdk::Recipient::from("dd:…")).await?;
```

Public API: send, receive, peer id. Delivery status and subscribe-to-events are partially exposed via the store/CLI (`dd trace`, `dd inspect`).

C ABI: `dd-ffi` (documented `unsafe`). Python/JS/Go/Swift/Kotlin SDKs are PLANNED on that boundary — not maintained yet.

Examples that MUST use only SDK APIs (bins in `deaddrop-app`):

* `dd-chat` (`crates/deaddrop-app/src/bin/dd-chat.rs`)
* `dd-file` (`crates/deaddrop-app/src/bin/dd-file.rs`)

See [examples/README.md](../examples/README.md). `dd-git` is PLANNED and is not in this tree.
