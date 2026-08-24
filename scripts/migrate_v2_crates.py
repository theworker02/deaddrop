"""One-shot crate consolidation: copy sources into 4 crates and rewrite imports."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.replace("\r\n", "\n"), encoding="utf-8")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def apply(text: str, pairs: list[tuple[str, str]]) -> str:
    for a, b in pairs:
        text = text.replace(a, b)
    return text


CORE = [
    ("dd_protocol::", "crate::protocol::"),
    ("dd_crypto::", "crate::crypto::"),
    ("dd_identity::", "crate::identity::"),
    ("dd_chunk::", "crate::chunk::"),
    ("dd_store::", "crate::store::"),
    ("dd_receipts::", "crate::receipt::"),
    ("dd_observability::", "crate::event::"),
    ("dd_core::", "crate::"),
]

NET = [
    ("dd_protocol::", "deaddrop_core::protocol::"),
    ("dd_crypto::", "deaddrop_core::crypto::"),
    ("dd_identity::", "deaddrop_core::identity::"),
    ("dd_chunk::", "deaddrop_core::chunk::"),
    ("dd_store::", "deaddrop_core::store::"),
    ("dd_receipts::", "deaddrop_core::receipt::"),
    ("dd_observability::", "deaddrop_core::event::"),
    ("dd_routing::", "crate::routing::"),
    ("dd_sync::", "crate::sync::"),
    ("dd_discovery::", "crate::discovery::"),
    ("dd_transport_lan::", "crate::discovery::lan::"),
    ("dd_transport_tcp::", "crate::transport::tcp::"),
    ("dd_transport_quic::", "crate::transport::quic::"),
    ("dd_transport_memory::", "crate::transport::memory::"),
    ("dd_transport::", "crate::transport::"),
    ("dd_daemon::", "crate::node::"),
    ("dd_core::", "deaddrop_core::"),
]

PROTO_INTERNAL = [
    ("use crate::codec::", "use super::codec::"),
    ("use crate::messages::", "use super::messages::"),
    ("use crate::envelope::", "use super::envelope::"),
    ("use crate::inventory::", "use super::inventory::"),
    ("use crate::handshake::", "use super::handshake::"),
]


def main() -> None:
    core = ROOT / "crates" / "deaddrop-core" / "src"
    net = ROOT / "crates" / "deaddrop-net" / "src"

    # --- core leaf modules from dd-core ---
    for name in [
        "caps",
        "destination",
        "envelope",
        "error",
        "hexutil",
        "ids",
        "lifecycle",
        "limits",
        "mode",
        "priority",
        "trust",
    ]:
        write(core / f"{name}.rs", read(f"crates/dd-core/src/{name}.rs"))

    write(core / "crypto" / "mod.rs", apply(read("crates/dd-crypto/src/lib.rs"), CORE))
    write(core / "identity" / "mod.rs", apply(read("crates/dd-identity/src/lib.rs"), CORE))
    write(core / "chunk" / "mod.rs", apply(read("crates/dd-chunk/src/lib.rs"), CORE))
    write(core / "store" / "mod.rs", apply(read("crates/dd-store/src/lib.rs"), CORE))
    write(core / "receipt" / "mod.rs", apply(read("crates/dd-receipts/src/lib.rs"), CORE))
    write(core / "event" / "mod.rs", apply(read("crates/dd-observability/src/lib.rs"), CORE))
    write(core / "config" / "mod.rs", apply(read("crates/dd-daemon/src/config.rs"), CORE))

    for name in ["codec", "envelope", "handshake", "inventory", "messages"]:
        text = apply(read(f"crates/dd-protocol/src/{name}.rs"), CORE)
        text = apply(text, PROTO_INTERNAL)
        write(core / "protocol" / f"{name}.rs", text)
    write(
        core / "protocol" / "mod.rs",
        """mod codec;
mod envelope;
mod handshake;
mod inventory;
mod messages;

pub use codec::*;
pub use envelope::*;
pub use handshake::*;
pub use inventory::*;
pub use messages::*;
""",
    )

    # --- net ---
    write(net / "discovery" / "mod.rs", apply(read("crates/dd-discovery/src/lib.rs"), NET))
    write(net / "discovery" / "lan.rs", apply(read("transports/lan/src/lib.rs"), NET))
    lan_mod = (net / "discovery" / "mod.rs").read_text(encoding="utf-8")
    if "pub mod lan;" not in lan_mod:
        (net / "discovery" / "mod.rs").write_text(
            "pub mod lan;\n" + lan_mod, encoding="utf-8"
        )

    write(net / "transport" / "mod.rs", apply(read("crates/dd-transport/src/lib.rs"), NET))
    write(net / "transport" / "tcp.rs", apply(read("transports/dd-transport-tcp/src/lib.rs"), NET))
    write(net / "transport" / "memory.rs", apply(read("transports/dd-transport-memory/src/lib.rs"), NET))
    write(net / "transport" / "quic.rs", apply(read("transports/dd-transport-quic/src/lib.rs"), NET))
    tmod = (net / "transport" / "mod.rs").read_text(encoding="utf-8")
    if "pub mod tcp;" not in tmod:
        (net / "transport" / "mod.rs").write_text(
            "pub mod tcp;\n#[cfg(feature = \"quic\")]\npub mod quic;\npub mod memory;\n"
            + tmod,
            encoding="utf-8",
        )

    write(net / "routing" / "mod.rs", apply(read("crates/dd-routing/src/lib.rs"), NET))
    write(net / "sync" / "mod.rs", apply(read("crates/dd-sync/src/lib.rs"), NET))

    node = apply(read("crates/dd-daemon/src/node.rs"), NET)
    node = node.replace("use crate::config::Config;", "use deaddrop_core::config::Config;")
    node = node.replace("crate::config::Config", "deaddrop_core::config::Config")
    write(net / "node.rs", node)

    print("copied core+net sources")


if __name__ == "__main__":
    main()
