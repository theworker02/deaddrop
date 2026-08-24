//! DeadDrop core: protocol, crypto, identities, objects, storage.
//! This crate MUST NOT depend on networking or applications.

mod caps;
mod destination;
mod envelope;
mod error;
mod hexutil;
mod ids;
mod lifecycle;
mod limits;
mod mode;
mod priority;
mod trust;

pub mod carrier;
pub mod channel;
pub mod chunk;
pub mod config;
pub mod crypto;
pub mod event;
pub mod identity;
pub mod protocol;
pub mod receipt;
pub mod rules;
pub mod sealed;
pub mod space;
pub mod store;

pub use caps::*;
pub use destination::*;
pub use envelope::*;
pub use error::*;
pub use hexutil::*;
pub use ids::*;
pub use lifecycle::*;
pub use limits::*;
pub use mode::*;
pub use priority::*;
pub use sealed::{SEAL_QUORUM_EXT, SEAL_UNTIL_EXT};
pub use trust::*;

/// Wire protocol major version. Independent of the Cargo package version.
pub const PROTOCOL_VERSION: u16 = 2;
pub const PROTOCOL_LABEL: &str = "DDP/2";
pub const STORAGE_SCHEMA_VERSION: u32 = 3;
pub const APP_NAMESPACES: &[&str] = &[
    "dd.chat",
    "dd.file",
    "dd.git",
    "dd.package",
    "dd.web",
    "dd.sensor",
    "dd.receipt",
    "dd.identity-transition",
    "dd.message",
    "dd.board",
    "dd.space",
    "dd.channel",
    "dd.web-capsule",
    "dd.revocation",
];

pub type Result<T> = std::result::Result<T, DdError>;
