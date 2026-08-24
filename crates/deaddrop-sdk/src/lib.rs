//! Stable application API. Hides stores, inventory, and transports.

use deaddrop_core::chunk::ErasureSpec;
use deaddrop_core::config::Config;
use deaddrop_core::event::Event;
use deaddrop_core::{NodeMode, ObjectId, PeerId, Priority, Result};
pub use deaddrop_net::SendOpts;
use deaddrop_net::{InboxItem, Node};
use std::path::{Path, PathBuf};

pub struct DeadDropBuilder {
    dir: Option<PathBuf>,
    mode: Option<NodeMode>,
}

impl DeadDropBuilder {
    pub fn new() -> Self {
        Self {
            dir: None,
            mode: None,
        }
    }

    pub fn data_dir(mut self, p: impl Into<PathBuf>) -> Self {
        self.dir = Some(p.into());
        self
    }

    pub fn mode(mut self, mode: NodeMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn build(self) -> Result<DeadDrop> {
        let dir = self.dir.unwrap_or_else(default_dir);
        let mut cfg = Config::load(&dir.join("deaddrop.toml"))?;
        if let Some(m) = self.mode {
            cfg.node.mode = m;
        }
        Ok(DeadDrop {
            node: Node::open(&dir, cfg)?,
        })
    }
}

impl Default for DeadDropBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DeadDrop {
    pub(crate) node: Node,
}

pub struct Recipient(pub String);

impl Recipient {
    pub fn from(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl DeadDrop {
    pub fn builder() -> DeadDropBuilder {
        DeadDropBuilder::new()
    }

    /// Open the default data directory (`DEADDROP_HOME` or platform project dir).
    /// This is synchronous: it loads identity and SQLite. It does not dial a network.
    pub fn connect() -> Result<Self> {
        Self::builder().build()
    }

    pub fn open_dir(dir: &Path) -> Result<Self> {
        Self::builder().data_dir(dir.to_path_buf()).build()
    }

    pub async fn send(&self, to: Recipient, payload: impl AsRef<[u8]>) -> Result<ObjectId> {
        self.node.send_payload(
            &to.0,
            payload.as_ref().to_vec(),
            false,
            None,
            Priority::Normal,
            "dd.file",
            None,
            false,
        )
    }

    pub async fn send_file(&self, path: impl AsRef<Path>, to: Recipient) -> Result<ObjectId> {
        self.node
            .send_file(path.as_ref(), &to.0, false, None, Priority::Normal)
    }

    pub fn send_with(&self, opts: SendOpts) -> Result<ObjectId> {
        self.node.send_opts(opts)
    }

    pub fn receive(&self) -> Result<Vec<InboxItem>> {
        self.node.inbox()
    }

    pub fn events(&self) -> Vec<Event> {
        self.node.events()
    }

    pub fn peer_id(&self) -> PeerId {
        self.node.identity.peer_id
    }

    pub fn node(&self) -> &Node {
        &self.node
    }
}

pub fn erasure(data_shards: u32, parity_shards: u32) -> ErasureSpec {
    ErasureSpec {
        data_shards,
        parity_shards,
    }
}

fn default_dir() -> PathBuf {
    std::env::var("DEADDROP_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("deaddrop"))
}

pub mod ffi;
