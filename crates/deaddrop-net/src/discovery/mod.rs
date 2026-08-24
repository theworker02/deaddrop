pub mod lan;
use async_trait::async_trait;
use deaddrop_core::store::Store;
use deaddrop_core::{PROTOCOL_VERSION, PeerId, Result, hex_encode};
use std::net::SocketAddr;

pub use lan::{LanDiscovery, dedupe_endpoints, scan_lan};

pub const BEACON_MAGIC: &[u8; 4] = b"DDP2";
pub const LAST_LOCATOR_KEY: &str = "lan-locator:last";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub peer: Option<PeerId>,
    pub locator: String,
}

pub fn locator_key(peer: PeerId) -> String {
    format!("lan-locator:{}", hex_encode(peer.as_bytes()))
}

pub fn remember_locator(store: &Store, peer: Option<PeerId>, locator: &str) -> Result<()> {
    if let Some(p) = peer {
        store.kv_set(&locator_key(p), locator)?;
    }
    store.kv_set(LAST_LOCATOR_KEY, locator)
}

pub fn remembered_locator(store: &Store, peer: PeerId) -> Result<Option<String>> {
    store.kv_get(&locator_key(peer))
}

pub fn last_locator(store: &Store) -> Result<Option<String>> {
    store.kv_get(LAST_LOCATOR_KEY)
}

/// Discovery MUST NOT imply trust. A beacon is a reachability claim only.
#[async_trait]
pub trait DiscoveryProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn advertise(&self, self_id: PeerId, stream_port: u16) -> Result<()>;
    async fn scan(&self, timeout_ms: u64) -> Result<Vec<Endpoint>>;
}

#[derive(Debug, Clone, Copy)]
pub struct Beacon {
    pub version: u16,
    pub stream_port: u16,
    pub node_id: PeerId,
}

impl Beacon {
    pub fn encode(self) -> [u8; 4 + 2 + 2 + 32] {
        let mut buf = [0u8; 40];
        buf[0..4].copy_from_slice(BEACON_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_be_bytes());
        buf[6..8].copy_from_slice(&self.stream_port.to_be_bytes());
        buf[8..].copy_from_slice(self.node_id.as_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 40 || &bytes[0..4] != BEACON_MAGIC {
            return Err(deaddrop_core::DdError::invalid_frame("beacon"));
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != PROTOCOL_VERSION {
            return Err(deaddrop_core::DdError::protocol(
                deaddrop_core::ErrorCode::Ddp1002UnsupportedVersion,
                "beacon",
            ));
        }
        let stream_port = u16::from_be_bytes([bytes[6], bytes[7]]);
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[8..40]);
        Ok(Self {
            version,
            stream_port,
            node_id: PeerId::from_digest(id),
        })
    }
}

pub struct StaticPeers {
    pub endpoints: Vec<SocketAddr>,
}

#[async_trait]
impl DiscoveryProvider for StaticPeers {
    fn name(&self) -> &'static str {
        "static"
    }
    async fn advertise(&self, _self_id: PeerId, _stream_port: u16) -> Result<()> {
        Ok(())
    }
    async fn scan(&self, _timeout_ms: u64) -> Result<Vec<Endpoint>> {
        Ok(self
            .endpoints
            .iter()
            .map(|a| Endpoint {
                peer: None,
                locator: a.to_string(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deaddrop_core::store::Store;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "dd-lan-{}-{}",
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn remembers_locator_by_peer() {
        let dir = tmp("kv");
        let store = Store::open(&dir, Default::default()).unwrap();
        let peer = PeerId::from_digest([9u8; 32]);
        remember_locator(&store, Some(peer), "192.168.1.20:7947").unwrap();
        assert_eq!(
            remembered_locator(&store, peer).unwrap().as_deref(),
            Some("192.168.1.20:7947")
        );
        assert_eq!(
            last_locator(&store).unwrap().as_deref(),
            Some("192.168.1.20:7947")
        );
    }
}
