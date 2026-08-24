use crate::{DdError, NodeMode, Result, RoutingPolicyKind};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub node: NodeSection,
    pub storage: StorageSection,
    pub routing: RoutingSection,
    pub discovery: DiscoverySection,
    pub transport: TransportSection,
    pub bootstrap: Vec<Bootstrap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSection {
    pub mode: NodeMode,
    #[serde(default)]
    pub role: crate::NodeRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSection {
    pub maximum: String,
    pub reserved_local: String,
    pub relay_budget: String,
    pub temporary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSection {
    pub strategy: String,
    pub replication_budget: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverySection {
    pub lan: bool,
    pub lan_port: u16,
    /// public | contacts | space-members | invite-only | hidden
    #[serde(default)]
    pub mode: DiscoveryMode,
    /// Rotate LAN beacon identifiers daily. Handshake still uses the real PeerId.
    #[serde(default)]
    pub ephemeral_ids: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryMode {
    #[default]
    Public,
    Contacts,
    SpaceMembers,
    InviteOnly,
    Hidden,
}

impl DiscoveryMode {
    pub fn advertise_lan(self) -> bool {
        !matches!(self, Self::Hidden)
    }

    pub fn parse_cli(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "public" => Some(Self::Public),
            "contacts" => Some(Self::Contacts),
            "space-members" | "space_members" => Some(Self::SpaceMembers),
            "invite-only" | "invite_only" => Some(Self::InviteOnly),
            "hidden" => Some(Self::Hidden),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportSection {
    pub quic: bool,
    pub listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    pub endpoint: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node: NodeSection {
                mode: NodeMode::Balanced,
                role: crate::NodeRole::Personal,
            },
            storage: StorageSection {
                maximum: "20GB".into(),
                reserved_local: "5GB".into(),
                relay_budget: "10GB".into(),
                temporary: "5GB".into(),
            },
            routing: RoutingSection {
                strategy: "adaptive".into(),
                replication_budget: 8,
            },
            discovery: DiscoverySection {
                lan: true,
                lan_port: 7946,
                mode: DiscoveryMode::Public,
                ephemeral_ids: false,
            },
            transport: TransportSection {
                quic: true,
                listen: "0.0.0.0:7947".into(),
            },
            bootstrap: vec![],
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let s = std::fs::read_to_string(path)?;
        toml::from_str(&s).map_err(|e| DdError::invalid_frame(format!("config: {e}")))
    }

    pub fn strategy(&self) -> RoutingPolicyKind {
        match self.routing.strategy.as_str() {
            "direct" => RoutingPolicyKind::Direct,
            "epidemic" => RoutingPolicyKind::Epidemic,
            "encounter" => RoutingPolicyKind::Encounter,
            "utility" => RoutingPolicyKind::Utility,
            "adaptive" => RoutingPolicyKind::Adaptive,
            _ => RoutingPolicyKind::SprayAndWait,
        }
    }

    pub fn parse_bytes(s: &str) -> u64 {
        let t = s.trim().to_ascii_uppercase();
        let (n, mul) = if let Some(x) = t.strip_suffix("GB") {
            (x, 1024u64 * 1024 * 1024)
        } else if let Some(x) = t.strip_suffix("MB") {
            (x, 1024 * 1024)
        } else if let Some(x) = t.strip_suffix("KB") {
            (x, 1024)
        } else {
            (t.as_str(), 1)
        };
        n.trim().parse::<f64>().unwrap_or(0.0) as u64 * mul
    }
}
