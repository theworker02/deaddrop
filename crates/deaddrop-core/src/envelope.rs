use crate::destination::Destination;
use crate::ids::{ContentId, ManifestId, ObjectId, PeerId};
use crate::limits::{MAX_EXTENSIONS, NONCE_LEN};
use crate::priority::Priority;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingPolicyKind {
    Direct,
    Epidemic,
    #[default]
    SprayAndWait,
    Encounter,
    Utility,
    Adaptive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingPolicy {
    pub kind: RoutingPolicyKind,
    pub replication_budget: u32,
    #[serde(default)]
    pub trusted_only: bool,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            kind: RoutingPolicyKind::Adaptive,
            replication_budget: crate::limits::DEFAULT_REPLICATION_BUDGET,
            trusted_only: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadDescriptor {
    Inline {
        length: u64,
        content_id: ContentId,
    },
    Blob {
        length: u64,
        content_id: ContentId,
    },
    Chunked {
        length: u64,
        manifest_id: ManifestId,
        content_id: ContentId,
    },
    Manifest {
        manifest_id: ManifestId,
    },
    /// EXPERIMENTAL: streaming manifests are not implemented in v0.2.
    StreamManifest {
        manifest_id: ManifestId,
    },
    Collection {
        members: Vec<ObjectId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientWrap {
    pub peer: PeerId,
    #[serde(with = "serde_bytes")]
    pub eph_pk: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")]
    pub wrapped_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityDescriptor {
    pub scheme: String,
    pub public: bool,
    pub wraps: Vec<RecipientWrap>,
    #[serde(with = "serde_bytes")]
    pub content_nonce: [u8; NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    pub name: String,
    pub critical: bool,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DropEnvelope {
    pub protocol_version: u16,
    pub object_id: ObjectId,
    pub source: PeerId,
    pub destination: Destination,
    pub creation_time: u64,
    pub expiration: u64,
    pub priority: Priority,
    pub hop_limit: u8,
    pub hop_count: u8,
    pub payload_descriptor: PayloadDescriptor,
    pub routing_policy: RoutingPolicy,
    pub security_descriptor: SecurityDescriptor,
    pub application: String,
    pub topic: Option<String>,
    pub extensions: Vec<Extension>,
    #[serde(with = "serde_bytes")]
    pub author_pk: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl DropEnvelope {
    pub fn remaining_hops(&self) -> u8 {
        self.hop_limit.saturating_sub(self.hop_count)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expiration
    }

    pub fn validate_extension_count(&self) -> crate::Result<()> {
        if self.extensions.len() > MAX_EXTENSIONS {
            return Err(crate::DdError::protocol(
                crate::ErrorCode::Ddp1006LimitExceeded,
                "too many extensions",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub ed25519_pk: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub x25519_pk: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}
