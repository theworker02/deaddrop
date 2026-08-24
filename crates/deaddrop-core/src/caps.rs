use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDoc {
    pub protocol: u16,
    pub max_frame: u32,
    pub max_drop: u64,
    pub chunking: Vec<String>,
    pub compression: Vec<String>,
    pub inventory: Vec<String>,
    pub routing: Vec<String>,
    pub receipts: bool,
    pub extensions: Vec<String>,
    pub relay_capacity: RelayCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayCapacity {
    #[default]
    Full,
    Low,
    None,
}

impl CapabilityDoc {
    pub fn local_v2() -> Self {
        Self {
            protocol: crate::PROTOCOL_VERSION,
            max_frame: crate::limits::MAX_FRAME_SIZE,
            max_drop: crate::limits::MAX_DROP_SIZE,
            chunking: vec!["fixed".into(), "cdc-v1".into(), "erasure-xor-v1".into()],
            compression: vec!["none".into(), "zstd".into()],
            inventory: vec!["sorted-v1".into(), "bloom-v1".into()],
            routing: vec![
                "direct".into(),
                "epidemic".into(),
                "spray".into(),
                "encounter".into(),
                "adaptive".into(),
            ],
            receipts: true,
            extensions: vec![
                "dd.group/1".into(),
                "sealed-drop-v1".into(),
                "erasure-v1".into(),
                "receipt-v2".into(),
                "spaces-v1".into(),
                "quic-v1".into(),
                "lan-v1".into(),
            ],
            relay_capacity: RelayCapacity::Full,
        }
    }

    /// Negotiate the intersection. Unknown optional capabilities are ignored.
    pub fn negotiate(&self, other: &Self) -> crate::Result<NegotiatedCaps> {
        if other.protocol != self.protocol {
            return Err(crate::DdError::protocol(
                crate::ErrorCode::Ddp1002UnsupportedVersion,
                format!("peer speaks DDP/{}", other.protocol),
            ));
        }
        Ok(NegotiatedCaps {
            protocol: self.protocol,
            max_frame: self.max_frame.min(other.max_frame),
            max_drop: self.max_drop.min(other.max_drop),
            chunking: intersect(&self.chunking, &other.chunking),
            compression: intersect(&self.compression, &other.compression),
            inventory: intersect(&self.inventory, &other.inventory),
            routing: intersect(&self.routing, &other.routing),
            receipts: self.receipts && other.receipts,
            peer_relay: other.relay_capacity,
        })
    }
}

fn intersect(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|x| b.contains(x)).cloned().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiatedCaps {
    pub protocol: u16,
    pub max_frame: u32,
    pub max_drop: u64,
    pub chunking: Vec<String>,
    pub compression: Vec<String>,
    pub inventory: Vec<String>,
    pub routing: Vec<String>,
    pub receipts: bool,
    pub peer_relay: RelayCapacity,
}

impl NegotiatedCaps {
    pub fn prefer_inventory(&self) -> &'static str {
        if self.inventory.iter().any(|s| s == "bloom-v1") {
            "bloom-v1"
        } else {
            "sorted-v1"
        }
    }
}
