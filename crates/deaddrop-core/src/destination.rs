use crate::ids::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Destination {
    One { peer: PeerId },
    Many { peers: Vec<PeerId> },
    Group { id: String },
    Public,
}

impl Destination {
    pub fn includes(&self, peer: &PeerId) -> bool {
        match self {
            Self::One { peer: p } => p == peer,
            Self::Many { peers } => peers.contains(peer),
            Self::Group { .. } => false,
            Self::Public => true,
        }
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }
}
