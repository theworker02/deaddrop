//! Signed Space membership records. Payload-agnostic shared namespaces.

use crate::crypto::{CryptoProvider, DefaultProvider, PrivateIdentity};
use crate::{PeerId, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceKind {
    Private,
    InviteOnly,
    Public,
    Ephemeral,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceRecord {
    pub name: String,
    pub kind: SpaceKind,
    pub members: Vec<PeerId>,
    pub retention: String,
    pub created_at: u64,
    pub founder: PeerId,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl SpaceRecord {
    pub fn issue(
        author: &PrivateIdentity,
        name: String,
        kind: SpaceKind,
        members: Vec<PeerId>,
        retention: String,
        now: u64,
    ) -> Self {
        let mut rec = Self {
            name,
            kind,
            members,
            retention,
            created_at: now,
            founder: author.peer_id,
            signature: [0; 64],
        };
        rec.signature = DefaultProvider.sign(&author.signing_key(), &rec.preimage());
        rec
    }

    pub fn preimage(&self) -> Vec<u8> {
        let mut b = Vec::from(&b"ddp-space-v2"[..]);
        b.extend_from_slice(self.name.as_bytes());
        b.extend_from_slice(self.founder.as_bytes());
        b.extend_from_slice(&self.created_at.to_be_bytes());
        b
    }

    pub fn verify(&self, founder_pk: &[u8; 32]) -> Result<()> {
        DefaultProvider.verify(founder_pk, &self.preimage(), &self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceInvite {
    pub space: String,
    pub invitee: Option<PeerId>,
    pub issued_by: PeerId,
    pub created_at: u64,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl SpaceInvite {
    pub fn issue(
        author: &PrivateIdentity,
        space: String,
        invitee: Option<PeerId>,
        now: u64,
    ) -> Self {
        let mut inv = Self {
            space,
            invitee,
            issued_by: author.peer_id,
            created_at: now,
            signature: [0; 64],
        };
        let mut msg = Vec::from(&b"ddp-space-invite-v2"[..]);
        msg.extend_from_slice(inv.space.as_bytes());
        msg.extend_from_slice(author.peer_id.as_bytes());
        inv.signature = DefaultProvider.sign(&author.signing_key(), &msg);
        inv
    }
}
