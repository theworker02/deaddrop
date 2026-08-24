use crate::chunk::Manifest;
use crate::{CapabilityDoc, ChunkId, DropEnvelope, ObjectId, PublicIdentity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    ClientHello {
        protocol: u16,
        identity: PublicIdentity,
        #[serde(with = "serde_bytes")]
        eph_pk: [u8; 32],
        nonce: u64,
        caps: CapabilityDoc,
        #[serde(with = "serde_bytes")]
        identity_proof: [u8; 64],
    },
    ServerHello {
        protocol: u16,
        identity: PublicIdentity,
        #[serde(with = "serde_bytes")]
        eph_pk: [u8; 32],
        nonce: u64,
        caps: CapabilityDoc,
        #[serde(with = "serde_bytes")]
        transcript_sig: [u8; 64],
    },
    InventorySorted {
        object_ids: Vec<ObjectId>,
    },
    InventoryBloom {
        n: u32,
        k: u8,
        #[serde(with = "serde_bytes")]
        bits: Vec<u8>,
    },
    Want {
        object_ids: Vec<ObjectId>,
        chunks: Vec<ChunkWant>,
    },
    Envelope {
        envelope: DropEnvelope,
        manifest: Manifest,
    },
    ChunkData {
        object_id: ObjectId,
        chunk_id: ChunkId,
        index: u32,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    Have {
        object_id: ObjectId,
        chunks_present: Vec<u32>,
    },
    ReceiptOffer {
        object_id: ObjectId,
    },
    Error {
        code: String,
        message: String,
    },
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkWant {
    pub object_id: ObjectId,
    pub indices: Vec<u32>,
}

impl Message {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ClientHello { .. } => "client_hello",
            Self::ServerHello { .. } => "server_hello",
            Self::InventorySorted { .. } => "inventory_sorted",
            Self::InventoryBloom { .. } => "inventory_bloom",
            Self::Want { .. } => "want",
            Self::Envelope { .. } => "envelope",
            Self::ChunkData { .. } => "chunk_data",
            Self::Have { .. } => "have",
            Self::ReceiptOffer { .. } => "receipt_offer",
            Self::Error { .. } => "error",
            Self::Done => "done",
        }
    }
}
