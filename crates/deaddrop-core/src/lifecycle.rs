use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropState {
    Created,
    Stored,
    Queued,
    Offered,
    PartiallyTransferred,
    Forwarded,
    Delivered,
    Expired,
    Rejected,
    GarbageCollected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Disconnected,
    TransportConnected,
    Negotiating,
    Authenticated,
    InventorySync,
    Transferring,
    Idle,
    Closing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    Local,
    Incoming,
    Relay,
    Temporary,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Accepted,
    Stored,
    Forwarded,
    Delivered,
    /// Application opt-in only. MUST NOT be emitted by core unless requested.
    Opened,
    Rejected,
    Expired,
}
