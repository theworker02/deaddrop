use crate::{ObjectId, PeerId};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    PeerDiscovered {
        peer: String,
    },
    PeerAuthenticated {
        peer: String,
    },
    PeerDisconnected {
        peer: String,
    },
    DropCreated {
        object: String,
    },
    DropAccepted {
        object: String,
    },
    DropForwarded {
        object: String,
        peer: String,
    },
    DropDelivered {
        object: String,
    },
    DropReceived {
        object: String,
    },
    DropExpired {
        object: String,
    },
    TransferStarted {
        object: String,
    },
    TransferPaused {
        object: String,
    },
    TransferCompleted {
        object: String,
    },
    RouteChanged {
        object: String,
        peer: String,
    },
    SpaceUpdated {
        name: String,
    },
    ChannelUpdated {
        name: String,
    },
    ChunkReceived {
        object: String,
        index: u32,
    },
    ChunkVerified {
        object: String,
        index: u32,
    },
    ChunkRejected {
        object: String,
        index: u32,
    },
    RouteSelected {
        object: String,
        peer: String,
        score: f64,
    },
    RouteRejected {
        object: String,
        peer: String,
    },
    StoragePressure {
        used: u64,
        limit: u64,
    },
}

impl Event {
    pub fn peer_discovered(p: PeerId) -> Self {
        Self::PeerDiscovered {
            peer: p.to_string(),
        }
    }
    pub fn drop_created(o: ObjectId) -> Self {
        Self::DropCreated {
            object: o.to_string(),
        }
    }
    pub fn peer_connected(p: PeerId) -> Self {
        Self::PeerAuthenticated {
            peer: p.to_string(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub peers_discovered: AtomicU64,
    pub active_sessions: AtomicU64,
    pub drops_created: AtomicU64,
    pub drops_delivered: AtomicU64,
    pub drops_relayed: AtomicU64,
    pub chunks_transferred: AtomicU64,
    pub bytes_transferred: AtomicU64,
    pub route_decisions: AtomicU64,
    pub failed_auth: AtomicU64,
    pub expired: AtomicU64,
}

impl Metrics {
    pub fn snapshot(&self) -> MetricsSnap {
        MetricsSnap {
            peers_discovered: self.peers_discovered.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            drops_created: self.drops_created.load(Ordering::Relaxed),
            drops_delivered: self.drops_delivered.load(Ordering::Relaxed),
            drops_relayed: self.drops_relayed.load(Ordering::Relaxed),
            chunks_transferred: self.chunks_transferred.load(Ordering::Relaxed),
            bytes_transferred: self.bytes_transferred.load(Ordering::Relaxed),
            route_decisions: self.route_decisions.load(Ordering::Relaxed),
            failed_auth: self.failed_auth.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnap {
    pub peers_discovered: u64,
    pub active_sessions: u64,
    pub drops_created: u64,
    pub drops_delivered: u64,
    pub drops_relayed: u64,
    pub chunks_transferred: u64,
    pub bytes_transferred: u64,
    pub route_decisions: u64,
    pub failed_auth: u64,
    pub expired: u64,
}

#[derive(Clone, Default)]
pub struct Bus {
    events: Arc<Mutex<Vec<Event>>>,
}

impl Bus {
    pub fn emit(&self, e: Event) {
        tracing::info!(target: "ddp", event = ?e, "event");
        self.events.lock().expect("bus").push(e);
    }
    pub fn take(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().expect("bus"))
    }
}
