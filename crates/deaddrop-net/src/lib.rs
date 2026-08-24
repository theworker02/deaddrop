//! DeadDrop networking: discovery, transports, sessions, sync, routing.

pub mod control;
pub mod discovery;
pub mod node;
pub mod routing;
pub mod scheduler;
pub mod sync;
pub mod transport;

pub use discovery::{Endpoint, last_locator, remember_locator, remembered_locator, scan_lan};
pub use node::{InboxItem, Node, SendOpts};
pub use routing::{
    AdaptiveRouter, DeliveryForecast, RouteDecision, RoutingStrategy, predict_delivery,
    strategy_from_kind,
};
pub use sync::{SyncOpts, SyncStats, sync_session};
