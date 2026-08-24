//! Channel subscriptions. Nodes MUST NOT store every public channel by default.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelFilter {
    Subscribe,
    Ignore,
    RelayOnly,
    MetadataOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPolicy {
    Public,
    SignedPublic,
    Private,
    GroupEncrypted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSub {
    pub name: String,
    pub filter: ChannelFilter,
    pub policy: ChannelPolicy,
}
