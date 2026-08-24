use serde::{Deserialize, Serialize};

/// Contact trust. Discovery never implies `Known` or `Verified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    #[default]
    Unknown,
    Observed,
    Known,
    Verified,
    Blocked,
}
