use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeMode {
    Performance,
    #[default]
    Balanced,
    Battery,
    Offline,
    RelayOnly,
    Private,
}

impl NodeMode {
    pub fn discovery_enabled(self) -> bool {
        !matches!(self, Self::Offline | Self::Private)
    }

    pub fn unsolicited_relay(self) -> bool {
        matches!(self, Self::Performance | Self::Balanced | Self::RelayOnly)
    }

    pub fn retain_encounters(self) -> bool {
        !matches!(self, Self::Private | Self::Offline)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    #[default]
    Personal,
    Mobile,
    Relay,
    Gateway,
    Archive,
    Edge,
    Bridge,
}

impl NodeRole {
    pub fn from_str_role(s: &str) -> Option<Self> {
        Some(match s {
            "personal" => Self::Personal,
            "mobile" => Self::Mobile,
            "relay" => Self::Relay,
            "gateway" => Self::Gateway,
            "archive" => Self::Archive,
            "edge" => Self::Edge,
            "bridge" => Self::Bridge,
            _ => return None,
        })
    }
}
