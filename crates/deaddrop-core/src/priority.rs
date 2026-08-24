use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Bulk = 0,
    #[default]
    Normal = 1,
    Important = 2,
    Urgent = 3,
}

impl Priority {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Bulk,
            2 => Self::Important,
            3 => Self::Urgent,
            _ => Self::Normal,
        }
    }

    /// Per-peer share of transfer slots. Urgent cannot monopolize the link.
    pub fn slot_weight(self) -> u32 {
        match self {
            Self::Bulk => 1,
            Self::Normal => 2,
            Self::Important => 3,
            Self::Urgent => 3,
        }
    }

    /// CLI names: background/bulk, normal, high, critical.
    /// Wire values stay Bulk=0, Normal=1, Important=2, Urgent=3.
    pub fn parse_cli(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "background" | "bulk" => Some(Self::Bulk),
            "normal" => Some(Self::Normal),
            "high" | "important" => Some(Self::Important),
            "critical" | "urgent" => Some(Self::Urgent),
            _ => None,
        }
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Bulk => "bulk",
            Self::Normal => "normal",
            Self::Important => "high",
            Self::Urgent => "critical",
        }
    }
}
