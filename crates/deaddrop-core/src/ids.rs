use crate::Result;
use crate::error::DdError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub const DIGEST_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    #[default]
    Blake3,
    Sha256,
}

impl HashAlgorithm {
    pub fn code(self) -> &'static str {
        match self {
            Self::Blake3 => "b3",
            Self::Sha256 => "sha256",
        }
    }

    pub fn parse_code(s: &str) -> Result<Self> {
        match s {
            "b3" | "blake3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            _ => Err(DdError::protocol(
                crate::error::ErrorCode::Ddp1004UnsupportedHash,
                format!("unknown hash algorithm {s}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest(#[serde(with = "serde_bytes")] pub [u8; DIGEST_LEN]);

impl Digest {
    pub fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }
}

fn parse_prefixed(s: &str, expected: &str) -> Result<(HashAlgorithm, Digest)> {
    let mut parts = s.splitn(3, ':');
    let prefix = parts.next().unwrap_or("");
    let alg = parts.next().unwrap_or("");
    let hex = parts.next().unwrap_or("");
    if prefix != expected {
        return Err(DdError::protocol(
            crate::error::ErrorCode::Ddp1005BadIdentifier,
            format!("expected {expected}:…, got {s}"),
        ));
    }
    let algorithm = HashAlgorithm::parse_code(alg)?;
    let bytes = crate::hexutil::hex_decode(hex)?;
    if bytes.len() != DIGEST_LEN {
        return Err(DdError::protocol(
            crate::error::ErrorCode::Ddp1005BadIdentifier,
            "digest must be 32 bytes",
        ));
    }
    let mut d = [0u8; DIGEST_LEN];
    d.copy_from_slice(&bytes);
    Ok((algorithm, Digest(d)))
}

fn format_prefixed(prefix: &str, alg: HashAlgorithm, digest: &Digest) -> String {
    format!(
        "{prefix}:{}:{}",
        alg.code(),
        crate::hexutil::hex_encode(&digest.0)
    )
}

macro_rules! typed_id {
    ($name:ident, $prefix:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name {
            pub algorithm: HashAlgorithm,
            pub digest: Digest,
        }

        impl $name {
            pub fn new(algorithm: HashAlgorithm, digest: Digest) -> Self {
                Self { algorithm, digest }
            }

            pub fn blake3(raw: [u8; DIGEST_LEN]) -> Self {
                Self {
                    algorithm: HashAlgorithm::Blake3,
                    digest: Digest(raw),
                }
            }

            pub fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
                self.digest.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&format_prefixed($prefix, self.algorithm, &self.digest))
            }
        }

        impl FromStr for $name {
            type Err = DdError;
            fn from_str(s: &str) -> Result<Self> {
                let (algorithm, digest) = parse_prefixed(s, $prefix)?;
                Ok(Self { algorithm, digest })
            }
        }
    };
}

typed_id!(ContentId, "ddc");
typed_id!(ObjectId, "ddo");
typed_id!(ChunkId, "ddk");
typed_id!(ManifestId, "ddm");

/// Cryptographic node identifier. Text form: `dd:` + 64 hex characters of the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(#[serde(with = "serde_bytes")] pub [u8; DIGEST_LEN]);

impl PeerId {
    pub fn from_digest(d: [u8; DIGEST_LEN]) -> Self {
        Self(d)
    }

    pub fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    pub fn short(&self) -> String {
        format!("dd:{}…", crate::hexutil::hex_encode(&self.0[..4]))
    }
}

/// Daily rotating discovery identifier. Does not replace the cryptographic PeerId.
pub fn ephemeral_discovery_id(peer: PeerId, now: u64) -> PeerId {
    let day = now / 86400;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ddp-eph-v1");
    hasher.update(peer.as_bytes());
    hasher.update(&day.to_be_bytes());
    PeerId::from_digest(*hasher.finalize().as_bytes())
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dd:{}", crate::hexutil::hex_encode(&self.0))
    }
}

impl FromStr for PeerId {
    type Err = DdError;
    fn from_str(s: &str) -> Result<Self> {
        let rest = s.strip_prefix("dd:").ok_or_else(|| {
            DdError::protocol(
                crate::error::ErrorCode::Ddp1005BadIdentifier,
                "peer id must start with dd:",
            )
        })?;
        if rest.len() != 64 {
            return Err(DdError::protocol(
                crate::error::ErrorCode::Ddp1005BadIdentifier,
                "peer id must be dd: plus 64 hex characters",
            ));
        }
        let bytes = crate::hexutil::hex_decode(rest)?;
        let mut id = [0u8; DIGEST_LEN];
        id.copy_from_slice(&bytes);
        Ok(Self(id))
    }
}

pub fn peer_id_matches_prefix(id: &PeerId, prefix_hex: &str) -> bool {
    let full = crate::hexutil::hex_encode(&id.0);
    full.starts_with(&prefix_hex.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_ids_roundtrip() {
        let raw = [0xab; 32];
        let c = ContentId::blake3(raw);
        let s = c.to_string();
        assert!(s.starts_with("ddc:b3:"));
        assert_eq!(s.parse::<ContentId>().unwrap(), c);
        let p = PeerId::from_digest(raw);
        assert_eq!(p.to_string().parse::<PeerId>().unwrap(), p);
    }
}
