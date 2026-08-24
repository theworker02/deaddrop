use crate::crypto::{CryptoProvider, DefaultProvider, verify_identity};
use crate::{
    DdError, ErrorCode, HashAlgorithm, PeerId, PublicIdentity, Result, TrustState, hex_decode,
    hex_encode,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use crate::crypto::PrivateIdentity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactCard {
    pub name: Option<String>,
    pub identity: String,
    pub fingerprint: String,
    pub capabilities: Vec<String>,
    pub public: PublicIdentity,
}

impl ContactCard {
    pub fn from_public(name: Option<String>, public: PublicIdentity) -> Result<Self> {
        let peer = verify_identity(&public)?;
        let fp = fingerprint(&public);
        Ok(Self {
            name,
            identity: peer.to_string(),
            fingerprint: fp,
            capabilities: Vec::new(),
            public,
        })
    }

    pub fn to_text(&self) -> String {
        format!(
            "DD Contact\nName: {}\nIdentity: {}\nFingerprint: {}\nCapabilities: {}\n",
            self.name.as_deref().unwrap_or(""),
            self.identity,
            self.fingerprint,
            self.capabilities.join(",")
        )
    }

    pub fn to_ddcontact(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| DdError::crypto(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(b"DD Contact") {
            return parse_text_card(std::str::from_utf8(bytes).map_err(|_| {
                DdError::protocol(ErrorCode::Ddp1001InvalidFrame, "contact not utf-8")
            })?);
        }
        serde_json::from_slice(bytes).map_err(|e| DdError::invalid_frame(e.to_string()))
    }

    pub fn peer_id(&self) -> Result<PeerId> {
        verify_identity(&self.public)
    }
}

pub fn fingerprint(public: &PublicIdentity) -> String {
    let p = DefaultProvider;
    let mut buf = Vec::from(&b"ddp-fp-v2"[..]);
    buf.extend_from_slice(&public.ed25519_pk);
    buf.extend_from_slice(&public.x25519_pk);
    let d = p.hash(HashAlgorithm::Blake3, &buf);
    hex_encode(&d.0[..8])
}

/// Human-comparable form `DD-7F91-22BA`. The cryptographic identity remains `dd:`.
pub fn display_fingerprint(public: &PublicIdentity) -> String {
    let h = fingerprint(public).to_ascii_uppercase();
    if h.len() >= 8 {
        format!("DD-{}-{}", &h[..4], &h[4..8])
    } else {
        format!("DD-{h}")
    }
}

fn parse_text_card(s: &str) -> Result<ContactCard> {
    let mut name = None;
    let mut identity = String::new();
    let mut fingerprint = String::new();
    let mut capabilities = Vec::new();
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("Name: ") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Identity: ") {
            identity = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Fingerprint: ") {
            fingerprint = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Capabilities: ") {
            capabilities = v
                .split(',')
                .filter(|x| !x.is_empty())
                .map(|x| x.trim().to_string())
                .collect();
        }
    }
    Err(DdError::protocol(
        ErrorCode::Ddp1001InvalidFrame,
        format!(
            "text contact {identity} {fingerprint} {name:?} {capabilities:?} requires JSON public keys"
        ),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub card: ContactCard,
    pub trust: TrustState,
}

#[derive(Debug, Default)]
pub struct ContactBook {
    inner: HashMap<PeerId, Contact>,
}

impl ContactBook {
    pub fn insert(&mut self, mut contact: Contact) -> Result<PeerId> {
        let id = contact.card.peer_id()?;
        if contact.trust == TrustState::Unknown {
            contact.trust = TrustState::Known;
        }
        self.inner.insert(id, contact);
        Ok(id)
    }

    pub fn observe(&mut self, public: PublicIdentity) -> Result<PeerId> {
        let id = verify_identity(&public)?;
        self.inner.entry(id).or_insert_with(|| Contact {
            card: ContactCard::from_public(None, public).expect("verified"),
            trust: TrustState::Observed,
        });
        Ok(id)
    }

    pub fn get(&self, id: &PeerId) -> Option<&Contact> {
        self.inner.get(id)
    }

    pub fn get_mut(&mut self, id: &PeerId) -> Option<&mut Contact> {
        self.inner.get_mut(id)
    }

    pub fn resolve(&self, spec: &str) -> Result<(PeerId, PublicIdentity)> {
        let raw = spec.trim();
        if raw.is_empty() {
            return Err(DdError::protocol(
                ErrorCode::Ddi5001UnknownContact,
                "empty peer",
            ));
        }
        let named: Vec<_> = self
            .inner
            .iter()
            .filter(|(_, c)| {
                c.trust != TrustState::Blocked
                    && c.card
                        .name
                        .as_deref()
                        .is_some_and(|n| n.eq_ignore_ascii_case(raw))
            })
            .collect();
        match named.len() {
            1 => {
                let (id, c) = named[0];
                return Ok((*id, c.card.public.clone()));
            }
            n if n > 1 => {
                return Err(DdError::protocol(
                    ErrorCode::Ddp1005BadIdentifier,
                    "ambiguous contact name",
                ));
            }
            _ => {}
        }
        let rest = raw.strip_prefix("dd:").unwrap_or(raw).to_ascii_lowercase();
        if rest.len() < 8 {
            return Err(DdError::protocol(
                ErrorCode::Ddi5001UnknownContact,
                format!(
                    "unknown name '{raw}' (import a .ddcontact, or use dd: plus at least 8 hex chars)"
                ),
            ));
        }
        let matches: Vec<_> = self
            .inner
            .iter()
            .filter(|(id, c)| {
                c.trust != TrustState::Blocked && hex_encode(id.as_bytes()).starts_with(&rest)
            })
            .collect();
        match matches.len() {
            1 => {
                let (id, c) = matches[0];
                Ok((*id, c.card.public.clone()))
            }
            0 => Err(DdError::protocol(
                ErrorCode::Ddi5001UnknownContact,
                "no matching contact",
            )),
            _ => Err(DdError::protocol(
                ErrorCode::Ddp1005BadIdentifier,
                "ambiguous prefix",
            )),
        }
    }

    pub fn set_trust(&mut self, id: &PeerId, trust: TrustState) {
        if let Some(c) = self.inner.get_mut(id) {
            c.trust = trust;
        }
    }

    pub fn all(&self) -> impl Iterator<Item = (&PeerId, &Contact)> {
        self.inner.iter()
    }
}

/// Old identity attests a replacement. Reachability is not silently destroyed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityTransition {
    pub old_peer: PeerId,
    pub new_public: PublicIdentity,
    pub created_at: u64,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl IdentityTransition {
    pub fn issue(old: &PrivateIdentity, new_public: PublicIdentity, now: u64) -> Result<Self> {
        let new_id = verify_identity(&new_public)?;
        let mut msg = Vec::from(&b"ddp-rotate-v2"[..]);
        msg.extend_from_slice(old.peer_id.as_bytes());
        msg.extend_from_slice(new_id.as_bytes());
        msg.extend_from_slice(&now.to_be_bytes());
        let sig = DefaultProvider.sign(&old.signing_key(), &msg);
        Ok(Self {
            old_peer: old.peer_id,
            new_public,
            created_at: now,
            signature: sig,
        })
    }

    pub fn verify(&self, old_public: &PublicIdentity) -> Result<PeerId> {
        let old_id = verify_identity(old_public)?;
        if old_id != self.old_peer {
            return Err(DdError::crypto("transition old peer mismatch"));
        }
        let new_id = verify_identity(&self.new_public)?;
        let mut msg = Vec::from(&b"ddp-rotate-v2"[..]);
        msg.extend_from_slice(old_id.as_bytes());
        msg.extend_from_slice(new_id.as_bytes());
        msg.extend_from_slice(&self.created_at.to_be_bytes());
        DefaultProvider.verify(&old_public.ed25519_pk, &msg, &self.signature)?;
        Ok(new_id)
    }
}

#[derive(Serialize, Deserialize)]
pub struct IdentityFile {
    pub version: u8,
    pub ed25519_secret_hex: String,
    pub x25519_secret_hex: String,
}

impl IdentityFile {
    pub fn from_private(id: &PrivateIdentity) -> Self {
        Self {
            version: 2,
            ed25519_secret_hex: hex_encode(&id.ed25519_bytes()),
            x25519_secret_hex: hex_encode(&id.x25519_bytes()),
        }
    }

    pub fn into_private(self) -> Result<PrivateIdentity> {
        let ed = decode32(&self.ed25519_secret_hex)?;
        let x = decode32(&self.x25519_secret_hex)?;
        Ok(PrivateIdentity::from_secrets(ed, x))
    }
}

fn decode32(h: &str) -> Result<[u8; 32]> {
    let v = hex_decode(h)?;
    if v.len() != 32 {
        return Err(DdError::crypto("expected 32 bytes"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_attests() {
        let old = PrivateIdentity::generate();
        let new = PrivateIdentity::generate();
        let t = IdentityTransition::issue(&old, new.public.clone(), 10).unwrap();
        assert_eq!(t.verify(&old.public).unwrap(), new.peer_id);
    }

    #[test]
    fn resolve_short_name() {
        let a = PrivateIdentity::generate();
        let mut book = ContactBook::default();
        book.insert(Contact {
            card: ContactCard::from_public(Some("laptop".into()), a.public.clone()).unwrap(),
            trust: TrustState::Known,
        })
        .unwrap();
        let (id, _) = book.resolve("laptop").unwrap();
        assert_eq!(id, a.peer_id);
        assert!(book.resolve("nope").is_err());
    }
}
