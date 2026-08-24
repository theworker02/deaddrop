use crate::crypto::{CryptoProvider, DefaultProvider, PrivateIdentity};
use crate::{ObjectId, PeerId, ReceiptKind, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub kind: ReceiptKind,
    pub object_id: ObjectId,
    pub issuer: PeerId,
    pub created_at: u64,
    /// Optional peer this receipt attests a forward toward. Absent on older receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_peer: Option<PeerId>,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl Receipt {
    pub fn issue(
        kind: ReceiptKind,
        object_id: ObjectId,
        issuer: &PrivateIdentity,
        now: u64,
    ) -> Self {
        let mut msg = preimage(kind, &object_id, issuer.peer_id, now, None);
        let signature = DefaultProvider.sign(&issuer.signing_key(), &msg);
        msg.clear();
        Self {
            kind,
            object_id,
            issuer: issuer.peer_id,
            created_at: now,
            witness_peer: None,
            signature,
        }
    }

    /// Compact signed statement: issuer possessed `object_id` and forwarded toward `to`.
    pub fn issue_forwarded(
        object_id: ObjectId,
        issuer: &PrivateIdentity,
        to: PeerId,
        now: u64,
    ) -> Self {
        let mut msg = preimage(
            ReceiptKind::Forwarded,
            &object_id,
            issuer.peer_id,
            now,
            Some(to),
        );
        let signature = DefaultProvider.sign(&issuer.signing_key(), &msg);
        msg.clear();
        Self {
            kind: ReceiptKind::Forwarded,
            object_id,
            issuer: issuer.peer_id,
            created_at: now,
            witness_peer: Some(to),
            signature,
        }
    }

    pub fn verify(&self, issuer_pk: &[u8; 32]) -> Result<()> {
        let msg = preimage(
            self.kind,
            &self.object_id,
            self.issuer,
            self.created_at,
            self.witness_peer,
        );
        DefaultProvider.verify(issuer_pk, &msg, &self.signature)
    }
}

fn preimage(
    kind: ReceiptKind,
    object_id: &ObjectId,
    issuer: PeerId,
    ts: u64,
    witness: Option<PeerId>,
) -> Vec<u8> {
    let mut m = Vec::from(&b"ddp-receipt-v2"[..]);
    m.push(kind as u8);
    m.extend_from_slice(object_id.as_bytes());
    m.extend_from_slice(issuer.as_bytes());
    m.extend_from_slice(&ts.to_be_bytes());
    if let Some(p) = witness {
        m.extend_from_slice(b"ddp-witness-v2");
        m.extend_from_slice(p.as_bytes());
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateIdentity;

    #[test]
    fn receipt_sign_verify() {
        let n = PrivateIdentity::generate();
        let oid = ObjectId::blake3([9u8; 32]);
        let r = Receipt::issue(ReceiptKind::Delivered, oid, &n, 42);
        r.verify(&n.public.ed25519_pk).unwrap();
        let f = Receipt::issue_forwarded(oid, &n, n.peer_id, 43);
        f.verify(&n.public.ed25519_pk).unwrap();
        assert!(f.witness_peer.is_some());
    }
}
