//! Cryptographic policy lives here. Networking crates MUST go through `CryptoProvider`.
//!
//! Constructions: Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305, BLAKE3, HMAC-SHA256.
//! No custom primitives.

use crate::{
    DIGEST_LEN, DdError, Digest, ErrorCode, HashAlgorithm, NONCE_LEN, PeerId, PublicIdentity,
    RecipientWrap, Result,
};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

pub const ENC_SCHEME: &str = "x25519-hkdf-chacha20poly1305-v2";
pub const SESSION_SCHEME: &str = "x25519-hkdf-chacha20poly1305-session-v2";

pub trait CryptoProvider: Send + Sync {
    fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Digest;
    fn sign(&self, sk: &SigningKey, msg: &[u8]) -> [u8; 64];
    fn verify(&self, pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()>;
    fn aead_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>>;
    fn aead_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultProvider;

impl CryptoProvider for DefaultProvider {
    fn hash(&self, alg: HashAlgorithm, data: &[u8]) -> Digest {
        match alg {
            HashAlgorithm::Blake3 => Digest(*blake3::hash(data).as_bytes()),
            HashAlgorithm::Sha256 => Digest(Sha256::digest(data).into()),
        }
    }

    fn sign(&self, sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
        sk.sign(msg).to_bytes()
    }

    fn verify(&self, pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let vk =
            VerifyingKey::from_bytes(pk).map_err(|_| DdError::crypto("bad ed25519 public key"))?;
        vk.verify(msg, &Signature::from_bytes(sig))
            .map_err(|_| DdError::crypto("signature invalid"))
    }

    fn aead_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>> {
        let aead =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| DdError::crypto("aead key"))?;
        aead.encrypt(nonce.into(), Payload { msg: pt, aad })
            .map_err(|_| DdError::crypto("encrypt failed"))
    }

    fn aead_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>> {
        let aead =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| DdError::crypto("aead key"))?;
        aead.decrypt(nonce.into(), Payload { msg: ct, aad })
            .map_err(|_| DdError::crypto("decrypt failed"))
    }
}

impl DefaultProvider {
    pub fn peer_id(&self, ed: &[u8; 32], x: &[u8; 32]) -> PeerId {
        let mut buf = Vec::from(&b"ddp-nid-v2"[..]);
        buf.extend_from_slice(ed);
        buf.extend_from_slice(x);
        PeerId::from_digest(self.hash(HashAlgorithm::Blake3, &buf).0)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateIdentity {
    #[zeroize(skip)]
    pub public: PublicIdentity,
    #[zeroize(skip)]
    pub peer_id: PeerId,
    ed25519: [u8; 32],
    x25519: [u8; 32],
}

impl PrivateIdentity {
    pub fn generate() -> Self {
        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        OsRng.fill_bytes(&mut ed);
        OsRng.fill_bytes(&mut x);
        Self::from_secrets(ed, x)
    }

    pub fn from_secrets(ed25519: [u8; 32], x25519: [u8; 32]) -> Self {
        let p = DefaultProvider;
        let signing = SigningKey::from_bytes(&ed25519);
        let ed_pk = signing.verifying_key().to_bytes();
        let x_sk = StaticSecret::from(x25519);
        let x_pk = XPublic::from(&x_sk).to_bytes();
        let mut pre = Vec::from(&b"ddp-id-v2"[..]);
        pre.extend_from_slice(&ed_pk);
        pre.extend_from_slice(&x_pk);
        let signature = p.sign(&signing, &pre);
        let public = PublicIdentity {
            version: 2,
            ed25519_pk: ed_pk,
            x25519_pk: x_pk,
            signature,
        };
        let peer_id = p.peer_id(&ed_pk, &x_pk);
        Self {
            public,
            peer_id,
            ed25519,
            x25519,
        }
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed25519)
    }

    pub fn x25519_secret(&self) -> StaticSecret {
        StaticSecret::from(self.x25519)
    }

    pub fn ed25519_bytes(&self) -> [u8; 32] {
        self.ed25519
    }

    pub fn x25519_bytes(&self) -> [u8; 32] {
        self.x25519
    }
}

pub fn verify_identity(id: &PublicIdentity) -> Result<PeerId> {
    if id.version != 2 {
        return Err(DdError::protocol(
            ErrorCode::Ddp1002UnsupportedVersion,
            "identity version",
        ));
    }
    let p = DefaultProvider;
    let mut pre = Vec::from(&b"ddp-id-v2"[..]);
    pre.extend_from_slice(&id.ed25519_pk);
    pre.extend_from_slice(&id.x25519_pk);
    p.verify(&id.ed25519_pk, &pre, &id.signature)?;
    Ok(p.peer_id(&id.ed25519_pk, &id.x25519_pk))
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn generate_cek() -> [u8; 32] {
    random_bytes()
}

fn wrap_derive(shared: &[u8; 32], eph_pk: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(eph_pk), shared);
    let mut key = [0u8; 32];
    hk.expand(b"ddp-wrap-v2", &mut key)
        .map_err(|_| DdError::crypto("hkdf wrap"))?;
    Ok(key)
}

pub fn wrap_cek(
    recipient_x25519: &[u8; 32],
    recipient: PeerId,
    cek: &[u8; 32],
) -> Result<RecipientWrap> {
    let eph_sk = StaticSecret::random_from_rng(OsRng);
    let eph_pk = XPublic::from(&eph_sk);
    let shared = eph_sk.diffie_hellman(&XPublic::from(*recipient_x25519));
    let key = wrap_derive(shared.as_bytes(), eph_pk.as_bytes())?;
    let nonce = random_bytes::<NONCE_LEN>();
    let p = DefaultProvider;
    let mut aad = Vec::from(&b"ddp-wrap-aad-v2"[..]);
    aad.extend_from_slice(recipient.as_bytes());
    let wrapped = p.aead_encrypt(&key, &nonce, &aad, cek)?;
    Ok(RecipientWrap {
        peer: recipient,
        eph_pk: eph_pk.to_bytes(),
        nonce,
        wrapped_key: wrapped,
    })
}

pub fn unwrap_cek(identity: &PrivateIdentity, wrap: &RecipientWrap) -> Result<[u8; 32]> {
    if wrap.peer != identity.peer_id {
        return Err(DdError::protocol(
            ErrorCode::Ddp1008NotRecipient,
            "wrap is for another peer",
        ));
    }
    let eph = XPublic::from(wrap.eph_pk);
    let shared = identity.x25519_secret().diffie_hellman(&eph);
    let key = wrap_derive(shared.as_bytes(), eph.as_bytes())?;
    let p = DefaultProvider;
    let mut aad = Vec::from(&b"ddp-wrap-aad-v2"[..]);
    aad.extend_from_slice(identity.peer_id.as_bytes());
    let cek = p.aead_decrypt(&key, &wrap.nonce, &aad, &wrap.wrapped_key)?;
    if cek.len() != 32 {
        return Err(DdError::crypto("wrapped key length"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&cek);
    Ok(out)
}

pub fn encrypt_payload(
    cek: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    DefaultProvider.aead_encrypt(cek, nonce, aad, pt)
}

pub fn decrypt_payload(
    cek: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    DefaultProvider.aead_decrypt(cek, nonce, aad, ct)
}

/// Session keys from ephemeral X25519 (forward secrecy). Replay: transcript hash bound into HKDF.
pub struct SessionKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
    pub transcript: [u8; DIGEST_LEN],
}

pub fn session_keys(
    initiator: bool,
    local_eph_sk: &StaticSecret,
    remote_eph_pk: &XPublic,
    transcript: &[u8],
) -> Result<SessionKeys> {
    let shared = local_eph_sk.diffie_hellman(remote_eph_pk);
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared.as_bytes());
    let mut okm = [0u8; 64];
    hk.expand(b"ddp-session-v2", &mut okm)
        .map_err(|_| DdError::crypto("hkdf session"))?;
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    let transcript_d = DefaultProvider.hash(HashAlgorithm::Blake3, transcript).0;
    Ok(if initiator {
        SessionKeys {
            send: a,
            recv: b,
            transcript: transcript_d,
        }
    } else {
        SessionKeys {
            send: b,
            recv: a,
            transcript: transcript_d,
        }
    })
}

pub fn hmac_tag(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out[..16]);
    tag
}

pub fn u64_be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

pub fn push_lp_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

pub fn x25519_ephemeral() -> (StaticSecret, XPublic) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = XPublic::from(&sk);
    (sk, pk)
}

pub use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_wrap() {
        let a = PrivateIdentity::generate();
        let b = PrivateIdentity::generate();
        assert_eq!(verify_identity(&a.public).unwrap(), a.peer_id);
        let cek = generate_cek();
        let wrap = wrap_cek(&b.public.x25519_pk, b.peer_id, &cek).unwrap();
        assert_eq!(unwrap_cek(&b, &wrap).unwrap(), cek);
        assert!(unwrap_cek(&a, &wrap).is_err());
    }

    #[test]
    fn decode_encode_hash() {
        let p = DefaultProvider;
        let d = p.hash(HashAlgorithm::Blake3, b"abc");
        assert_eq!(d.0.len(), 32);
    }
}
