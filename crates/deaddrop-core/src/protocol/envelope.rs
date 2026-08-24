use crate::chunk::{ChunkingAlg, Manifest, chunk_payload, reassemble};
use crate::crypto::{
    CryptoProvider, DefaultProvider, ENC_SCHEME, PrivateIdentity, decrypt_payload, encrypt_payload,
    generate_cek, push_lp_str, random_bytes, u64_be, unwrap_cek, wrap_cek,
};
use crate::{
    DEFAULT_TTL_SECS, DdError, Destination, DropEnvelope, ErrorCode, HashAlgorithm, MAX_RECIPIENTS,
    MAX_TTL_SECS, MIN_TTL_SECS, PROTOCOL_VERSION, PayloadDescriptor, PeerId, Priority,
    PublicIdentity, Result, RoutingPolicy, SecurityDescriptor,
};

pub struct CreateDrop<'a> {
    pub author: &'a PrivateIdentity,
    pub recipients: Vec<(PeerId, PublicIdentity)>,
    pub destination: Destination,
    pub plaintext: Vec<u8>,
    pub now: u64,
    pub ttl_secs: Option<u64>,
    pub priority: Priority,
    pub routing: RoutingPolicy,
    pub application: String,
    pub topic: Option<String>,
    pub chunking: ChunkingAlg,
    pub compress: bool,
    pub hop_limit: u8,
    pub public: bool,
    pub seal_until: Option<u64>,
    pub seal_quorum: Option<u32>,
    pub erasure: Option<crate::chunk::ErasureSpec>,
}

pub struct BuiltDrop {
    pub envelope: DropEnvelope,
    pub manifest: Manifest,
    pub chunks: Vec<Vec<u8>>,
}

pub fn envelope_preimage(env: &DropEnvelope) -> Vec<u8> {
    let mut buf = Vec::from(&b"ddp-env-v2"[..]);
    buf.extend_from_slice(&env.protocol_version.to_be_bytes());
    buf.extend_from_slice(env.source.as_bytes());
    buf.extend_from_slice(&u64_be(env.creation_time));
    buf.extend_from_slice(&u64_be(env.expiration));
    buf.push(env.priority.as_u8());
    buf.push(env.hop_limit);
    push_lp_str(&mut buf, &env.application);
    match &env.payload_descriptor {
        PayloadDescriptor::Chunked {
            length,
            manifest_id,
            content_id,
        } => {
            buf.extend_from_slice(&u64_be(*length));
            buf.extend_from_slice(manifest_id.as_bytes());
            buf.extend_from_slice(content_id.as_bytes());
        }
        PayloadDescriptor::Inline { length, content_id }
        | PayloadDescriptor::Blob { length, content_id } => {
            buf.extend_from_slice(&u64_be(*length));
            buf.extend_from_slice(content_id.as_bytes());
        }
        PayloadDescriptor::Manifest { manifest_id }
        | PayloadDescriptor::StreamManifest { manifest_id } => {
            buf.extend_from_slice(manifest_id.as_bytes());
        }
        PayloadDescriptor::Collection { members } => {
            buf.extend_from_slice(&(members.len() as u32).to_be_bytes());
            for m in members {
                buf.extend_from_slice(m.as_bytes());
            }
        }
    }
    buf.extend_from_slice(&env.author_pk);
    if !env.extensions.is_empty() {
        buf.extend_from_slice(b"ddp-ext-v2");
        for e in &env.extensions {
            crate::crypto::push_lp_str(&mut buf, &e.name);
            buf.push(u8::from(e.critical));
            buf.extend_from_slice(&(e.data.len() as u32).to_be_bytes());
            buf.extend_from_slice(&e.data);
        }
    }
    buf
}

pub fn build_drop(req: CreateDrop<'_>) -> Result<BuiltDrop> {
    if req.recipients.len() > MAX_RECIPIENTS {
        return Err(DdError::protocol(
            ErrorCode::Ddp1006LimitExceeded,
            "too many recipients",
        ));
    }
    let ttl = req
        .ttl_secs
        .unwrap_or(DEFAULT_TTL_SECS)
        .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
    let expires = req.now.saturating_add(ttl);
    let mut body = req.plaintext;
    if req.compress {
        body = zstd_compress(&body)?;
    }
    let (ciphertext, security) = if req.public || matches!(req.destination, Destination::Public) {
        (
            body,
            SecurityDescriptor {
                scheme: "signed-only-v2".into(),
                public: true,
                wraps: vec![],
                content_nonce: [0u8; 12],
            },
        )
    } else {
        let cek = generate_cek();
        let nonce = random_bytes::<12>();
        let mut aad = Vec::from(&b"ddp-payload-aad-v2"[..]);
        aad.extend_from_slice(req.author.peer_id.as_bytes());
        let ct = encrypt_payload(&cek, &nonce, &aad, &body)?;
        let mut wraps = Vec::new();
        for (peer, ident) in &req.recipients {
            wraps.push(wrap_cek(&ident.x25519_pk, *peer, &cek)?);
        }
        (
            ct,
            SecurityDescriptor {
                scheme: ENC_SCHEME.into(),
                public: false,
                wraps,
                content_nonce: nonce,
            },
        )
    };
    let chunked = if let Some(spec) = req.erasure {
        crate::chunk::apply_erasure(chunk_payload(&ciphertext, req.chunking)?, spec)?
    } else {
        chunk_payload(&ciphertext, req.chunking)?
    };
    let manifest_id = chunked.manifest.id();
    let mut env = DropEnvelope {
        protocol_version: PROTOCOL_VERSION,
        object_id: crate::ObjectId::blake3([0u8; 32]),
        source: req.author.peer_id,
        destination: req.destination,
        creation_time: req.now,
        expiration: expires,
        priority: req.priority,
        hop_limit: req.hop_limit.clamp(1, crate::MAX_HOP_LIMIT),
        hop_count: 0,
        payload_descriptor: PayloadDescriptor::Chunked {
            length: chunked.manifest.total_length,
            manifest_id,
            content_id: chunked.manifest.payload_hash,
        },
        routing_policy: req.routing,
        security_descriptor: security,
        application: req.application,
        topic: req.topic,
        extensions: seal_extensions(req.seal_until, req.seal_quorum),
        author_pk: req.author.public.ed25519_pk,
        signature: [0u8; 64],
    };
    let pre = envelope_preimage(&env);
    env.signature = DefaultProvider.sign(&req.author.signing_key(), &pre);
    let oid_digest = DefaultProvider.hash(crate::HashAlgorithm::Blake3, &{
        let mut b = pre.clone();
        b.extend_from_slice(&env.signature);
        b
    });
    env.object_id = crate::ObjectId::blake3(oid_digest.0);
    Ok(BuiltDrop {
        envelope: env,
        manifest: chunked.manifest,
        chunks: chunked.chunks,
    })
}

fn seal_extensions(until: Option<u64>, quorum: Option<u32>) -> Vec<crate::Extension> {
    let mut out = Vec::new();
    if let Some(ts) = until {
        out.push(crate::Extension {
            name: crate::SEAL_UNTIL_EXT.into(),
            critical: false,
            data: ts.to_be_bytes().to_vec(),
        });
    }
    if let Some(n) = quorum {
        out.push(crate::Extension {
            name: crate::SEAL_QUORUM_EXT.into(),
            critical: false,
            data: n.to_be_bytes().to_vec(),
        });
    }
    out
}

fn zstd_compress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(data, 3).map_err(|e| DdError::crypto(e.to_string()))
}

pub fn zstd_decompress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data).map_err(|e| DdError::crypto(e.to_string()))
}

pub fn verify_envelope(env: &DropEnvelope, now: u64) -> Result<()> {
    if env.protocol_version != PROTOCOL_VERSION {
        return Err(DdError::protocol(
            ErrorCode::Ddp1002UnsupportedVersion,
            format!("DDP/{}", env.protocol_version),
        ));
    }
    env.validate_extension_count()?;
    for ext in &env.extensions {
        if ext.critical && ext.name != crate::SEAL_UNTIL_EXT && ext.name != crate::SEAL_QUORUM_EXT {
            return Err(DdError::protocol(
                ErrorCode::Ddp1003UnknownCriticalExtension,
                ext.name.clone(),
            ));
        }
    }
    if env.expiration <= env.creation_time {
        return Err(DdError::protocol(
            ErrorCode::Ddp1001InvalidFrame,
            "expiration",
        ));
    }
    if now >= env.expiration {
        return Err(DdError::protocol(ErrorCode::Ddp1007Expired, "expired"));
    }
    if env.hop_count > env.hop_limit {
        return Err(DdError::protocol(ErrorCode::Ddp1001InvalidFrame, "hops"));
    }
    let pre = envelope_preimage(env);
    DefaultProvider.verify(&env.author_pk, &pre, &env.signature)?;
    let oid = crate::ObjectId::blake3(
        DefaultProvider
            .hash(HashAlgorithm::Blake3, &{
                let mut b = pre;
                b.extend_from_slice(&env.signature);
                b
            })
            .0,
    );
    if oid != env.object_id {
        return Err(DdError::invalid_frame("object_id mismatch"));
    }
    Ok(())
}

pub fn decrypt_payload_for(
    identity: &PrivateIdentity,
    env: &DropEnvelope,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if env.security_descriptor.public {
        return Ok(ciphertext.to_vec());
    }
    let wrap = env
        .security_descriptor
        .wraps
        .iter()
        .find(|w| w.peer == identity.peer_id)
        .ok_or_else(|| DdError::protocol(ErrorCode::Ddp1008NotRecipient, "no wrap"))?;
    let cek = unwrap_cek(identity, wrap)?;
    let mut aad = Vec::from(&b"ddp-payload-aad-v2"[..]);
    aad.extend_from_slice(env.source.as_bytes());
    decrypt_payload(
        &cek,
        &env.security_descriptor.content_nonce,
        &aad,
        ciphertext,
    )
}

pub fn open_drop(
    identity: &PrivateIdentity,
    env: &DropEnvelope,
    manifest: &Manifest,
    chunks: &[Vec<u8>],
) -> Result<Vec<u8>> {
    open_drop_at(identity, env, manifest, chunks, crate::store::unix_now(), 0)
}

/// `receipt_issuers` is the count of distinct stored witness/delivery receipts.
/// Quorum seals are local policy, not a cryptographic time-lock.
pub fn open_drop_at(
    identity: &PrivateIdentity,
    env: &DropEnvelope,
    manifest: &Manifest,
    chunks: &[Vec<u8>],
    now: u64,
    receipt_issuers: u32,
) -> Result<Vec<u8>> {
    crate::sealed::enforce(env, now, receipt_issuers)?;
    let ct = if let Some(info) = &manifest.erasure {
        let _ = info;
        reassemble(manifest, chunks)?
    } else {
        reassemble(manifest, chunks)?
    };
    decrypt_payload_for(identity, env, &ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify_identity;

    #[test]
    fn build_verify_open() {
        let alice = PrivateIdentity::generate();
        let charlie = PrivateIdentity::generate();
        let cid = verify_identity(&charlie.public).unwrap();
        let built = build_drop(CreateDrop {
            author: &alice,
            recipients: vec![(cid, charlie.public.clone())],
            destination: Destination::One { peer: cid },
            plaintext: b"secret".to_vec(),
            now: 1_700_000_000,
            ttl_secs: Some(3600),
            priority: Priority::Normal,
            routing: RoutingPolicy::default(),
            application: "dd.file".into(),
            topic: None,
            chunking: crate::chunk::default_fixed(),
            compress: false,
            hop_limit: 8,
            public: false,
            seal_until: None,
            seal_quorum: None,
            erasure: None,
        })
        .unwrap();
        verify_envelope(&built.envelope, 1_700_000_100).unwrap();
        let pt = open_drop(&charlie, &built.envelope, &built.manifest, &built.chunks).unwrap();
        assert_eq!(pt, b"secret");
        assert!(open_drop(&alice, &built.envelope, &built.manifest, &built.chunks).is_err());
    }
}
