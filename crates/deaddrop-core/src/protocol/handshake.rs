use super::codec::{decode_cbor, encode_cbor, read_frame_async, write_frame_async};
use super::messages::Message;
use crate::crypto::{
    CryptoProvider, DefaultProvider, PrivateIdentity, X25519Public, X25519Secret, random_bytes,
    session_keys, verify_identity, x25519_ephemeral,
};
use crate::{CapabilityDoc, DdError, ErrorCode, NegotiatedCaps, PublicIdentity, Result};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Session {
    pub peer: crate::PeerId,
    pub peer_identity: PublicIdentity,
    pub caps: NegotiatedCaps,
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_nonce: u64,
    pub recv_nonce: u64,
}

pub async fn handshake_initiator<S>(identity: &PrivateIdentity, stream: &mut S) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (eph_sk, eph_pk) = x25519_ephemeral();
    let nonce = u64::from_le_bytes(random_bytes::<8>());
    let mut proof_msg = Vec::from(&b"ddp-ch-v2"[..]);
    proof_msg.extend_from_slice(&eph_pk.to_bytes());
    proof_msg.extend_from_slice(&nonce.to_be_bytes());
    let identity_proof = DefaultProvider.sign(&identity.signing_key(), &proof_msg);
    let hello = Message::ClientHello {
        protocol: crate::PROTOCOL_VERSION,
        identity: identity.public.clone(),
        eph_pk: eph_pk.to_bytes(),
        nonce,
        caps: CapabilityDoc::local_v2(),
        identity_proof,
    };
    write_plain(stream, &hello).await?;
    let reply = read_plain(stream).await?;
    match reply {
        Message::ServerHello {
            protocol,
            identity: peer_ident,
            eph_pk: remote_eph,
            nonce: snonce,
            caps,
            transcript_sig,
        } => finish(
            true,
            protocol,
            peer_ident,
            &eph_sk,
            &X25519Public::from(remote_eph),
            nonce,
            snonce,
            caps,
            &transcript_sig,
            Some(&identity.public),
        ),
        other => Err(DdError::invalid_frame(format!(
            "expected server_hello, got {}",
            other.name()
        ))),
    }
}

pub async fn handshake_responder<S>(identity: &PrivateIdentity, stream: &mut S) -> Result<Session>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello = read_plain(stream).await?;
    let Message::ClientHello {
        protocol,
        identity: peer_ident,
        eph_pk: remote_eph,
        nonce: cnonce,
        caps,
        identity_proof,
    } = hello
    else {
        return Err(DdError::protocol(
            ErrorCode::Dda3001AuthFailed,
            "expected client_hello",
        ));
    };
    let mut proof_msg = Vec::from(&b"ddp-ch-v2"[..]);
    proof_msg.extend_from_slice(&remote_eph);
    proof_msg.extend_from_slice(&cnonce.to_be_bytes());
    DefaultProvider
        .verify(&peer_ident.ed25519_pk, &proof_msg, &identity_proof)
        .map_err(|_| DdError::protocol(ErrorCode::Dda3001AuthFailed, "client proof"))?;
    let (eph_sk, eph_pk) = x25519_ephemeral();
    let snonce = u64::from_le_bytes(random_bytes::<8>());
    let remote = X25519Public::from(remote_eph);
    let transcript = transcript_bytes(
        &peer_ident,
        &identity.public,
        &remote_eph,
        &eph_pk.to_bytes(),
        cnonce,
        snonce,
    );
    let sig = DefaultProvider.sign(&identity.signing_key(), &transcript);
    let reply = Message::ServerHello {
        protocol: crate::PROTOCOL_VERSION,
        identity: identity.public.clone(),
        eph_pk: eph_pk.to_bytes(),
        nonce: snonce,
        caps: CapabilityDoc::local_v2(),
        transcript_sig: sig,
    };
    write_plain(stream, &reply).await?;
    finish(
        false,
        protocol,
        peer_ident,
        &eph_sk,
        &remote,
        cnonce,
        snonce,
        caps,
        &[0u8; 64],
        Some(&identity.public),
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    initiator: bool,
    protocol: u16,
    peer_ident: PublicIdentity,
    local_eph: &X25519Secret,
    remote_eph: &X25519Public,
    cnonce: u64,
    snonce: u64,
    peer_caps: CapabilityDoc,
    transcript_sig: &[u8; 64],
    local_public: Option<&PublicIdentity>,
) -> Result<Session> {
    if protocol != crate::PROTOCOL_VERSION {
        return Err(DdError::protocol(
            ErrorCode::Ddp1002UnsupportedVersion,
            format!("DDP/{protocol}"),
        ));
    }
    let peer = verify_identity(&peer_ident)?;
    let local_eph_pk = X25519Public::from(local_eph);
    let (client_ident, server_ident, client_eph, server_eph) = if initiator {
        (
            local_public.expect("local"),
            &peer_ident,
            local_eph_pk.to_bytes(),
            remote_eph.to_bytes(),
        )
    } else {
        (
            &peer_ident,
            local_public.expect("local"),
            remote_eph.to_bytes(),
            local_eph_pk.to_bytes(),
        )
    };
    let transcript = transcript_bytes(
        client_ident,
        server_ident,
        &client_eph,
        &server_eph,
        cnonce,
        snonce,
    );
    if initiator {
        DefaultProvider.verify(&peer_ident.ed25519_pk, &transcript, transcript_sig)?;
    }
    let keys = session_keys(initiator, local_eph, remote_eph, &transcript)?;
    let caps = CapabilityDoc::local_v2().negotiate(&peer_caps)?;
    Ok(Session {
        peer,
        peer_identity: peer_ident,
        caps,
        send_key: keys.send,
        recv_key: keys.recv,
        send_nonce: 0,
        recv_nonce: 0,
    })
}

fn transcript_bytes(
    client: &PublicIdentity,
    server: &PublicIdentity,
    client_eph: &[u8; 32],
    server_eph: &[u8; 32],
    cnonce: u64,
    snonce: u64,
) -> Vec<u8> {
    let mut t = Vec::from(&b"ddp-hs-v2"[..]);
    t.extend_from_slice(&client.ed25519_pk);
    t.extend_from_slice(&client.x25519_pk);
    t.extend_from_slice(&server.ed25519_pk);
    t.extend_from_slice(&server.x25519_pk);
    t.extend_from_slice(client_eph);
    t.extend_from_slice(server_eph);
    t.extend_from_slice(&cnonce.to_be_bytes());
    t.extend_from_slice(&snonce.to_be_bytes());
    t
}

async fn write_plain<S: AsyncWrite + Unpin>(s: &mut S, msg: &Message) -> Result<()> {
    write_frame_async(s, &encode_cbor(msg)?).await
}

async fn read_plain<S: AsyncRead + Unpin>(s: &mut S) -> Result<Message> {
    let bytes = read_frame_async(s).await?;
    decode_cbor(&bytes)
}

pub async fn write_msg<S: AsyncWrite + Unpin>(s: &mut S, msg: &Message) -> Result<()> {
    write_plain(s, msg).await
}

pub async fn read_msg<S: AsyncRead + Unpin>(s: &mut S) -> Result<Message> {
    read_plain(s).await
}
