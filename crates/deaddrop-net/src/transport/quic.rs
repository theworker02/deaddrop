//! QUIC transport using quinn. Certificates are ephemeral self-signed **transport**
//! credentials. They do not replace DeadDrop identity or payload encryption (DDP-0008).

use crate::transport::{ByteStream, Transport, TransportCaps};
use async_trait::async_trait;
use deaddrop_core::{DdError, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::net::SocketAddr;
use std::sync::Arc;

pub fn make_server_config() -> Result<(ServerConfig, CertificateDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|e| DdError::crypto(e.to_string()))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut server = ServerConfig::with_single_cert(vec![cert_der.clone()], key.into())
        .map_err(|e| DdError::crypto(e.to_string()))?;
    let _ = &mut server;
    Ok((server, cert_der))
}

pub async fn bind_server(addr: SocketAddr) -> Result<Endpoint> {
    let (server, _) = make_server_config()?;
    Endpoint::server(server, addr).map_err(|e| DdError::crypto(e.to_string()))
}

/// Skip certificate verification: DDP authenticates peers at the session layer.
/// Transport TLS only provides confidentiality of frames on the path.
#[derive(Debug)]
struct SkipServerVerify;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn insecure_client_config() -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| DdError::crypto(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerify))
        .with_no_client_auth();
    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| DdError::crypto(e.to_string()))?,
    )))
}

pub struct QuicTransport;

#[async_trait]
impl Transport for QuicTransport {
    fn name(&self) -> &'static str {
        "quic"
    }
    fn capabilities(&self) -> TransportCaps {
        TransportCaps {
            encrypted: true,
            multiplex: true,
            migration: true,
        }
    }
    async fn connect(&self, locator: &str) -> Result<Box<dyn ByteStream>> {
        let addr: SocketAddr = locator
            .parse()
            .map_err(|e| DdError::invalid_frame(format!("quic locator: {e}")))?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| DdError::crypto(e.to_string()))?;
        endpoint.set_default_client_config(insecure_client_config()?);
        let conn = endpoint
            .connect(addr, "localhost")
            .map_err(|e| DdError::crypto(e.to_string()))?
            .await
            .map_err(|e| DdError::crypto(e.to_string()))?;
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| DdError::crypto(e.to_string()))?;
        Ok(Box::new(QuicStream { send, recv }))
    }
}

pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl tokio::io::AsyncRead for QuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::new(&mut self.send).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.send).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match std::pin::Pin::new(&mut self.send).poll_shutdown(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(std::io::Error::other(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
