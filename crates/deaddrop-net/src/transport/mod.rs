pub mod memory;
#[cfg(feature = "quic")]
pub mod quic;
pub mod tcp;
use async_trait::async_trait;
use deaddrop_core::Result;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> ByteStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

#[derive(Debug, Clone)]
pub struct TransportCaps {
    pub encrypted: bool,
    pub multiplex: bool,
    pub migration: bool,
}

#[async_trait]
pub trait Transport: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> TransportCaps;
    async fn connect(&self, locator: &str) -> Result<Box<dyn ByteStream>>;
}
