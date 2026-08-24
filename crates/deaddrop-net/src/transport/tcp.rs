use crate::transport::{ByteStream, Transport, TransportCaps};
use async_trait::async_trait;
use deaddrop_core::{DdError, Result};
use tokio::net::TcpStream;

pub struct TcpTransport;

#[async_trait]
impl Transport for TcpTransport {
    fn name(&self) -> &'static str {
        "tcp"
    }
    fn capabilities(&self) -> TransportCaps {
        TransportCaps {
            encrypted: false,
            multiplex: false,
            migration: false,
        }
    }
    async fn connect(&self, locator: &str) -> Result<Box<dyn ByteStream>> {
        let s = TcpStream::connect(locator).await.map_err(DdError::from)?;
        Ok(Box::new(s))
    }
}
