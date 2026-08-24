use crate::discovery::{Beacon, DiscoveryProvider, Endpoint};
use async_trait::async_trait;
use deaddrop_core::{PROTOCOL_VERSION, PeerId, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{interval, timeout};

pub struct LanDiscovery {
    pub port: u16,
}

pub async fn scan_lan(port: u16, timeout_ms: u64) -> Result<Vec<Endpoint>> {
    LanDiscovery { port }.scan(timeout_ms).await
}

fn bind_scan(port: u16) -> std::io::Result<UdpSocket> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

#[async_trait]
impl DiscoveryProvider for LanDiscovery {
    fn name(&self) -> &'static str {
        "lan"
    }
    async fn advertise(&self, self_id: PeerId, stream_port: u16) -> Result<()> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.set_broadcast(true)?;
        let beacon = Beacon {
            version: PROTOCOL_VERSION,
            stream_port,
            node_id: self_id,
        };
        let bytes = beacon.encode();
        let mut tick = interval(Duration::from_secs(2));
        loop {
            tick.tick().await;
            let _ = sock
                .send_to(&bytes, SocketAddr::from(([255, 255, 255, 255], self.port)))
                .await;
        }
    }
    async fn scan(&self, timeout_ms: u64) -> Result<Vec<Endpoint>> {
        let sock = bind_scan(self.port)?;
        let mut buf = [0u8; 64];
        let mut out = Vec::new();
        let deadline = Duration::from_millis(timeout_ms.max(1));
        let start = tokio::time::Instant::now();
        while start.elapsed() < deadline {
            let remain = deadline.saturating_sub(start.elapsed());
            match timeout(remain, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    if let Ok(b) = Beacon::decode(&buf[..n]) {
                        out.push(Endpoint {
                            peer: Some(b.node_id),
                            locator: format!("{}:{}", from.ip(), b.stream_port),
                        });
                    }
                }
                _ => break,
            }
        }
        Ok(dedupe_endpoints(out))
    }
}

pub fn dedupe_endpoints(eps: Vec<Endpoint>) -> Vec<Endpoint> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for e in eps {
        let key = format!(
            "{}|{}",
            e.locator,
            e.peer.map(|p| p.to_string()).unwrap_or_default()
        );
        if seen.insert(key) {
            out.push(e);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_keeps_one_locator() {
        let p = PeerId::from_digest([1u8; 32]);
        let a = Endpoint {
            peer: Some(p),
            locator: "10.0.0.2:7947".into(),
        };
        let out = dedupe_endpoints(vec![a.clone(), a]);
        assert_eq!(out.len(), 1);
    }
}
