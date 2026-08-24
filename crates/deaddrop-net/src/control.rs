//! Local control API. Bound to loopback (and a Unix socket when available).
//! Not exposed on public interfaces.

use deaddrop_core::store::{Store, unix_now};
use deaddrop_core::{PROTOCOL_LABEL, Result};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const CONTROL_FILE: &str = "control.json";
pub const DAEMON_FILE: &str = "daemon.json";

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ControlInfo {
    pub listen: String,
    pub token: String,
    pub pid: u32,
    pub started_at: u64,
    #[serde(default)]
    pub unix_socket: Option<String>,
}

pub fn control_path(root: &Path) -> PathBuf {
    root.join(CONTROL_FILE)
}

pub fn daemon_path(root: &Path) -> PathBuf {
    root.join(DAEMON_FILE)
}

pub fn write_info(root: &Path, info: &ControlInfo) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(info)
        .map_err(|e| deaddrop_core::DdError::crypto(e.to_string()))?;
    std::fs::write(control_path(root), &bytes)?;
    std::fs::write(daemon_path(root), bytes)?;
    Ok(())
}

pub fn read_info(root: &Path) -> Result<Option<ControlInfo>> {
    let p = control_path(root);
    if !p.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(p)?;
    let info: ControlInfo = serde_json::from_slice(&bytes)
        .map_err(|e| deaddrop_core::DdError::invalid_frame(format!("control.json: {e}")))?;
    Ok(Some(info))
}

pub fn clear(root: &Path) {
    let _ = std::fs::remove_file(control_path(root));
    let _ = std::fs::remove_file(daemon_path(root));
    let _ = std::fs::remove_file(root.join("control.sock"));
}

pub fn random_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(1);
    format!("{n:x}{:x}", std::process::id())
}

pub struct ControlServer {
    pub info: ControlInfo,
    pub stop: Arc<AtomicBool>,
}

impl ControlServer {
    pub async fn bind(root: &Path, ddp_listen: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local = listener.local_addr()?;
        let token = random_token();
        #[cfg(unix)]
        let unix_socket = {
            let sock = root.join("control.sock");
            let _ = std::fs::remove_file(&sock);
            Some(sock.display().to_string())
        };
        #[cfg(not(unix))]
        let unix_socket = None::<String>;
        let info = ControlInfo {
            listen: local.to_string(),
            token: token.clone(),
            pid: std::process::id(),
            started_at: unix_now(),
            unix_socket: unix_socket.clone(),
        };
        write_info(root, &info)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_a = stop.clone();
        let root_a = root.to_path_buf();
        let token_a = token.clone();
        tokio::spawn(async move {
            loop {
                if stop_a.load(Ordering::Relaxed) {
                    break;
                }
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let stop = stop_a.clone();
                        let root = root_a.clone();
                        let token = token_a.clone();
                        tokio::spawn(async move {
                            let _ = handle_client(stream, &root, &token, &stop).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        #[cfg(unix)]
        if let Some(path) = unix_socket {
            let stop_b = stop.clone();
            let root_b = root.to_path_buf();
            let token_b = token;
            tokio::spawn(async move {
                if let Ok(ul) = tokio::net::UnixListener::bind(&path) {
                    loop {
                        if stop_b.load(Ordering::Relaxed) {
                            break;
                        }
                        if let Ok((stream, _)) = ul.accept().await {
                            let stop = stop_b.clone();
                            let root = root_b.clone();
                            let token = token_b.clone();
                            tokio::spawn(async move {
                                let _ = handle_unix(stream, &root, &token, &stop).await;
                            });
                        }
                    }
                }
            });
        }
        let _ = ddp_listen;
        Ok(Self { info, stop })
    }
}

#[cfg(unix)]
async fn handle_unix(
    stream: tokio::net::UnixStream,
    root: &Path,
    token: &str,
    stop: &Arc<AtomicBool>,
) -> Result<()> {
    handle_generic(stream, root, token, stop).await
}

async fn handle_client(
    stream: tokio::net::TcpStream,
    root: &Path,
    token: &str,
    stop: &Arc<AtomicBool>,
) -> Result<()> {
    handle_generic(stream, root, token, stop).await
}

async fn handle_generic<S>(
    mut stream: S,
    root: &Path,
    token: &str,
    stop: &Arc<AtomicBool>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let authed = req.contains(&format!("Bearer {token}")) || req.lines().any(|l| l.trim() == token);
    if !authed {
        let body = b"HTTP/1.0 401 Unauthorized\r\nContent-Length: 12\r\n\r\nunauthorized";
        let _ = stream.write_all(body).await;
        return Ok(());
    }
    let path = req
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("/");
    if path == "/v1/shutdown" || path.starts_with("/v1/shutdown") {
        stop.store(true, Ordering::Relaxed);
        let body = br#"{"ok":true}"#;
        write_http(&mut stream, 200, body).await?;
        return Ok(());
    }
    let payload = match status_json(root, path) {
        Ok(v) => v,
        Err(e) => serde_json::json!({"error": e.to_string()}),
    };
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    write_http(&mut stream, 200, &bytes).await?;
    Ok(())
}

async fn write_http<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    body: &[u8],
) -> Result<()> {
    let head = format!(
        "HTTP/1.0 {code} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

fn status_json(root: &Path, path: &str) -> Result<serde_json::Value> {
    let store = Store::open(root, Default::default())?;
    let now = unix_now();
    match path {
        "/v1/status" => {
            let id = store.load_identity()?;
            let s = store.stats()?;
            Ok(serde_json::json!({
                "protocol": PROTOCOL_LABEL,
                "identity": id.peer_id.to_string(),
                "objects": s.objects,
                "storage": s.physical_size,
            }))
        }
        "/v1/peers" => {
            let book = store.load_contacts()?;
            let list: Vec<_> = book
                .all()
                .map(|(id, c)| {
                    serde_json::json!({
                        "id": id.to_string(),
                        "name": c.card.name,
                        "trust": format!("{:?}", c.trust),
                    })
                })
                .collect();
            Ok(serde_json::json!({ "peers": list }))
        }
        "/v1/drops" => {
            let ids: Vec<_> = store
                .inventory(now)?
                .into_iter()
                .map(|i| i.to_string())
                .collect();
            Ok(serde_json::json!({ "drops": ids }))
        }
        "/v1/routes" => Ok(serde_json::json!({
            "note": "route table is computed per Drop; use dd route explain"
        })),
        "/v1/transfers" => Ok(transfers_json(&store, now)?),
        "/v1/spaces" => {
            let spaces: Vec<_> = store
                .list_spaces()?
                .into_iter()
                .map(|s| serde_json::json!({"name": s.name}))
                .collect();
            Ok(serde_json::json!({ "spaces": spaces }))
        }
        "/v1/channels" => {
            let ch: Vec<_> = store
                .list_channels()?
                .into_iter()
                .map(|(n, f, p)| serde_json::json!({"name": n, "filter": f, "policy": p}))
                .collect();
            Ok(serde_json::json!({ "channels": ch }))
        }
        "/v1/events" => Ok(serde_json::json!({
            "note": "subscribe via SDK DeadDrop::events(); HTTP is a snapshot API"
        })),
        _ => Ok(serde_json::json!({ "error": "not found", "path": path })),
    }
}

pub fn transfers_json(store: &Store, now: u64) -> Result<serde_json::Value> {
    let mut active = 0u64;
    let mut queued = 0u64;
    let mut completed = 0u64;
    let mut items = Vec::new();
    for id in store.inventory(now)? {
        let complete = store.complete(&id).unwrap_or(false);
        let mask = store.present_mask(&id).unwrap_or_default();
        let present = mask.iter().filter(|x| **x).count();
        let total = mask.len().max(1);
        if complete {
            completed += 1;
        } else if present > 0 {
            active += 1;
        } else {
            queued += 1;
        }
        items.push(serde_json::json!({
            "id": id.to_string(),
            "chunks": format!("{present}/{total}"),
            "complete": complete,
        }));
    }
    Ok(serde_json::json!({
        "active": active,
        "queued": queued,
        "completed": completed,
        "items": items,
    }))
}

pub async fn query(root: &Path, path: &str) -> Result<serde_json::Value> {
    let Some(info) = read_info(root)? else {
        return Err(deaddrop_core::DdError::invalid_frame("daemon not running"));
    };
    let addr: SocketAddr = info
        .listen
        .parse()
        .map_err(|_| deaddrop_core::DdError::invalid_frame("control listen"))?;
    let mut s = tokio::net::TcpStream::connect(addr).await?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nAuthorization: Bearer {}\r\n\r\n",
        info.token
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("{}");
    Ok(serde_json::from_str(body).unwrap_or_else(|_| serde_json::json!({"raw": body})))
}
