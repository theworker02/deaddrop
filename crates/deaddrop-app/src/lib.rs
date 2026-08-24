use deaddrop_core::config::Config;
use deaddrop_core::protocol::Message;
use deaddrop_core::store::Store;
use deaddrop_core::{PROTOCOL_LABEL, Result};
use std::path::Path;

pub mod daemon_service;

#[derive(Debug, Clone)]
pub struct Check {
    pub ok: bool,
    pub warn: bool,
    pub name: String,
    pub detail: String,
}

pub fn doctor(data_dir: &Path, cfg: &Config) -> Result<Vec<Check>> {
    let mut out = Vec::new();
    let id_path = data_dir.join("identities").join("identity.json");
    if id_path.exists() {
        match Store::open(data_dir, Default::default()).and_then(|s| s.load_identity()) {
            Ok(id) => out.push(ok("identity", &id.peer_id.to_string())),
            Err(e) => out.push(fail("identity", &e.to_string())),
        }
    } else {
        out.push(fail("identity", "run `dd init`"));
    }
    out.push(ok("keystore", "identity.json (OS file permissions apply)"));
    let probe = data_dir.join(".write-probe");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            out.push(ok("permissions", &data_dir.display().to_string()));
        }
        Err(e) => out.push(fail("permissions", &e.to_string())),
    }
    match Store::open(data_dir, Default::default()) {
        Ok(s) => match s.verify() {
            Ok(p) if p.is_empty() => out.push(ok("database", "sqlite + chunks")),
            Ok(p) => out.push(warn(
                "database",
                &format!("{} issues (Drop bodies kept)", p.len()),
            )),
            Err(e) => out.push(fail("database", &e.to_string())),
        },
        Err(e) => out.push(fail("database", &e.to_string())),
    }
    out.push(ok(
        "crypto backend",
        "DefaultProvider (Ed25519/X25519/ChaCha20-Poly1305/BLAKE3)",
    ));
    if let Ok(s) = Store::open(data_dir, Default::default()) {
        match s.stats() {
            Ok(st) => {
                let cap = deaddrop_core::config::Config::parse_bytes(&cfg.storage.maximum);
                if st.physical_size + 64 * 1024 * 1024 > cap && cap > 0 {
                    out.push(warn(
                        "disk capacity",
                        &format!(
                            "{} used of {}",
                            deaddrop_core::store::format_bytes(st.physical_size),
                            cfg.storage.maximum
                        ),
                    ));
                } else {
                    out.push(ok(
                        "disk capacity",
                        &deaddrop_core::store::format_bytes(st.physical_size),
                    ));
                }
                let now = deaddrop_core::store::unix_now();
                let stale = s
                    .all_encounters()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|(_, e)| now.saturating_sub(e.last_seen) > 30 * 86_400)
                    .count();
                if stale > 0 {
                    out.push(warn("stale peers", &format!("{stale} not seen in 30d")));
                } else {
                    out.push(ok("stale peers", "none"));
                }
                match s.verify() {
                    Ok(p) if p.is_empty() => out.push(ok("Drop store", "chunk hashes match")),
                    Ok(p) => out.push(warn("corrupted Drops", &p.join("; "))),
                    Err(e) => out.push(fail("Drop store", &e.to_string())),
                }
            }
            Err(e) => out.push(fail("storage stats", &e.to_string())),
        }
    }
    out.push(if cfg.discovery.lan && cfg.discovery.mode.advertise_lan() {
        ok(
            "LAN discovery",
            &format!("UDP {} ({:?})", cfg.discovery.lan_port, cfg.discovery.mode),
        )
    } else {
        warn("LAN discovery", "disabled or hidden")
    });
    out.push(if cfg.transport.quic {
        warn(
            "QUIC",
            "enabled in config; default `dd serve` listens TCP. QUIC types are EXPERIMENTAL",
        )
    } else {
        warn("QUIC", "disabled in config")
    });
    out.push(warn(
        "Bluetooth",
        "unavailable (no BLE transport in this tree)",
    ));
    out.push(ok("routing engine", &cfg.routing.strategy));
    let now = deaddrop_core::store::unix_now();
    if now < 1_700_000_000 {
        out.push(warn(
            "time synchronization",
            "system clock looks before 2023; sealed-until policy may mis-fire",
        ));
    } else {
        out.push(ok(
            "time synchronization",
            "local clock present (no NTP client)",
        ));
    }
    match deaddrop_net::control::read_info(data_dir) {
        Ok(Some(info)) => match std::net::TcpStream::connect_timeout(
            &info
                .listen
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:1".parse().expect("literal")),
            std::time::Duration::from_millis(200),
        ) {
            Ok(_) => out.push(ok(
                "daemon",
                &format!("pid {} control {}", info.pid, info.listen),
            )),
            Err(_) => out.push(warn(
                "daemon",
                "control.json present but not reachable — run `dd daemon start`",
            )),
        },
        _ => out.push(warn("daemon", "not running (CLI store still works)")),
    }
    out.push(ok("protocol compatibility", PROTOCOL_LABEL));
    out.push(ok(
        "network interfaces",
        "OS default; LAN uses UDP broadcast",
    ));
    Ok(out)
}

pub fn doctor_repair(data_dir: &Path) -> Result<Vec<String>> {
    let store = Store::open(data_dir, Default::default())?;
    store.repair_safe()
}

pub fn inspect_protocol_bytes(bytes: &[u8]) -> String {
    let payload = if bytes.len() >= 4 {
        let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if n + 4 == bytes.len() {
            &bytes[4..]
        } else {
            bytes
        }
    } else {
        bytes
    };
    match deaddrop_core::protocol::decode_cbor::<Message>(payload) {
        Ok(m) => format!(
            "Frame Type      {}\nVersion         {PROTOCOL_LABEL}\nPayload Size    {} bytes\nAuthenticated   (session layer; inspect is offline)\n",
            m.name(),
            payload.len()
        ),
        Err(e) => {
            format!("decode error: {e}\n(not a DDP Message; JSON/debug export is separate)\n")
        }
    }
}

pub fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

pub fn parse_duration_or_rfc3339(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(d) = t.strip_suffix('d') {
        return d.parse::<u64>().ok().map(|n| n * 86400);
    }
    if let Some(h) = t.strip_suffix('h') {
        return h.parse::<u64>().ok().map(|n| n * 3600);
    }
    if let Some(m) = t.strip_suffix('m') {
        return m.parse::<u64>().ok().map(|n| n * 60);
    }
    if let Some(sec) = t.strip_suffix('s') {
        return sec.parse::<u64>().ok();
    }
    if t.contains('T') {
        return parse_rfc3339_utc(t);
    }
    t.parse::<u64>().ok()
}

fn parse_rfc3339_utc(s: &str) -> Option<u64> {
    let s = s.trim().trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let y: i32 = d.next()?.parse().ok()?;
    let mo: u32 = d.next()?.parse().ok()?;
    let day: u32 = d.next()?.parse().ok()?;
    let mut t = time.split(':');
    let h: u32 = t.next()?.parse().ok()?;
    let mi: u32 = t.next()?.parse().ok()?;
    let se: u32 = t.next()?.parse::<f64>().ok()? as u32;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&day) {
        return None;
    }
    let mut days: i64 = 0;
    for yy in 1970..y {
        days += if is_leap(yy) { 366 } else { 365 };
    }
    let md = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..mo {
        days += md[m as usize] as i64;
        if m == 2 && is_leap(y) {
            days += 1;
        }
    }
    days += (day as i64) - 1;
    Some((days as u64) * 86400 + (h as u64) * 3600 + (mi as u64) * 60 + se as u64)
}

fn is_leap(y: i32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

fn ok(name: &str, d: &str) -> Check {
    Check {
        ok: true,
        warn: false,
        name: name.into(),
        detail: d.into(),
    }
}
fn warn(name: &str, d: &str) -> Check {
    Check {
        ok: true,
        warn: true,
        name: name.into(),
        detail: d.into(),
    }
}
fn fail(name: &str, d: &str) -> Check {
    Check {
        ok: false,
        warn: false,
        name: name.into(),
        detail: d.into(),
    }
}
