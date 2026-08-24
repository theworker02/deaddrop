//! Background daemon spawn and OS service install (systemd user, LaunchAgent, logon task).

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const WINDOWS_TASK: &str = "DeadDropDaemon";
pub const SYSTEMD_UNIT: &str = "deaddrop.service";
pub const LAUNCH_LABEL: &str = "com.deaddrop.daemon";

pub fn daemon_executable() -> Result<PathBuf> {
    let me = std::env::current_exe().context("current executable")?;
    let sibling = me.with_file_name(if cfg!(windows) {
        "dd-daemon.exe"
    } else {
        "dd-daemon"
    });
    if sibling.is_file() {
        Ok(sibling)
    } else {
        Ok(me)
    }
}

pub fn spawn_background(data_dir: &Path, listen: SocketAddr, peers: &[SocketAddr]) -> Result<u32> {
    std::fs::create_dir_all(data_dir)?;
    let log_path = data_dir.join("daemon.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let log_err = log.try_clone()?;
    let bin = daemon_executable()?;
    let mut cmd = Command::new(&bin);
    let stem = bin.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem == "dd" {
        cmd.arg("--data-dir")
            .arg(data_dir)
            .arg("daemon")
            .arg("start")
            .arg("--foreground")
            .arg("--listen")
            .arg(listen.to_string());
        for p in peers {
            cmd.arg("--peer").arg(p.to_string());
        }
    } else {
        cmd.arg("--data-dir")
            .arg(data_dir)
            .arg("--listen")
            .arg(listen.to_string());
        for p in peers {
            cmd.arg("--peer").arg(p.to_string());
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    }
    let child = cmd.spawn().context("spawn daemon")?;
    Ok(child.id())
}

pub fn daemon_command_line(exec: &Path, data_dir: &Path, listen: SocketAddr) -> Vec<String> {
    let stem = exec.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let mut args = vec![exec.display().to_string()];
    if stem == "dd" {
        args.extend([
            "--data-dir".into(),
            data_dir.display().to_string(),
            "daemon".into(),
            "start".into(),
            "--foreground".into(),
            "--listen".into(),
            listen.to_string(),
        ]);
    } else {
        args.extend([
            "--data-dir".into(),
            data_dir.display().to_string(),
            "--listen".into(),
            listen.to_string(),
        ]);
    }
    args
}

pub fn systemd_unit(exec: &Path, data_dir: &Path, listen: SocketAddr) -> String {
    let line = daemon_command_line(exec, data_dir, listen).join(" ");
    format!(
        "[Unit]\nDescription=DeadDrop DDP/2 node\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={line}\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n"
    )
}

pub fn launchd_plist(exec: &Path, data_dir: &Path, listen: SocketAddr) -> String {
    let log = data_dir.join("daemon.log");
    let args = daemon_command_line(exec, data_dir, listen);
    let args_xml: String = args
        .iter()
        .map(|a| format!("    <string>{}</string>\n", a))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCH_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args_xml}  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
</dict>
</plist>
"#,
        log.display(),
        log.display()
    )
}

pub fn install(data_dir: &Path, listen: SocketAddr) -> Result<String> {
    let exec = daemon_executable()?;
    let abs_dir = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
    install_os(&exec, &abs_dir, listen)
}

#[cfg(target_os = "linux")]
fn install_os(exec: &Path, abs_dir: &Path, listen: SocketAddr) -> Result<String> {
    let unit_dir = dirs_config()?.join("systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let path = unit_dir.join(SYSTEMD_UNIT);
    std::fs::write(&path, systemd_unit(exec, abs_dir, listen))?;
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    let _ = Command::new("systemctl")
        .args(["--user", "enable", "--now", SYSTEMD_UNIT])
        .status();
    Ok(format!(
        "installed systemd user unit {}\nstart/stop: systemctl --user start|stop {SYSTEMD_UNIT}",
        path.display()
    ))
}

#[cfg(target_os = "macos")]
fn install_os(exec: &Path, abs_dir: &Path, listen: SocketAddr) -> Result<String> {
    let dir = home_dir()?.join("Library/LaunchAgents");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{LAUNCH_LABEL}.plist"));
    std::fs::write(&path, launchd_plist(exec, abs_dir, listen))?;
    let _ = Command::new("launchctl")
        .args(["unload", &path.to_string_lossy()])
        .status();
    let st = Command::new("launchctl")
        .args(["load", &path.to_string_lossy()])
        .status();
    let extra = if st.map(|s| s.success()).unwrap_or(false) {
        "loaded"
    } else {
        "wrote plist; run: launchctl load ~/Library/LaunchAgents/com.deaddrop.daemon.plist"
    };
    Ok(format!(
        "installed LaunchAgent {} ({extra})",
        path.display()
    ))
}

#[cfg(windows)]
fn install_os(exec: &Path, abs_dir: &Path, listen: SocketAddr) -> Result<String> {
    let parts = daemon_command_line(exec, abs_dir, listen);
    let tr = format!(
        "\"{}\" {}",
        parts[0],
        parts[1..]
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let status = Command::new("schtasks")
        .args([
            "/Create",
            "/F",
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
            "/TN",
            WINDOWS_TASK,
            "/TR",
            &tr,
        ])
        .status()
        .context("schtasks")?;
    if !status.success() {
        anyhow::bail!(
            "schtasks failed (try from an elevated prompt). Task command would be:\n  {tr}"
        );
    }
    let _ = Command::new("schtasks")
        .args(["/Run", "/TN", WINDOWS_TASK])
        .status();
    Ok(format!(
        "installed Windows logon task {WINDOWS_TASK} (Task Scheduler, no admin service)"
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn install_os(_exec: &Path, _abs_dir: &Path, _listen: SocketAddr) -> Result<String> {
    anyhow::bail!("service install is supported on Linux, macOS, and Windows")
}

pub fn uninstall() -> Result<String> {
    uninstall_os()
}

#[cfg(target_os = "linux")]
fn uninstall_os() -> Result<String> {
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", SYSTEMD_UNIT])
        .status();
    if let Ok(dir) = dirs_config() {
        let path = dir.join("systemd/user").join(SYSTEMD_UNIT);
        let _ = std::fs::remove_file(&path);
        return Ok(format!("removed {}", path.display()));
    }
    Ok("disabled deaddrop.service".into())
}

#[cfg(target_os = "macos")]
fn uninstall_os() -> Result<String> {
    if let Ok(home) = home_dir() {
        let path = home
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCH_LABEL}.plist"));
        let _ = Command::new("launchctl")
            .args(["unload", &path.to_string_lossy()])
            .status();
        let _ = std::fs::remove_file(&path);
        return Ok(format!("removed {}", path.display()));
    }
    Ok("unloaded LaunchAgent".into())
}

#[cfg(windows)]
fn uninstall_os() -> Result<String> {
    let _ = Command::new("schtasks")
        .args(["/End", "/TN", WINDOWS_TASK])
        .status();
    let status = Command::new("schtasks")
        .args(["/Delete", "/F", "/TN", WINDOWS_TASK])
        .status()
        .context("schtasks delete")?;
    if !status.success() {
        anyhow::bail!("no task {WINDOWS_TASK} (already uninstalled?)");
    }
    Ok(format!("removed Windows task {WINDOWS_TASK}"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn uninstall_os() -> Result<String> {
    anyhow::bail!("service uninstall is supported on Linux, macOS, and Windows")
}

#[cfg(unix)]
fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is unset")
}

#[cfg(target_os = "linux")]
fn dirs_config() -> Result<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(x));
    }
    Ok(home_dir()?.join(".config"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn systemd_unit_mentions_listen() {
        let u = systemd_unit(
            Path::new("/usr/bin/dd-daemon"),
            Path::new("/var/lib/deaddrop"),
            "0.0.0.0:7947".parse().unwrap(),
        );
        assert!(u.contains("0.0.0.0:7947"));
        assert!(u.contains("/var/lib/deaddrop"));
    }

    #[test]
    fn launchd_plist_is_xml() {
        let p = launchd_plist(
            Path::new("/usr/local/bin/dd-daemon"),
            Path::new("/tmp/dd"),
            "127.0.0.1:7947".parse().unwrap(),
        );
        assert!(p.contains(LAUNCH_LABEL));
        assert!(p.contains("127.0.0.1:7947"));
    }
}
