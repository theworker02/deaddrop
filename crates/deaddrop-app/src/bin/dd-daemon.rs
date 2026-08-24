use clap::Parser;
use deaddrop_core::config::Config;
use deaddrop_net::Node;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "DEADDROP_HOME")]
    data_dir: Option<PathBuf>,
    #[arg(long, default_value = "0.0.0.0:7947")]
    listen: SocketAddr,
    #[arg(long = "peer")]
    peers: Vec<SocketAddr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    tracing_subscriber::fmt().init();
    let args = Args::parse();
    let dir = args
        .data_dir
        .unwrap_or_else(|| std::env::temp_dir().join("deaddrop"));
    std::fs::create_dir_all(&dir)?;
    let node = Node::open(&dir, Config::load(&dir.join("deaddrop.toml"))?)?;
    println!(
        "dd-daemon {} TCP {}",
        node.identity.peer_id.short(),
        args.listen
    );
    node.serve(args.listen, args.peers).await?;
    Ok(())
}
