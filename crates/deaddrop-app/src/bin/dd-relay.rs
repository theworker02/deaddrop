use clap::Parser;
use deaddrop_core::config::Config;
use deaddrop_core::store::Store;
use deaddrop_net::Node;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, default_value = "0.0.0.0:7947")]
    listen: SocketAddr,
    #[arg(long = "peer")]
    peers: Vec<SocketAddr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;
    let node = match Node::open(&args.data_dir, Config::default()) {
        Ok(n) => n,
        Err(_) => {
            Store::open(&args.data_dir, Default::default())?
                .init_identity(false)
                .ok();
            Node::open(&args.data_dir, Config::default())?
        }
    };
    println!(
        "dd-relay (carrier only) {} — no plaintext access",
        node.identity.peer_id.short()
    );
    node.serve(args.listen, args.peers).await?;
    Ok(())
}
