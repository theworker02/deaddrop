use clap::Parser;
use deaddrop_sdk::{DeadDrop, Recipient};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    to: String,
    text: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let node = DeadDrop::open_dir(&args.data_dir)?;
    let oid = node
        .send(Recipient::from(args.to), args.text.as_bytes())
        .await?;
    println!("queued {oid} (offline ok; carry when a peer appears)");
    for m in node.receive()? {
        println!("from {} : {}", m.from, String::from_utf8_lossy(&m.body));
    }
    Ok(())
}
