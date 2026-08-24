use clap::Parser;
use deaddrop_sdk::{DeadDrop, Recipient};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    to: String,
    file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let node = DeadDrop::open_dir(&args.data_dir)?;
    let oid = node.send_file(&args.file, Recipient::from(args.to)).await?;
    println!("stored {oid}; interrupt-safe: missing chunks resume on next session");
    Ok(())
}
