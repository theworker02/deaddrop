use clap::{Parser, Subcommand};
use deaddrop_core::crypto::{CryptoProvider, DefaultProvider, PrivateIdentity, verify_identity};
use deaddrop_core::protocol::{decode_cbor, encode_cbor, envelope_preimage};
use deaddrop_core::{HashAlgorithm, hex_encode};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Vectors { dir: PathBuf },
    Test { endpoint: String },
}

fn main() {
    let args = Args::parse();
    match args.cmd {
        Cmd::Vectors { dir } => {
            let mut failed = 0;
            for kind in ["identity", "envelope", "handshake"] {
                let p = dir.join(format!("{kind}.json"));
                if !p.exists() {
                    eprintln!("missing {kind}.json");
                    failed += 1;
                    continue;
                }
                println!("ok {kind} present");
            }
            let env_path = dir.join("envelope.json");
            if env_path.exists() {
                let raw = std::fs::read(&env_path).expect("read envelope.json");
                let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let input = v["input"].as_str().unwrap_or("");
                let expect = v["digest_hex"].as_str().unwrap_or("");
                let got = hex_encode(
                    &DefaultProvider
                        .hash(HashAlgorithm::Blake3, input.as_bytes())
                        .0,
                );
                if got != expect {
                    eprintln!("blake3 vector mismatch: got {got} want {expect}");
                    failed += 1;
                } else {
                    println!("ok blake3({input}) = {got}");
                }
            }
            let id = PrivateIdentity::generate();
            assert_eq!(verify_identity(&id.public).unwrap(), id.peer_id);
            let _ = encode_cbor(&id.public);
            let _ = decode_cbor::<deaddrop_core::PublicIdentity>;
            let _ = envelope_preimage;
            std::process::exit(if failed == 0 { 0 } else { 1 });
        }
        Cmd::Test { endpoint } => {
            eprintln!("EXPERIMENTAL: independent-server harness not implemented for {endpoint}");
            std::process::exit(2);
        }
    }
}
