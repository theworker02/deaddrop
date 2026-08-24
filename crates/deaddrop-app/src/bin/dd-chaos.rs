use clap::{Parser, ValueEnum};

#[derive(Clone, Debug, ValueEnum)]
enum Fault {
    Disconnect,
    PacketLoss,
    DiskFull,
    CorruptChunk,
    ClockSkew,
    DuplicateFrame,
    Malformed,
}

#[derive(Parser)]
struct Args {
    #[arg(value_enum)]
    fault: Fault,
}

fn main() {
    let args = Args::parse();
    match args.fault {
        Fault::Malformed => {
            println!(
                "inject malformed frame: implementations MUST return DDP1001 and keep running"
            );
        }
        other => {
            println!(
                "EXPERIMENTAL chaos fault {other:?}: run against dd serve and expect recovery, not panic"
            );
        }
    }
}
