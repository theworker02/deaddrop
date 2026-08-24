use clap::Parser;
use deaddrop_core::crypto::PrivateIdentity;
use deaddrop_core::identity::ContactCard;
use deaddrop_core::protocol::{CreateDrop, build_drop};
use deaddrop_core::store::Store;
use deaddrop_core::{Destination, Ownership, Priority, RoutingPolicy, RoutingPolicyKind};
use deaddrop_net::sync::{SyncOpts, sync_session};
use deaddrop_net::transport::memory::pair;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Option<SimCmd>,
    #[arg(long)]
    scenario: Option<PathBuf>,
    #[arg(long, default_value_t = 48291)]
    seed: u64,
    #[arg(long, default_value_t = 200)]
    nodes: usize,
    #[arg(long, default_value_t = 400)]
    drops: usize,
    #[arg(long, default_value_t = 24)]
    hours: u64,
    #[arg(long, default_value = "spray")]
    strategy: String,
}

#[derive(clap::Subcommand)]
enum SimCmd {
    /// Run a scenario file (toml or json). Large node counts are capped in this binary.
    Run { scenario: PathBuf },
}

#[derive(Deserialize, Default)]
struct Scenario {
    #[serde(default = "n500")]
    nodes: usize,
    #[serde(default)]
    duration: Option<String>,
}

fn n500() -> usize {
    500
}

#[tokio::main]
async fn main() {
    let mut args = Args::parse();
    if let Some(SimCmd::Run { scenario }) = args.cmd.take() {
        args.scenario = Some(scenario);
    }
    run_from_args(args).await;
}

async fn run_from_args(args: Args) {
    let mut nodes_n = args.nodes;
    let mut hours = args.hours;
    if let Some(p) = args.scenario {
        if let Ok(s) = std::fs::read_to_string(p) {
            if let Ok(sc) = toml::from_str::<Scenario>(&s) {
                nodes_n = sc.nodes;
                if sc.duration.as_deref() == Some("7d") {
                    hours = 24 * 7;
                }
            }
        }
    }
    if nodes_n > 400 {
        eprintln!(
            "capping nodes {nodes_n} -> 200 (engineering pairwise model; not a 10k-node CI run)"
        );
        nodes_n = 200;
    }
    let kind = match args.strategy.as_str() {
        "direct" => RoutingPolicyKind::Direct,
        "epidemic" => RoutingPolicyKind::Epidemic,
        "encounter" => RoutingPolicyKind::Encounter,
        "adaptive" => RoutingPolicyKind::Adaptive,
        "tournament" => {
            println!("Routing Tournament (engineering random-encounter model)");
            println!("{:<20} {:>12} {:>12}", "Strategy", "created", "encounters");
            for (name, k) in [
                ("Adaptive", RoutingPolicyKind::Adaptive),
                ("Spray-and-Wait", RoutingPolicyKind::SprayAndWait),
                ("Encounter", RoutingPolicyKind::Encounter),
                ("Epidemic", RoutingPolicyKind::Epidemic),
                ("Direct", RoutingPolicyKind::Direct),
            ] {
                let r = run(
                    args.seed,
                    nodes_n.min(40),
                    args.drops.min(80),
                    hours.min(6),
                    k,
                )
                .await;
                println!(
                    "{:<20} {:>12} {:>12}",
                    name, r["drops_created"], r["encounters"]
                );
            }
            println!("Numbers are from this run. Do not treat them as demographic science.");
            return;
        }
        _ => RoutingPolicyKind::SprayAndWait,
    };
    let report = run(args.seed, nodes_n, args.drops, hours, kind).await;
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

async fn run(
    seed: u64,
    n: usize,
    drops: usize,
    hours: u64,
    kind: RoutingPolicyKind,
) -> serde_json::Value {
    let mut rng = StdRng::seed_from_u64(seed);
    let tmp = std::env::temp_dir().join(format!("ddp-sim-{seed}"));
    let _ = std::fs::remove_dir_all(&tmp);
    let mut ids = Vec::new();
    let mut stores = Vec::new();
    for i in 0..n {
        let dir = tmp.join(format!("n{i}"));
        let st = Store::open(&dir, Default::default()).unwrap();
        let id = PrivateIdentity::generate();
        st.save_identity(&id).unwrap();
        ids.push(id);
        stores.push(st);
    }
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            let card = ContactCard::from_public(None, ids[j].public.clone()).unwrap();
            let _ = stores[i].put_contact(card, deaddrop_core::TrustState::Known);
        }
    }
    let now0 = 1_700_000_000u64;
    let mut created = 0u64;
    for d in 0..drops {
        let src = rng.gen_range(0..n);
        let mut dst = rng.gen_range(0..n);
        if dst == src {
            dst = (dst + 1) % n;
        }
        let built = build_drop(CreateDrop {
            author: &ids[src],
            recipients: vec![(ids[dst].peer_id, ids[dst].public.clone())],
            destination: Destination::One {
                peer: ids[dst].peer_id,
            },
            plaintext: format!("drop{d}").into_bytes(),
            now: now0,
            ttl_secs: Some(hours * 3600 + 3600),
            priority: Priority::Normal,
            routing: RoutingPolicy {
                kind,
                replication_budget: 8,
                trusted_only: false,
            },
            application: "dd.sim".into(),
            topic: None,
            chunking: deaddrop_core::chunk::default_fixed(),
            compress: false,
            hop_limit: 16,
            public: false,
            seal_until: None,
            seal_quorum: None,
            erasure: None,
        })
        .unwrap();
        let chunks: Vec<_> = built
            .chunks
            .into_iter()
            .enumerate()
            .map(|(i, b)| (i as u32, b))
            .collect();
        stores[src]
            .put_object(
                &built.envelope,
                &built.manifest,
                &chunks,
                Ownership::Local,
                now0,
            )
            .unwrap();
        created += 1;
    }
    let steps = (hours * 4).min(200) as usize;
    let mut copies = 0u64;
    for t in 0..steps {
        let a = rng.gen_range(0..n);
        let mut b = rng.gen_range(0..n);
        if a == b {
            b = (b + 1) % n;
        }
        let (sa, sb) = pair(1 << 20);
        let ia = &ids[a];
        let ib = &ids[b];
        // Safety: stores are separate; we transmute lifetimes via split borrow by index.
        let (left, right) = if a < b {
            let (l, r) = stores.split_at_mut(b);
            (&mut l[a], &mut r[0])
        } else {
            let (l, r) = stores.split_at_mut(a);
            (&mut r[0], &mut l[b])
        };
        let oa = SyncOpts {
            store: left,
            identity: ia,
            mode: deaddrop_core::NodeMode::Balanced,
            default_strategy: kind,
            metrics: None,
            bus: None,
            initiator: true,
        };
        let ob = SyncOpts {
            store: right,
            identity: ib,
            mode: deaddrop_core::NodeMode::Balanced,
            default_strategy: kind,
            metrics: None,
            bus: None,
            initiator: false,
        };
        let _ = tokio::join!(sync_session(oa, sa), sync_session(ob, sb));
        copies += 1;
        let _ = t;
    }
    let mut delivered = 0u64;
    for st in &stores {
        delivered += st.inventory(now0 + hours * 3600).unwrap().len() as u64;
    }
    serde_json::json!({
        "seed": seed,
        "nodes": n,
        "drops_created": created,
        "object_replicas_end": delivered,
        "encounters": copies,
        "strategy": format!("{kind:?}"),
        "note": "Engineering mobility: random pairwise encounters. Not a demographic model."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deterministic_seed() {
        let a = run(7, 12, 8, 2, RoutingPolicyKind::SprayAndWait).await;
        let b = run(7, 12, 8, 2, RoutingPolicyKind::SprayAndWait).await;
        assert_eq!(a["drops_created"], b["drops_created"]);
        assert_eq!(a["encounters"], b["encounters"]);
    }
}
