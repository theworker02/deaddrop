use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use deaddrop_app::{doctor, doctor_repair, format_uptime, parse_duration_or_rfc3339};
use deaddrop_core::config::Config;
use deaddrop_core::identity::{ContactCard, IdentityFile, IdentityTransition};
use deaddrop_core::store::{Store, format_bytes, unix_now};
use deaddrop_core::{NodeMode, PROTOCOL_LABEL, Priority, hex_encode};
use deaddrop_net::{Node, SendOpts};
use std::io::{IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, ValueEnum)]
enum Output {
    Human,
    Json,
    Quiet,
}

#[derive(Parser)]
#[command(
    name = "dd",
    about = "DeadDrop — delay-tolerant networking (DDP/2 reference node)",
    version,
    arg_required_else_help = true
)]
struct Cli {
    #[arg(long, env = "DEADDROP_HOME", global = true)]
    data_dir: Option<PathBuf>,
    #[arg(long, global = true, default_value = "human")]
    output: Output,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    verbose: bool,
    #[arg(long, global = true)]
    quiet: bool,
    #[arg(long, global = true)]
    no_color: bool,
    #[arg(long, global = true)]
    profile: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        #[arg(long)]
        force: bool,
    },
    #[command(subcommand)]
    Identity(IdentityCmd),
    /// Import a peer contact (`.ddcontact`) or a sneakernet bundle (`.ddrop` / carrier dir).
    Import {
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    Status,
    Peers,
    #[command(subcommand)]
    Peer(PeerCmd),
    Send {
        path: Option<PathBuf>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        public: bool,
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        trusted_only: bool,
        #[arg(long)]
        circle: Option<String>,
        #[arg(long)]
        priority: Option<String>,
        #[arg(long)]
        seal_until: Option<String>,
        #[arg(long)]
        seal_quorum: Option<u32>,
        #[arg(long, value_name = "DATA,PARITY")]
        erasure: Option<String>,
    },
    Receive,
    Inbox,
    #[command(hide = true, subcommand)]
    Drop(DropCmd),
    #[command(hide = true)]
    Objects,
    Inspect {
        #[arg(value_name = "KIND_OR_ID")]
        object: String,
        extra: Option<String>,
    },
    #[command(hide = true, subcommand)]
    Route(RouteCmd),
    #[command(hide = true)]
    Trace {
        object: String,
    },
    #[command(hide = true, subcommand)]
    Store(StoreCmd),
    #[command(hide = true, name = "network")]
    NetworkStats,
    Config,
    Doctor {
        #[arg(long)]
        repair: bool,
    },
    #[command(hide = true)]
    Mode {
        mode: String,
    },
    #[command(hide = true)]
    Serve {
        #[arg(long, default_value = "0.0.0.0:7947")]
        listen: SocketAddr,
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        #[arg(long)]
        no_broadcast: bool,
    },
    #[command(subcommand)]
    Daemon(DaemonCmd),
    /// One-shot TCP session with a listening node, then exit.
    /// Same LAN: `dd connect` (discovers the other node) or `dd connect --to home`.
    #[command(visible_alias = "connect")]
    Sync {
        /// Listening node (`HOST:PORT`). Optional when LAN beacons or `--to` can resolve it.
        #[arg(value_name = "HOST:PORT")]
        addr: Option<SocketAddr>,
        #[arg(long, value_name = "HOST:PORT")]
        peer: Option<SocketAddr>,
        /// Contact name or id; uses a live beacon or last known locator.
        #[arg(long)]
        to: Option<String>,
    },
    #[command(hide = true, subcommand)]
    Protocol(ProtocolCmd),
    Radar,
    #[command(hide = true)]
    Health {
        #[arg(long)]
        explain: bool,
    },
    #[command(hide = true)]
    Privacy,
    #[command(hide = true)]
    Search {
        query: String,
    },
    #[command(hide = true)]
    Pin {
        object: String,
    },
    #[command(hide = true)]
    Tag {
        object: String,
        tag: String,
    },
    #[command(hide = true, subcommand)]
    Space(SpaceCmd),
    #[command(hide = true, subcommand)]
    Channel(ChannelCmd),
    #[command(hide = true, subcommand)]
    Msg(MsgCmd),
    #[command(hide = true, subcommand)]
    Message(MsgCmd),
    #[command(hide = true, subcommand)]
    Transfer(TransferCmd),
    #[command(hide = true, subcommand)]
    Transport(TransportCmd),
    #[command(hide = true, subcommand)]
    Relay(RelayCmd),
    Completion {
        shell: String,
    },
    Version,
    #[command(hide = true, subcommand)]
    Board(BoardCmd),
    #[command(hide = true, subcommand)]
    Package(PkgCmd),
    #[command(hide = true, subcommand)]
    Web(WebCmd),
    #[command(subcommand)]
    Export(ExportCmd),
    #[command(hide = true, name = "import-carrier")]
    ImportCarrier {
        src: PathBuf,
    },
    #[command(hide = true)]
    Alias {
        id: String,
        name: String,
    },
    #[command(hide = true)]
    Pair {
        #[arg(long)]
        qr: bool,
    },
    #[command(hide = true, name = "node")]
    NodeRole {
        #[arg(long)]
        role: String,
    },
}

#[derive(Subcommand)]
enum ExportCmd {
    Carrier {
        dest: PathBuf,
    },
    Space {
        name: String,
        #[arg(long)]
        output: PathBuf,
    },
    Pending {
        #[arg(long)]
        destination: Option<String>,
        #[arg(long)]
        carrier: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PeerCmd {
    #[command(alias = "ls")]
    List,
    Inspect {
        id: String,
    },
    Alias {
        id: String,
        name: String,
    },
}

#[derive(Subcommand)]
enum DropCmd {
    #[command(alias = "ls")]
    List,
    Inspect {
        id: String,
    },
}

#[derive(Subcommand)]
enum RouteCmd {
    Explain {
        object: String,
        peer: String,
    },
    Predict {
        destination: String,
    },
    /// Legacy: `dd route <object> --explain <peer>`
    #[command(external_subcommand)]
    Raw(Vec<String>),
}

#[derive(Subcommand)]
enum TransferCmd {
    #[command(alias = "ls")]
    List,
}

#[derive(Subcommand)]
enum TransportCmd {
    #[command(alias = "ls")]
    List,
}

#[derive(Subcommand)]
enum RelayCmd {
    Status,
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// Start the node. Detaches unless `--foreground`.
    Start {
        #[arg(long, default_value = "0.0.0.0:7947")]
        listen: SocketAddr,
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Stay in this terminal (systemd/LaunchAgent/Task Scheduler use this).
        #[arg(long)]
        foreground: bool,
    },
    Stop,
    Restart {
        #[arg(long, default_value = "0.0.0.0:7947")]
        listen: SocketAddr,
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        #[arg(long)]
        foreground: bool,
    },
    Status,
    Logs,
    /// Install a user service: systemd --user, LaunchAgent, or a Windows logon task.
    Install {
        #[arg(long, default_value = "0.0.0.0:7947")]
        listen: SocketAddr,
    },
    Uninstall,
}

#[derive(Subcommand)]
enum IdentityCmd {
    Show,
    Export {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    Import {
        file: PathBuf,
    },
    Rotate,
    Verify,
    Revoke {
        device: String,
    },
}

#[derive(Subcommand)]
enum StoreCmd {
    Stats,
    Verify,
    Compact,
}

#[derive(Subcommand)]
enum ProtocolCmd {
    Inspect { file: PathBuf },
}

#[derive(Subcommand)]
enum SpaceCmd {
    Create {
        name: String,
        #[arg(long, default_value = "invite-only")]
        kind: String,
    },
    Invite {
        name: String,
    },
    List,
}

#[derive(Subcommand)]
enum ChannelCmd {
    Subscribe { name: String },
    Publish { name: String, file: PathBuf },
    List,
}

#[derive(Subcommand)]
enum MsgCmd {
    Send { to: String, text: String },
}

#[derive(Subcommand)]
enum BoardCmd {
    Create { name: String },
    Post { name: String, text: String },
}

#[derive(Subcommand)]
enum PkgCmd {
    Publish { file: PathBuf },
}

#[derive(Subcommand)]
enum WebCmd {
    Pack { dir: PathBuf },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let _ = (cli.verbose, cli.no_color);
    let mut dir = data_dir(cli.data_dir)?;
    if let Some(profile) = &cli.profile {
        dir = dir.join("profiles").join(profile);
        std::fs::create_dir_all(&dir)?;
    }
    let json = matches!(cli.output, Output::Json) || cli.json;
    let quiet = matches!(cli.output, Output::Quiet) || cli.quiet;
    match cli.command {
        Commands::Init { force } => {
            let store = Store::open(&dir, Default::default())?;
            let id = store.init_identity(force)?;
            let card = ContactCard::from_public(None, id.public.clone())?;
            std::fs::write(dir.join("identity.pub.ddcontact"), card.to_ddcontact()?)?;
            println!("identity  {}", id.peer_id);
            println!("protocol  {PROTOCOL_LABEL}");
            println!("data dir  {}", dir.display());
            println!("contact   {}", dir.join("identity.pub.ddcontact").display());
            let cfg_path = dir.join("deaddrop.toml");
            if !cfg_path.exists() {
                std::fs::write(&cfg_path, toml::to_string_pretty(&Config::default())?)?;
            }
            println!();
            println!("Two computers on the same network:");
            println!("  1. Copy identity.pub.ddcontact to the other machine");
            println!("  2. There:  dd import identity.pub.ddcontact --name this-pc");
            println!("  3. Here:   dd daemon start --listen 0.0.0.0:7947");
            println!("  4. There:  dd send ./file --to this-pc");
            println!("  5. There:  dd connect --to this-pc");
            println!("  6. Here:   dd receive");
            println!("No LAN? Use a USB stick: dd export pending --output E:/pending.ddrop");
        }
        Commands::Identity(c) => identity_cmd(&dir, c)?,
        Commands::Import { file, name } => {
            import_path(&dir, &file, name)?;
        }
        Commands::Status => status(&dir, json)?,
        Commands::Peers | Commands::Peer(PeerCmd::List) => {
            peer_list(&dir, json, quiet).await?;
        }
        Commands::Peer(PeerCmd::Inspect { id }) => peer_inspect(&dir, &id, json)?,
        Commands::Peer(PeerCmd::Alias { id, name }) => {
            let store = Store::open(&dir, Default::default())?;
            let book = store.load_contacts()?;
            let (pid, _) = book.resolve(&id)?;
            store.set_alias(pid, &name)?;
            println!("alias {name}");
        }
        Commands::Send {
            path,
            to,
            public,
            ttl,
            expires,
            trusted_only,
            circle,
            priority,
            seal_until,
            seal_quorum,
            erasure,
        } => {
            send_cmd(
                &dir,
                path,
                to,
                public,
                ttl.or(expires),
                trusted_only,
                circle,
                priority,
                seal_until,
                seal_quorum,
                erasure,
                json,
                quiet,
            )
            .await?;
        }
        Commands::Receive | Commands::Inbox => inbox_cmd(&dir, json, quiet)?,
        Commands::Drop(DropCmd::List) | Commands::Objects => objects_cmd(&dir, json)?,
        Commands::Drop(DropCmd::Inspect { id }) => inspect(&dir, &id, json)?,
        Commands::Inspect { object, extra } => {
            let spec = extra.as_deref().unwrap_or(&object);
            match object.as_str() {
                "drop" => inspect(&dir, spec, json)?,
                "peer" => peer_inspect(&dir, spec, json)?,
                "route" => {
                    let node = Node::open(&dir, Config::default())?;
                    print!(
                        "{}",
                        node.explain_route(spec, extra.as_deref().unwrap_or(spec))?
                    );
                }
                "space" => {
                    let store = Store::open(&dir, Default::default())?;
                    for s in store.list_spaces()? {
                        if s.name.contains(spec) {
                            println!("{}  {:?}", s.name, s.kind);
                        }
                    }
                }
                "channel" => {
                    let store = Store::open(&dir, Default::default())?;
                    for (n, f, p) in store.list_channels()? {
                        if n.contains(spec) {
                            println!("{n}  {f}  {p}");
                        }
                    }
                }
                "manifest" | "receipt" => inspect(&dir, spec, json)?,
                _ => inspect(&dir, &object, json)?,
            }
        }
        Commands::Route(RouteCmd::Explain { object, peer }) => {
            let node = Node::open(&dir, Config::default())?;
            print!("{}", node.explain_route(&object, &peer)?);
        }
        Commands::Route(RouteCmd::Predict { destination }) => {
            let node = Node::open(&dir, Config::load(&dir.join("deaddrop.toml"))?)?;
            let f = node.predict_route(&destination)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&f)?);
            } else {
                println!("Destination: {}", f.destination);
                println!("Estimated delivery (not a guarantee)");
                println!("  < 1 hour    {:>5.0}%", f.p_lt_1h * 100.0);
                println!("  < 6 hours   {:>5.0}%", f.p_lt_6h * 100.0);
                println!("  < 24 hours  {:>5.0}%", f.p_lt_24h * 100.0);
                println!("  < 3 days    {:>5.0}%", f.p_lt_3d * 100.0);
                println!(
                    "Confidence    {:>5.0}%  (n={})",
                    f.confidence * 100.0,
                    f.sample_encounters
                );
                println!("{}", f.note);
            }
        }
        Commands::Route(RouteCmd::Raw(args)) => {
            anyhow::bail!(
                "unknown route args {args:?}; try `dd route explain <drop> <peer>` or `dd route predict <peer>`"
            );
        }
        Commands::Trace { object } => {
            let store = Store::open(&dir, Default::default())?;
            for id in store.inventory(unix_now())? {
                if id.to_string().contains(&object)
                    || hex_encode(id.as_bytes()).starts_with(&object)
                {
                    for (ts, ev) in store.traces(&id)? {
                        println!("{ts} {ev}");
                    }
                }
            }
        }
        Commands::Store(StoreCmd::Stats) => {
            let store = Store::open(&dir, Default::default())?;
            let s = store.stats()?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "objects": s.objects,
                        "chunks": s.chunks,
                        "logical": s.logical_size,
                        "physical": s.physical_size,
                        "dedup": s.dedup_ratio(),
                    })
                );
            } else {
                println!("Objects             {}", s.objects);
                println!("Payloads             {}", s.payloads);
                println!("Chunks             {}", s.chunks);
                println!("Logical Size        {}", format_bytes(s.logical_size));
                println!("Physical Size       {}", format_bytes(s.physical_size));
                println!("Deduplication        {:.1}%", s.dedup_ratio() * 100.0);
            }
        }
        Commands::Store(StoreCmd::Verify) => {
            let store = Store::open(&dir, Default::default())?;
            let p = store.verify()?;
            if p.is_empty() {
                println!("ok");
            } else {
                for x in p {
                    println!("! {x}");
                }
            }
        }
        Commands::Store(StoreCmd::Compact) => {
            let store = Store::open(&dir, Default::default())?;
            let n = store.compact()?;
            println!("compacted; gc rows {n}");
        }
        Commands::NetworkStats => {
            let store = Store::open(&dir, Default::default())?;
            for (id, e) in store.all_encounters()? {
                println!(
                    "{id} encounters={} sent={} recv={}",
                    e.encounter_count, e.bytes_sent, e.bytes_received
                );
            }
        }
        Commands::Config => {
            let cfg = Config::load(&dir.join("deaddrop.toml"))?;
            print!("{}", toml::to_string_pretty(&cfg)?);
        }
        Commands::Doctor { repair } => {
            if repair {
                let notes = doctor_repair(&dir)?;
                if json {
                    println!("{}", serde_json::json!({ "repair": notes }));
                } else {
                    println!("DeadDrop Doctor --repair (never deletes Drops)");
                    for n in notes {
                        println!("✓ {n}");
                    }
                }
            } else {
                let cfg = Config::load(&dir.join("deaddrop.toml"))?;
                let checks = doctor(&dir, &cfg)?;
                if json {
                    let rows: Vec<_> = checks
                        .iter()
                        .map(|c| {
                            serde_json::json!({
                                "name": c.name,
                                "ok": c.ok,
                                "warn": c.warn,
                                "detail": c.detail,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::json!({ "checks": rows }));
                } else if !quiet {
                    println!("DeadDrop Doctor");
                    let mut pass = 0;
                    let mut warn = 0;
                    let mut fail = 0;
                    for c in &checks {
                        let mark = if !c.ok {
                            fail += 1;
                            "✗"
                        } else if c.warn {
                            warn += 1;
                            "!"
                        } else {
                            pass += 1;
                            "✓"
                        };
                        println!("{mark} {} — {}", c.name, c.detail);
                    }
                    println!("{warn} warning\n{fail} errors");
                    let _ = pass;
                }
            }
        }
        Commands::Mode { mode } => {
            let mut cfg = Config::load(&dir.join("deaddrop.toml")).unwrap_or_default();
            cfg.node.mode = parse_mode(&mode)?;
            std::fs::write(
                dir.join("deaddrop.toml"),
                toml::to_string_pretty(&cfg).unwrap_or_default(),
            )?;
            println!("mode {:?}", cfg.node.mode);
        }
        Commands::Serve {
            listen,
            peers,
            no_broadcast: _,
        } => {
            let node = Node::open(&dir, Config::load(&dir.join("deaddrop.toml"))?)?;
            if !quiet {
                println!(
                    "DeadDrop node {}  {PROTOCOL_LABEL}  listen={listen} (TCP)",
                    node.identity.peer_id.short()
                );
            }
            node.serve(listen, peers).await?;
        }
        Commands::Daemon(cmd) => daemon_cmd(&dir, cmd, json, quiet).await?,
        Commands::Sync { addr, peer, to } => {
            let node = Node::open(&dir, Config::load(&dir.join("deaddrop.toml"))?)?;
            let target = resolve_sync_addr(&node, addr, peer, to.as_deref()).await?;
            let stats = match node.sync_once(target).await {
                Ok(s) => s,
                Err(e) => {
                    let msg = e.to_string();
                    if looks_like_refused(&msg) {
                        anyhow::bail!(
                            "Nothing is listening at {target}. On that computer run:\n  dd daemon start --listen 0.0.0.0:7947"
                        );
                    }
                    return Err(e.into());
                }
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "addr": target.to_string(),
                        "peer": stats.peer.map(|p| p.to_string()),
                        "envelopes": stats.envelopes,
                        "chunks": stats.chunks,
                    })
                );
            } else if !quiet {
                println!(
                    "synced {} peer={} envelopes={} chunks={}",
                    target,
                    stats
                        .peer
                        .map(|p| p.short())
                        .unwrap_or_else(|| "unknown".into()),
                    stats.envelopes,
                    stats.chunks
                );
            }
        }
        Commands::Protocol(ProtocolCmd::Inspect { file }) => {
            let bytes = std::fs::read(&file)?;
            print!("{}", deaddrop_app::inspect_protocol_bytes(&bytes));
        }
        Commands::Radar => {
            let cfg = Config::load(&dir.join("deaddrop.toml")).unwrap_or_default();
            println!("DeadDrop Radar (LAN beacons, 3s scan)");
            println!("PEER                 LINK    ADDRESS");
            match deaddrop_net::scan_lan(cfg.discovery.lan_port, 3000).await {
                Ok(eps) if !eps.is_empty() => {
                    let store = Store::open(&dir, Default::default()).ok();
                    for e in &eps {
                        if let (Some(store), Some(pid)) = (store.as_ref(), e.peer) {
                            let _ = deaddrop_net::remember_locator(store, Some(pid), &e.locator);
                        }
                        println!(
                            "{:<20} LAN     {}",
                            e.peer
                                .map(|p| p.short())
                                .unwrap_or_else(|| "unknown".into()),
                            e.locator
                        );
                    }
                }
                _ => println!(
                    "(no beacons — start `dd daemon start` on the other computer; UDP 7946 / TCP 7947)"
                ),
            }
        }
        Commands::Health { explain } => {
            let store = Store::open(&dir, Default::default())?;
            let s = store.stats()?;
            let n = store.all_encounters()?.len();
            let conn = (n.min(10) as u32) * 10;
            let stor = if s.physical_size < 15_000_000_000 {
                90
            } else {
                60
            };
            let overall = (conn + stor) / 2;
            println!("Network Health (local estimates, not absolute)");
            println!("Connectivity          {conn}");
            println!("Storage               {stor}");
            println!("Peer Diversity        {}", n.min(100));
            println!("Overall               {overall}/100");
            if explain {
                println!(
                    "Peer Diversity — based on {} recorded encounters. Enable more relays or discovery to raise this.",
                    n
                );
            }
        }
        Commands::Privacy => {
            let cfg = Config::load(&dir.join("deaddrop.toml"))?;
            println!("Discovery visibility     {}", cfg.discovery.lan);
            println!(
                "Unknown peer relay       {}",
                cfg.node.mode.unsolicited_relay()
            );
            println!(
                "Encounter retention      {}",
                cfg.node.mode.retain_encounters()
            );
            println!("Telemetry                none (local only)");
        }
        Commands::Search { query } => {
            let store = Store::open(&dir, Default::default())?;
            for id in store.search_meta(&query)? {
                println!("{id}");
            }
        }
        Commands::Pin { object } => {
            let store = Store::open(&dir, Default::default())?;
            let node = Node::open(&dir, Config::default())?;
            let (oid, _) = resolve_oid(&node, &object)?;
            store.pin(&oid)?;
            println!("pinned {oid}");
        }
        Commands::Tag { object, tag } => {
            let store = Store::open(&dir, Default::default())?;
            let node = Node::open(&dir, Config::default())?;
            let (oid, _) = resolve_oid(&node, &object)?;
            store.tag(&oid, &tag)?;
            println!("tagged {oid} {tag}");
        }
        Commands::Space(SpaceCmd::Create { name, kind }) => {
            let node = Node::open(&dir, Config::default())?;
            let k = match kind.as_str() {
                "public" => deaddrop_core::space::SpaceKind::Public,
                "private" => deaddrop_core::space::SpaceKind::Private,
                "ephemeral" => deaddrop_core::space::SpaceKind::Ephemeral,
                _ => deaddrop_core::space::SpaceKind::InviteOnly,
            };
            let rec = deaddrop_core::space::SpaceRecord::issue(
                &node.identity,
                name,
                k,
                vec![node.identity.peer_id],
                "retain all".into(),
                unix_now(),
            );
            node.store.put_space(&rec)?;
            println!("space {}", rec.name);
        }
        Commands::Space(SpaceCmd::Invite { name }) => {
            let node = Node::open(&dir, Config::default())?;
            let inv =
                deaddrop_core::space::SpaceInvite::issue(&node.identity, name, None, unix_now());
            let path = dir.join("invite.ddspace");
            std::fs::write(&path, serde_json::to_vec_pretty(&inv)?)?;
            println!("invite {}", path.display());
        }
        Commands::Space(SpaceCmd::List) => {
            let store = Store::open(&dir, Default::default())?;
            for s in store.list_spaces()? {
                println!("{}  {:?}  members {}", s.name, s.kind, s.members.len());
            }
        }
        Commands::Channel(ChannelCmd::Subscribe { name }) => {
            let store = Store::open(&dir, Default::default())?;
            store.subscribe_channel(&deaddrop_core::channel::ChannelSub {
                name,
                filter: deaddrop_core::channel::ChannelFilter::Subscribe,
                policy: deaddrop_core::channel::ChannelPolicy::SignedPublic,
            })?;
            println!("subscribed");
        }
        Commands::Channel(ChannelCmd::Publish { name, file }) => {
            let node = Node::open(&dir, Config::default())?;
            let body = std::fs::read(&file)?;
            let oid = node.send_payload(
                "",
                body,
                true,
                None,
                Priority::Normal,
                "dd.channel",
                Some(name),
                false,
            )?;
            println!("{oid}");
        }
        Commands::Channel(ChannelCmd::List) => {
            let store = Store::open(&dir, Default::default())?;
            for (n, f, p) in store.list_channels()? {
                println!("{n}  {f}  {p}");
            }
        }
        Commands::Message(MsgCmd::Send { to, text }) | Commands::Msg(MsgCmd::Send { to, text }) => {
            let node = Node::open(&dir, Config::default())?;
            let oid = node.send_payload(
                &to,
                text.into_bytes(),
                false,
                None,
                Priority::Important,
                "dd.message",
                None,
                false,
            )?;
            println!("queued {oid} (intermediary identities not shown)");
        }
        Commands::Board(BoardCmd::Create { name }) => {
            println!("board {name} (posts are public signed Drops)");
        }
        Commands::Board(BoardCmd::Post { name, text }) => {
            let node = Node::open(&dir, Config::default())?;
            let oid = node.send_payload(
                "",
                text.into_bytes(),
                true,
                None,
                Priority::Normal,
                "dd.board",
                Some(name),
                false,
            )?;
            println!("{oid}");
        }
        Commands::Package(PkgCmd::Publish { file }) => {
            let node = Node::open(&dir, Config::default())?;
            let body = std::fs::read(&file)?;
            let oid = node.send_payload(
                "",
                body,
                true,
                None,
                Priority::Normal,
                "dd.package",
                None,
                false,
            )?;
            println!("signed package drop {oid}");
        }
        Commands::Web(WebCmd::Pack { dir: site }) => {
            let mut blob = Vec::new();
            for ent in walk_files(&site) {
                blob.extend_from_slice(ent.as_bytes());
                blob.push(0);
            }
            let out = dir.join("site.ddweb");
            std::fs::write(&out, blob)?;
            println!(
                "{} — viewer/sandbox is PLANNED; this file is a signed-capable payload container",
                out.display()
            );
        }
        Commands::Export(ExportCmd::Carrier { dest }) => {
            let store = Store::open(&dir, Default::default())?;
            let m = deaddrop_core::carrier::export_carrier(&store, &dest)?;
            println!("exported {} objects to {}", m.objects, dest.display());
        }
        Commands::Export(ExportCmd::Space { name, output }) => {
            let store = Store::open(&dir, Default::default())?;
            let m = deaddrop_core::carrier::export_ddrop(
                &store,
                &output,
                deaddrop_core::carrier::ExportFilter::default(),
            )?;
            println!(
                "exported {} objects (space {name} is advisory metadata) to {}",
                m.objects,
                output.display()
            );
        }
        Commands::Export(ExportCmd::Pending {
            destination,
            carrier,
            output,
        }) => {
            let store = Store::open(&dir, Default::default())?;
            let dest_peer = if let Some(d) = destination {
                let book = store.load_contacts()?;
                Some(book.resolve(&d)?.0)
            } else {
                None
            };
            let filter = deaddrop_core::carrier::ExportFilter {
                destination: dest_peer,
                pending_only: true,
            };
            let path = carrier
                .or(output)
                .unwrap_or_else(|| dir.join("pending.ddrop"));
            let m = if path.extension().and_then(|e| e.to_str()) == Some("ddrop") {
                deaddrop_core::carrier::export_ddrop(&store, &path, filter)?
            } else {
                deaddrop_core::carrier::export_carrier_filtered(&store, &path, filter)?
            };
            println!(
                "exported {} pending objects to {}",
                m.objects,
                path.display()
            );
        }
        Commands::ImportCarrier { src } => {
            import_path(&dir, &src, None)?;
        }
        Commands::Transfer(TransferCmd::List) => {
            let store = Store::open(&dir, Default::default())?;
            let v = deaddrop_net::control::transfers_json(&store, unix_now())?;
            if json {
                println!("{v}");
            } else {
                println!(
                    "active {}  queued {}  completed {}",
                    v["active"], v["queued"], v["completed"]
                );
            }
        }
        Commands::Transport(TransportCmd::List) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "tcp": "default listener",
                        "lan": "UDP beacons when serving",
                        "quic": "EXPERIMENTAL types",
                        "bluetooth": "PLANNED",
                        "wifi_direct": "PLANNED",
                        "usb": "sneakernet via dd export / dd import",
                    })
                );
            } else {
                println!("TCP          default `dd serve` / `dd daemon start`");
                println!("LAN          UDP beacons when the daemon is running");
                println!("QUIC         EXPERIMENTAL (types present; default loop is TCP)");
                println!("Bluetooth    PLANNED");
                println!("Wi-Fi Direct PLANNED");
                println!("USB          `dd export pending` / `dd import`");
            }
        }
        Commands::Relay(RelayCmd::Status) => {
            let cfg = Config::load(&dir.join("deaddrop.toml"))?;
            println!("role {:?}", cfg.node.role);
            println!("mode {:?}", cfg.node.mode);
            println!("unsolicited relay {}", cfg.node.mode.unsolicited_relay());
        }
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            let sh = match shell.to_ascii_lowercase().as_str() {
                "bash" => Shell::Bash,
                "zsh" => Shell::Zsh,
                "fish" => Shell::Fish,
                "powershell" | "pwsh" => Shell::PowerShell,
                "elvish" => Shell::Elvish,
                other => anyhow::bail!("unknown shell {other} (bash|zsh|fish|powershell)"),
            };
            generate(sh, &mut cmd, "dd", &mut std::io::stdout());
        }
        Commands::Version => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "crate": env!("CARGO_PKG_VERSION"),
                        "protocol": PROTOCOL_LABEL,
                    })
                );
            } else {
                println!("dd {} ({PROTOCOL_LABEL})", env!("CARGO_PKG_VERSION"));
            }
        }
        Commands::Alias { id, name } => {
            let store = Store::open(&dir, Default::default())?;
            let book = store.load_contacts()?;
            let (pid, _) = book.resolve(&id)?;
            store.set_alias(pid, &name)?;
            println!("alias {name}");
        }
        Commands::Pair { qr: _ } => {
            let store = Store::open(&dir, Default::default())?;
            let id = store.load_identity()?;
            let card = ContactCard::from_public(None, id.public.clone())?;
            let path = dir.join("identity.pub.ddcontact");
            std::fs::write(&path, card.to_ddcontact()?)?;
            println!("{}", card.to_text());
            println!("Wrote {}", path.display());
            println!(
                "Copy that file to the other computer, then: dd import {} --name <alias>",
                path.display()
            );
        }
        Commands::NodeRole { role } => {
            let mut cfg = Config::load(&dir.join("deaddrop.toml")).unwrap_or_default();
            cfg.node.role = deaddrop_core::NodeRole::from_str_role(&role)
                .ok_or_else(|| anyhow::anyhow!("unknown role"))?;
            std::fs::write(dir.join("deaddrop.toml"), toml::to_string_pretty(&cfg)?)?;
            println!("role {:?}", cfg.node.role);
        }
    }
    Ok(())
}

fn identity_cmd(dir: &PathBuf, c: IdentityCmd) -> Result<()> {
    let store = Store::open(dir, Default::default())?;
    match c {
        IdentityCmd::Show => {
            let id = store.load_identity()?;
            println!("{}", id.peer_id);
            println!(
                "fingerprint {}",
                deaddrop_core::identity::fingerprint(&id.public)
            );
        }
        IdentityCmd::Export { file } => {
            let id = store.load_identity()?;
            let card = ContactCard::from_public(None, id.public.clone())?;
            let path = file.unwrap_or_else(|| dir.join("identity.pub.ddcontact"));
            std::fs::write(path, card.to_ddcontact()?)?;
        }
        IdentityCmd::Import { file } => {
            let bytes = std::fs::read(file)?;
            let parsed: IdentityFile = serde_json::from_slice(&bytes)?;
            store.save_identity(&parsed.into_private()?)?;
            println!("imported private identity");
        }
        IdentityCmd::Rotate => {
            let old = store.load_identity()?;
            let new = deaddrop_core::crypto::PrivateIdentity::generate();
            let t = IdentityTransition::issue(&old, new.public.clone(), unix_now())?;
            store.save_identity(&new)?;
            std::fs::write(
                dir.join("identity-transition.json"),
                serde_json::to_vec_pretty(&t)?,
            )?;
            println!("rotated {} -> {}", old.peer_id, new.peer_id);
            println!("transition record written; import it on peers to preserve reachability");
        }
        IdentityCmd::Verify => {
            let id = store.load_identity()?;
            deaddrop_core::crypto::verify_identity(&id.public)?;
            println!("ok {}", id.peer_id);
        }
        IdentityCmd::Revoke { device } => {
            let id = store.load_identity()?;
            let rec = serde_json::json!({
                "type": "dd.revocation",
                "issuer": id.peer_id.to_string(),
                "target": device,
                "ts": unix_now(),
            });
            let path = dir.join("revocation.json");
            std::fs::write(&path, serde_json::to_vec_pretty(&rec)?)?;
            println!(
                "revocation record {} — propagate via Drop (store-carry-forward); no internet required",
                path.display()
            );
        }
    }
    Ok(())
}

fn status(dir: &std::path::Path, json: bool) -> Result<()> {
    let store = Store::open(dir, Default::default())?;
    let id = store.load_identity()?;
    let cfg = Config::load(&dir.join("deaddrop.toml"))?;
    let s = store.stats()?;
    let contacts = store.load_contacts()?.all().count();
    let now = unix_now();
    let t = deaddrop_net::control::transfers_json(&store, now)?;
    let daemon = deaddrop_net::control::read_info(dir).ok().flatten();
    let uptime = daemon
        .as_ref()
        .map(|d| format_uptime(now.saturating_sub(d.started_at)))
        .unwrap_or_else(|| "not running".into());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "identity": id.peer_id.to_string(),
                "protocol": PROTOCOL_LABEL,
                "mode": format!("{:?}", cfg.node.mode),
                "objects": s.objects,
                "storage_used": s.physical_size,
                "contacts": contacts,
                "transfers": t,
                "daemon": daemon,
            })
        );
        return Ok(());
    }
    println!("DeadDrop {}", env!("CARGO_PKG_VERSION"));
    println!("Node");
    println!("  {}", id.peer_id.short());
    println!("  online for {uptime}");
    println!("Identity");
    println!("  {}", id.peer_id);
    println!("Peers");
    println!("  known        {contacts}");
    println!("Transfers");
    println!("  active       {}", t["active"]);
    println!("  queued       {}", t["queued"]);
    println!("  completed    {}", t["completed"]);
    println!("Storage");
    println!(
        "  {} / {}",
        format_bytes(s.physical_size),
        cfg.storage.maximum
    );
    println!("Routes");
    println!(
        "  LAN          {}",
        if cfg.discovery.lan {
            "configured"
        } else {
            "disabled"
        }
    );
    println!("  TCP          use `dd daemon start` or `dd serve`");
    println!(
        "  QUIC         {}",
        if cfg.transport.quic {
            "configured (EXPERIMENTAL)"
        } else {
            "disabled"
        }
    );
    println!("  USB          idle (export/import)");
    println!("  Bluetooth    unavailable");
    println!("Daemon");
    println!(
        "  {}",
        if daemon.is_some() {
            "control socket recorded"
        } else {
            "not running"
        }
    );
    println!("Protocol       {PROTOCOL_LABEL}");
    Ok(())
}

fn inspect(dir: &std::path::Path, object: &str, json: bool) -> Result<()> {
    let store = Store::open(dir, Default::default())?;
    for id in store.inventory(unix_now())? {
        if id.to_string().contains(object) || hex_encode(id.as_bytes()).starts_with(object) {
            let env = store.get_envelope(&id)?.unwrap();
            let mask = store.present_mask(&id)?;
            let present = mask.iter().filter(|x| **x).count();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "object": id.to_string(),
                        "source": env.source.to_string(),
                        "priority": env.priority.cli_name(),
                        "hops": format!("{}/{}", env.hop_count, env.hop_limit),
                        "chunks": format!("{present}/{}", mask.len()),
                        "application": env.application,
                        "seal_until": deaddrop_core::sealed::seal_until(&env),
                    })
                );
                return Ok(());
            }
            println!("Object       {id}");
            println!("Source       {}", env.source);
            println!("Destination  {:?}", env.destination);
            println!("Creation     {}", env.creation_time);
            println!("Expiration   {}", env.expiration);
            println!("Priority     {}", env.priority.cli_name());
            println!("Hop Count    {}/{}", env.hop_count, env.hop_limit);
            println!("Chunks       {present}/{}", mask.len());
            println!("Signature    valid (verified at ingest)");
            println!("Encryption   {}", env.security_descriptor.scheme);
            if let Some(u) = deaddrop_core::sealed::seal_until(&env) {
                println!("Sealed until {u} (policy)");
            }
            return Ok(());
        }
    }
    anyhow::bail!("not found")
}

fn parse_mode(s: &str) -> Result<NodeMode> {
    Ok(match s {
        "performance" => NodeMode::Performance,
        "balanced" => NodeMode::Balanced,
        "battery" => NodeMode::Battery,
        "offline" => NodeMode::Offline,
        "relay" | "relay-only" => NodeMode::RelayOnly,
        "private" => NodeMode::Private,
        _ => anyhow::bail!("unknown mode"),
    })
}

fn data_dir(o: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = o {
        std::fs::create_dir_all(&p)?;
        return Ok(p);
    }
    let b = directories::ProjectDirs::from("org", "deaddrop", "deaddrop").context("home")?;
    let p = b.data_dir().to_path_buf();
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

fn resolve_oid(
    node: &Node,
    spec: &str,
) -> Result<(deaddrop_core::ObjectId, deaddrop_core::DropEnvelope)> {
    if let Ok(id) = spec.parse() {
        if let Some(env) = node.store.get_envelope(&id)? {
            return Ok((id, env));
        }
    }
    let prefix = spec.rsplit(':').next().unwrap_or(spec).to_ascii_lowercase();
    for id in node.store.inventory(unix_now())? {
        if hex_encode(id.as_bytes()).starts_with(&prefix) {
            if let Some(env) = node.store.get_envelope(&id)? {
                return Ok((id, env));
            }
        }
    }
    anyhow::bail!("object not found")
}

fn walk_files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let _ = visit(dir, &mut out);
    out
}

fn visit(dir: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        if p.is_dir() {
            visit(&p, out)?;
        } else if let Some(s) = p.to_str() {
            out.push(s.to_string());
        }
    }
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}\n> ");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

async fn send_cmd(
    dir: &Path,
    mut path: Option<PathBuf>,
    mut to: Option<String>,
    public: bool,
    ttl: Option<String>,
    trusted_only: bool,
    circle: Option<String>,
    priority: Option<String>,
    seal_until: Option<String>,
    seal_quorum: Option<u32>,
    erasure: Option<String>,
    json: bool,
    quiet: bool,
) -> Result<()> {
    let interactive = std::io::stdin().is_terminal() && !json;
    if path.is_none() && interactive {
        let p = prompt("File")?;
        path = Some(PathBuf::from(p));
    }
    if to.is_none() && !public && circle.is_none() && interactive {
        to = Some(prompt("Recipient")?);
    }
    let Some(path) = path else {
        anyhow::bail!("file path required (or run interactively on a TTY)");
    };
    let dest = to.as_deref().unwrap_or("");
    if !public && dest.is_empty() && circle.is_none() {
        anyhow::bail!("--to <peer>, --circle, or --public");
    }
    let pri = priority
        .as_deref()
        .and_then(Priority::parse_cli)
        .unwrap_or(Priority::Normal);
    let ttl_secs = ttl.as_deref().and_then(parse_duration_or_rfc3339);
    let seal_ts = seal_until.as_deref().and_then(|s| {
        if s.contains('T') {
            parse_duration_or_rfc3339(s)
        } else {
            parse_duration_or_rfc3339(s).map(|d| unix_now().saturating_add(d))
        }
    });
    let erasure_spec = if let Some(e) = erasure {
        let mut p = e.split(',');
        let data: u32 = p.next().unwrap_or("10").trim().parse().unwrap_or(10);
        let parity: u32 = p.next().unwrap_or("1").trim().parse().unwrap_or(1);
        Some(deaddrop_core::chunk::ErasureSpec {
            data_shards: data,
            parity_shards: parity,
        })
    } else {
        None
    };
    let node = Node::open(dir, Config::load(&dir.join("deaddrop.toml"))?)?;
    if !quiet {
        println!("Encrypting...");
    }
    let body = std::fs::read(&path)?;
    if let Some(c) = circle {
        let members = node.store.circle_members(&c)?;
        for m in members {
            let _ = node.send_opts(SendOpts {
                to: m.to_string(),
                plaintext: body.clone(),
                public: false,
                ttl: ttl_secs,
                priority: pri,
                application: "dd.file".into(),
                topic: None,
                trusted_only,
                seal_until: seal_ts,
                seal_quorum,
                erasure: erasure_spec,
            })?;
        }
        println!("queued for circle {c}");
        return Ok(());
    }
    let oid = node.send_opts(SendOpts {
        to: dest.to_string(),
        plaintext: body,
        public,
        ttl: ttl_secs,
        priority: pri,
        application: "dd.file".into(),
        topic: None,
        trusted_only,
        seal_until: seal_ts,
        seal_quorum,
        erasure: erasure_spec,
    })?;
    if json {
        println!("{}", serde_json::json!({ "id": oid.to_string() }));
    } else if !quiet {
        println!("✓ Drop created");
        println!("CID");
        println!("  {oid}");
        println!("Queued for delivery. Use `dd daemon start` or `dd connect`.");
    }
    Ok(())
}

fn inbox_cmd(dir: &Path, json: bool, quiet: bool) -> Result<()> {
    let node = Node::open(dir, Config::default())?;
    let items = node.inbox()?;
    if json {
        let rows: Vec<_> = items
            .iter()
            .map(|it| {
                serde_json::json!({
                    "id": it.object_id.to_string(),
                    "from": it.from.to_string(),
                    "bytes": it.bytes,
                    "application": it.application,
                })
            })
            .collect();
        println!("{}", serde_json::json!({ "inbox": rows }));
        return Ok(());
    }
    if quiet {
        return Ok(());
    }
    for it in items {
        println!("Incoming Drop");
        println!("ID       {}", it.object_id);
        println!("Type     {}", it.application);
        println!("Size     {} bytes", it.bytes);
        println!("Verified ✓");
        println!("From     {}", it.from);
        println!();
    }
    Ok(())
}

fn objects_cmd(dir: &Path, json: bool) -> Result<()> {
    let store = Store::open(dir, Default::default())?;
    let mut rows = Vec::new();
    for id in store.inventory(unix_now())? {
        if let Ok(Some(env)) = store.get_envelope(&id) {
            rows.push(serde_json::json!({
                "id": id.to_string(),
                "application": env.application,
                "priority": env.priority.cli_name(),
            }));
            if !json {
                println!(
                    "{id}  {}  hops {}/{}  {}",
                    env.application,
                    env.hop_count,
                    env.hop_limit,
                    env.priority.cli_name()
                );
            }
        }
    }
    if json {
        println!("{}", serde_json::json!({ "drops": rows }));
    }
    Ok(())
}

fn looks_like_refused(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("connection refused")
        || m.contains("10061")
        || m.contains("actively refused")
        || m.contains("os error 111")
}

fn parse_locator(s: &str) -> Result<SocketAddr> {
    s.parse()
        .map_err(|_| anyhow::anyhow!("invalid address {s}"))
}

async fn resolve_sync_addr(
    node: &Node,
    addr: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    to: Option<&str>,
) -> Result<SocketAddr> {
    if let Some(a) = addr.or(peer) {
        return Ok(a);
    }
    let lan_port = node.cfg.discovery.lan_port;
    let scan = deaddrop_net::scan_lan(lan_port, 2000)
        .await
        .unwrap_or_default();
    let others: Vec<_> = scan
        .into_iter()
        .filter(|e| e.peer != Some(node.identity.peer_id))
        .collect();
    for e in &others {
        let _ = deaddrop_net::remember_locator(node.store.as_ref(), e.peer, &e.locator);
    }

    if let Some(name) = to {
        let book = node.store.load_contacts()?;
        let (pid, _) = book.resolve(name).map_err(|e| {
            anyhow::anyhow!(
                "unknown contact '{name}' — import a .ddcontact or pass --peer HOST:PORT\n{e}"
            )
        })?;
        if let Some(e) = others.iter().find(|e| e.peer == Some(pid)) {
            return parse_locator(&e.locator);
        }
        if let Some(loc) = deaddrop_net::remembered_locator(node.store.as_ref(), pid)? {
            return parse_locator(&loc);
        }
        anyhow::bail!(
            "No LAN address for '{name}'. Start `dd daemon start` on that computer, or pass:\n  dd connect --peer HOST:7947"
        );
    }

    let mut locators = others
        .iter()
        .map(|e| e.locator.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if locators.len() == 1 {
        return parse_locator(locators.pop_first().unwrap().as_str());
    }
    if locators.is_empty() {
        if let Some(last) = deaddrop_net::last_locator(node.store.as_ref())? {
            return parse_locator(&last);
        }
        anyhow::bail!(
            "No LAN beacons and no last address.\nOn the other computer: dd daemon start --listen 0.0.0.0:7947\nThen: dd connect   or   dd connect --peer <ip>:7947   or   dd connect --to <name>"
        );
    }
    let mut msg = String::from("Several computers are advertising on this LAN. Pick one:\n");
    for e in &others {
        let label = e
            .peer
            .map(|p| p.short())
            .unwrap_or_else(|| "unknown".into());
        msg.push_str(&format!("  {}  {label}\n", e.locator));
    }
    msg.push_str("Use: dd connect --peer HOST:PORT   or   dd connect --to <name>");
    anyhow::bail!(msg)
}

async fn peer_list(dir: &Path, json: bool, quiet: bool) -> Result<()> {
    let store = Store::open(dir, Default::default())?;
    let self_id = store.load_identity().ok().map(|i| i.peer_id);
    let cfg = Config::load(&dir.join("deaddrop.toml")).unwrap_or_default();
    let beacons = deaddrop_net::scan_lan(cfg.discovery.lan_port, 1500)
        .await
        .unwrap_or_default();
    let mut live: std::collections::HashMap<deaddrop_core::PeerId, String> =
        std::collections::HashMap::new();
    let mut unmatched = Vec::new();
    for e in beacons {
        if e.peer == self_id {
            continue;
        }
        if let Some(pid) = e.peer {
            let _ = deaddrop_net::remember_locator(&store, Some(pid), &e.locator);
            live.insert(pid, e.locator);
        } else {
            unmatched.push(e);
        }
    }

    let book = store.load_contacts()?;
    let mut rows = Vec::new();
    let mut known = std::collections::HashSet::new();
    for (id, c) in book.all() {
        known.insert(*id);
        let live_loc = live.get(id).cloned();
        let remembered = deaddrop_net::remembered_locator(&store, *id).ok().flatten();
        let locator = live_loc.clone().or(remembered);
        rows.push(serde_json::json!({
            "id": id.to_string(),
            "trust": format!("{:?}", c.trust),
            "name": c.card.name,
            "locator": locator,
            "live": live_loc.is_some(),
        }));
    }
    for (id, loc) in &live {
        if known.contains(id) {
            continue;
        }
        rows.push(serde_json::json!({
            "id": id.to_string(),
            "trust": "Observed",
            "name": serde_json::Value::Null,
            "locator": loc,
            "live": true,
        }));
    }
    for e in unmatched {
        rows.push(serde_json::json!({
            "id": serde_json::Value::Null,
            "trust": "Observed",
            "name": serde_json::Value::Null,
            "locator": e.locator,
            "live": true,
        }));
    }

    if json {
        println!("{}", serde_json::json!({ "peers": rows }));
        return Ok(());
    }
    if quiet {
        return Ok(());
    }
    if rows.is_empty() {
        println!(
            "(no contacts or LAN beacons — import a .ddcontact, or start `dd daemon start` on the other PC)"
        );
        return Ok(());
    }
    println!("{:<14} {:<10} {:<22} ID", "NAME", "TRUST", "REACHABLE");
    for row in &rows {
        let name = row["name"].as_str().unwrap_or("(lan)");
        let trust = row["trust"].as_str().unwrap_or("");
        let loc = row["locator"].as_str().unwrap_or("—");
        let id = row["id"].as_str().unwrap_or("");
        println!("{name:<14} {trust:<10} {loc:<22} {id}");
    }
    Ok(())
}

fn peer_inspect(dir: &Path, id: &str, json: bool) -> Result<()> {
    let store = Store::open(dir, Default::default())?;
    let book = store.load_contacts()?;
    let (pid, _) = book.resolve(id).map_err(|e| {
        anyhow::anyhow!(
            "error: unable to resolve peer {id}\nsuggestion:\n  run `dd peer list` then `dd peer inspect <id>`\n{e}"
        )
    })?;
    let c = book.get(&pid).unwrap();
    let enc = store.encounter(pid).ok().flatten();
    let locator = deaddrop_net::remembered_locator(&store, pid).ok().flatten();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "id": pid.to_string(),
                "trust": format!("{:?}", c.trust),
                "name": c.card.name,
                "locator": locator,
                "encounters": enc.as_ref().map(|e| e.encounter_count),
            })
        );
        return Ok(());
    }
    println!("{}", c.card.to_text());
    println!("Trust: {:?}", c.trust);
    if let Some(loc) = locator {
        println!("Last locator: {loc}");
    }
    if let Some(e) = enc {
        println!(
            "Encounters: {} last_seen {}",
            e.encounter_count, e.last_seen
        );
    }
    Ok(())
}

async fn daemon_cmd(dir: &Path, cmd: DaemonCmd, json: bool, quiet: bool) -> Result<()> {
    match cmd {
        DaemonCmd::Start {
            listen,
            peers,
            foreground,
        } => daemon_start(dir, listen, peers, quiet, foreground).await?,
        DaemonCmd::Stop => daemon_stop(dir, quiet).await?,
        DaemonCmd::Restart {
            listen,
            peers,
            foreground,
        } => {
            let _ = daemon_stop(dir, true).await;
            daemon_start(dir, listen, peers, quiet, foreground).await?;
        }
        DaemonCmd::Status => {
            if let Ok(v) = deaddrop_net::control::query(dir, "/v1/status").await {
                println!("{v}");
            } else if json {
                println!("{}", serde_json::json!({"running": false}));
            } else {
                println!("daemon not running — start it with `dd daemon start`");
            }
        }
        DaemonCmd::Logs => {
            let log = dir.join("daemon.log");
            if log.exists() {
                print!("{}", std::fs::read_to_string(log)?);
            } else {
                println!("no daemon.log; logs go to stderr of `dd daemon start --foreground`");
            }
        }
        DaemonCmd::Install { listen } => {
            let msg = deaddrop_app::daemon_service::install(dir, listen)?;
            println!("{msg}");
        }
        DaemonCmd::Uninstall => {
            let msg = deaddrop_app::daemon_service::uninstall()?;
            println!("{msg}");
        }
    }
    Ok(())
}

async fn daemon_start(
    dir: &Path,
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    quiet: bool,
    foreground: bool,
) -> Result<()> {
    if !foreground {
        if deaddrop_net::control::query(dir, "/v1/status")
            .await
            .is_ok()
        {
            if !quiet {
                println!("daemon already running");
            }
            return Ok(());
        }
        let pid = deaddrop_app::daemon_service::spawn_background(dir, listen, &peers)?;
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        if json_running(dir).await {
            if !quiet {
                println!("daemon started pid={pid} listen={listen} (background)");
                println!("  logs:  dd daemon logs");
                println!("  stop:  dd daemon stop");
                println!("  boot:  dd daemon install");
            }
            return Ok(());
        }
        anyhow::bail!(
            "daemon pid {pid} did not come up. Try `dd daemon start --foreground` or read {}",
            dir.join("daemon.log").display()
        );
    }
    ignore_hangup();
    let node = Node::open(dir, Config::load(&dir.join("deaddrop.toml"))?)?;
    if !quiet {
        println!(
            "dd-daemon {} {PROTOCOL_LABEL} listen={listen} (TCP on your LAN)",
            node.identity.peer_id.short()
        );
        println!(
            "Other computers: dd connect   or   dd connect --peer <this-ip>:{}",
            listen.port()
        );
    }
    node.serve(listen, peers).await?;
    Ok(())
}

async fn json_running(dir: &Path) -> bool {
    deaddrop_net::control::query(dir, "/v1/status")
        .await
        .is_ok()
}

fn ignore_hangup() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
}

async fn daemon_stop(dir: &Path, quiet: bool) -> Result<()> {
    if let Ok(Some(info)) = deaddrop_net::control::read_info(dir) {
        let _ = deaddrop_net::control::query(dir, "/v1/shutdown").await;
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &info.pid.to_string()])
                .status();
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &info.pid.to_string(), "/F"])
                .status();
        }
        deaddrop_net::control::clear(dir);
        if !quiet {
            println!("stopped pid {}", info.pid);
        }
        Ok(())
    } else {
        anyhow::bail!("daemon not running")
    }
}

fn looks_like_bundle(path: &Path) -> bool {
    if path.is_dir() {
        return path.join("carrier.json").exists() || path.join("objects").is_dir();
    }
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ddrop") || e.eq_ignore_ascii_case("ddcarrier"))
    {
        return true;
    }
    if let Ok(mut f) = std::fs::File::open(path) {
        let mut mag = [0u8; 7];
        if std::io::Read::read(&mut f, &mut mag).ok() == Some(7) {
            return &mag == b"DDROP1\n";
        }
    }
    false
}

fn import_path(dir: &Path, src: &Path, name: Option<String>) -> Result<()> {
    let store = Store::open(dir, Default::default())?;
    if looks_like_bundle(src) {
        let n = deaddrop_core::carrier::import_carrier(&store, src)?;
        println!("imported {n} objects from bundle {}", src.display());
        println!("Decrypt what is addressed to this node with `dd receive`.");
        return Ok(());
    }
    let bytes = std::fs::read(src)?;
    let mut card = ContactCard::from_bytes(&bytes)?;
    if name.is_some() {
        card.name = name;
    }
    let id = store.put_contact(card, deaddrop_core::TrustState::Known)?;
    println!("imported peer {id}");
    println!("Send a file: dd send ./file --to {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn connect_without_address_parses() {
        let c = Cli::try_parse_from(["dd", "connect"]).expect("parse");
        match c.command {
            Commands::Sync { addr, peer, to } => {
                assert!(addr.is_none());
                assert!(peer.is_none());
                assert!(to.is_none());
            }
            _ => panic!("expected sync"),
        }
    }

    #[test]
    fn sync_peer_flag_still_works() {
        let c = Cli::try_parse_from(["dd", "sync", "--peer", "192.168.1.20:7947"]).expect("parse");
        match c.command {
            Commands::Sync { peer, .. } => {
                assert_eq!(peer.unwrap().to_string(), "192.168.1.20:7947");
            }
            _ => panic!("expected sync"),
        }
    }

    #[test]
    fn connect_to_name_parses() {
        let c = Cli::try_parse_from(["dd", "connect", "--to", "home"]).expect("parse");
        match c.command {
            Commands::Sync { to, .. } => assert_eq!(to.as_deref(), Some("home")),
            _ => panic!("expected sync"),
        }
    }

    #[test]
    fn research_commands_hidden_from_help() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("daemon"));
        assert!(help.contains("connect") || help.contains("sync"));
        assert!(!help.contains("  board"));
        assert!(!help.contains("  package"));
        assert!(!help.contains("  web"));
    }
}
