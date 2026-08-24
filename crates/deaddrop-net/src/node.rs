use crate::control::{self, ControlServer};
use crate::discovery::DiscoveryProvider;
use crate::discovery::lan::LanDiscovery;
use crate::routing::{format_explain, predict_delivery, strategy_from_kind};
use crate::sync::{SyncOpts, SyncStats, sync_session};
use deaddrop_core::chunk::{ErasureSpec, default_fixed};
use deaddrop_core::config::Config;
use deaddrop_core::crypto::PrivateIdentity;
use deaddrop_core::event::{Bus, Event, Metrics};
use deaddrop_core::protocol::{CreateDrop, build_drop, open_drop_at, verify_envelope};
use deaddrop_core::receipt::Receipt;
use deaddrop_core::store::{StorageQuotas, Store, unix_now};
use deaddrop_core::{
    Destination, NodeMode, Ownership, PROTOCOL_LABEL, PeerId, Priority, PublicIdentity, Result,
    RoutingPolicy, ephemeral_discovery_id,
};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct Node {
    pub store: Arc<Store>,
    pub identity: PrivateIdentity,
    pub cfg: Config,
    pub metrics: Metrics,
    pub bus: Bus,
}

impl Node {
    pub fn open(dir: &Path, cfg: Config) -> Result<Self> {
        let quotas = StorageQuotas {
            maximum: Config::parse_bytes(&cfg.storage.maximum),
            reserved_local: Config::parse_bytes(&cfg.storage.reserved_local),
            relay_budget: Config::parse_bytes(&cfg.storage.relay_budget),
            temporary: Config::parse_bytes(&cfg.storage.temporary),
        };
        let store = Store::open(dir, quotas)?;
        let identity = store.load_identity()?;
        Ok(Self {
            store: Arc::new(store),
            identity,
            cfg,
            metrics: Metrics::default(),
            bus: Bus::default(),
        })
    }

    pub fn send_file(
        &self,
        path: &Path,
        to: &str,
        public: bool,
        ttl: Option<u64>,
        priority: Priority,
    ) -> Result<deaddrop_core::ObjectId> {
        let body = std::fs::read(path)?;
        let book = self.store.load_contacts()?;
        let dest = if public {
            Destination::Public
        } else {
            let (peer, _) = book.resolve(to)?;
            Destination::One { peer }
        };
        let mut recipients = Vec::new();
        if !public {
            let (peer, ident) = book.resolve(to)?;
            recipients.push((peer, ident));
        }
        let built = build_drop(CreateDrop {
            author: &self.identity,
            recipients,
            destination: dest,
            plaintext: body,
            now: unix_now(),
            ttl_secs: ttl,
            priority,
            routing: RoutingPolicy {
                kind: self.cfg.strategy(),
                replication_budget: self.cfg.routing.replication_budget,
                trusted_only: false,
            },
            application: "dd.file".into(),
            topic: None,
            chunking: default_fixed(),
            compress: false,
            hop_limit: 16,
            public,
            seal_until: None,
            seal_quorum: None,
            erasure: None,
        })?;
        let chunks: Vec<_> = built
            .chunks
            .into_iter()
            .enumerate()
            .map(|(i, d)| (i as u32, d))
            .collect();
        let oid = self.store.put_object(
            &built.envelope,
            &built.manifest,
            &chunks,
            Ownership::Local,
            unix_now(),
        )?;
        self.store.trace(oid, unix_now(), "created locally")?;
        self.metrics
            .drops_created
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.bus.emit(Event::drop_created(oid));
        Ok(oid)
    }

    pub fn send_opts(&self, opts: SendOpts) -> Result<deaddrop_core::ObjectId> {
        let book = self.store.load_contacts()?;
        let dest = if opts.public {
            Destination::Public
        } else {
            let (peer, _) = book.resolve(&opts.to)?;
            Destination::One { peer }
        };
        let mut recipients = Vec::new();
        if !opts.public {
            let (peer, ident) = book.resolve(&opts.to)?;
            recipients.push((peer, ident));
        }
        let chunking = deaddrop_core::chunk::ChunkingAlg::Fixed {
            size: deaddrop_core::chunk::adaptive_chunk_size(opts.plaintext.len() as u64, 30, "tcp"),
        };
        let built = build_drop(CreateDrop {
            author: &self.identity,
            recipients,
            destination: dest,
            plaintext: opts.plaintext,
            now: unix_now(),
            ttl_secs: opts.ttl,
            priority: opts.priority,
            routing: RoutingPolicy {
                kind: self.cfg.strategy(),
                replication_budget: self.cfg.routing.replication_budget,
                trusted_only: opts.trusted_only,
            },
            application: opts.application,
            topic: opts.topic,
            chunking,
            compress: false,
            hop_limit: 16,
            public: opts.public,
            seal_until: opts.seal_until,
            seal_quorum: opts.seal_quorum,
            erasure: opts.erasure,
        })?;
        let chunks: Vec<_> = built
            .chunks
            .into_iter()
            .enumerate()
            .map(|(i, d)| (i as u32, d))
            .collect();
        let oid = self.store.put_object(
            &built.envelope,
            &built.manifest,
            &chunks,
            Ownership::Local,
            unix_now(),
        )?;
        self.store.trace(oid, unix_now(), "created locally")?;
        self.bus.emit(Event::drop_created(oid));
        Ok(oid)
    }

    pub fn send_payload(
        &self,
        to: &str,
        plaintext: Vec<u8>,
        public: bool,
        ttl: Option<u64>,
        priority: Priority,
        application: &str,
        topic: Option<String>,
        trusted_only: bool,
    ) -> Result<deaddrop_core::ObjectId> {
        self.send_opts(SendOpts {
            to: to.to_string(),
            plaintext,
            public,
            ttl,
            priority,
            application: application.into(),
            topic,
            trusted_only,
            seal_until: None,
            seal_quorum: None,
            erasure: None,
        })
    }

    pub fn inbox(&self) -> Result<Vec<InboxItem>> {
        let now = unix_now();
        let mut items = Vec::new();
        for id in self.store.inventory(now)? {
            let Some(env) = self.store.get_envelope(&id)? else {
                continue;
            };
            if !env.destination.includes(&self.identity.peer_id) && !env.destination.is_public() {
                continue;
            }
            if !self.store.complete(&id)? {
                continue;
            }
            let Some(man) = self.store.get_manifest(&id)? else {
                continue;
            };
            let chunks = self.store.load_chunks(&id)?;
            let receipts = self.store.receipt_issuer_count(&id).unwrap_or(0);
            match open_drop_at(&self.identity, &env, &man, &chunks, now, receipts) {
                Ok(pt) => items.push(InboxItem {
                    object_id: id,
                    from: env.source,
                    bytes: pt.len() as u64,
                    application: env.application,
                    body: pt,
                }),
                Err(_) => continue,
            }
        }
        Ok(items)
    }

    pub fn explain_route(&self, object: &str, peer: &str) -> Result<String> {
        let book = self.store.load_contacts()?;
        let (oid, _) = resolve_object(&self.store, object)?;
        let env = self
            .store
            .get_envelope(&oid)?
            .ok_or_else(|| deaddrop_core::DdError::invalid_frame("unknown object"))?;
        let (pid, _) = book.resolve(peer).or_else(|_| {
            peer.parse::<PeerId>().map(|p| {
                (
                    p,
                    PublicIdentity {
                        version: 2,
                        ed25519_pk: [0; 32],
                        x25519_pk: [0; 32],
                        signature: [0; 64],
                    },
                )
            })
        })?;
        let copies = self.store.replication(&oid)?;
        let d = strategy_from_kind(self.cfg.strategy()).decide(
            &env,
            pid,
            self.identity.peer_id,
            unix_now(),
            &self.store,
            self.cfg.node.mode,
            deaddrop_core::RelayCapacity::Full,
            copies,
        )?;
        Ok(format_explain(pid, &d))
    }

    pub fn ack_delivery(&self, object: &str) -> Result<Receipt> {
        let (oid, _) = resolve_object(&self.store, object)?;
        let r = Receipt::issue(
            deaddrop_core::ReceiptKind::Delivered,
            oid,
            &self.identity,
            unix_now(),
        );
        self.store
            .set_state(&oid, deaddrop_core::DropState::Delivered)?;
        Ok(r)
    }

    /// One-shot TCP session with a peer, then disconnect. Used by `dd sync` / `dd connect`.
    pub async fn sync_once(&self, addr: SocketAddr) -> Result<SyncStats> {
        let s = tokio::net::TcpStream::connect(addr).await?;
        let opts = SyncOpts {
            store: self.store.as_ref(),
            identity: &self.identity,
            mode: self.cfg.node.mode,
            default_strategy: self.cfg.strategy(),
            metrics: Some(&self.metrics),
            bus: Some(&self.bus),
            initiator: true,
        };
        let stats = sync_session(opts, s).await?;
        let _ =
            crate::discovery::remember_locator(self.store.as_ref(), stats.peer, &addr.to_string());
        Ok(stats)
    }

    pub async fn serve(&self, listen: SocketAddr, static_peers: Vec<SocketAddr>) -> Result<()> {
        let listener = TcpListener::bind(listen).await?;
        tracing::info!(
            "DDP {} listen {listen} id {}",
            PROTOCOL_LABEL,
            self.identity.peer_id
        );
        let control = ControlServer::bind(self.store.root(), listen).await?;
        let stop = control.stop.clone();
        if self.cfg.discovery.lan && self.cfg.discovery.mode.advertise_lan() {
            let lan = LanDiscovery {
                port: self.cfg.discovery.lan_port,
            };
            let beacon_id = if self.cfg.discovery.ephemeral_ids {
                ephemeral_discovery_id(self.identity.peer_id, unix_now())
            } else {
                self.identity.peer_id
            };
            let stream_port = listen.port();
            tokio::spawn(async move {
                let _ = lan.advertise(beacon_id, stream_port).await;
            });
        }
        let store = self.store.clone();
        let identity = PrivateIdentity::from_secrets(
            self.identity.ed25519_bytes(),
            self.identity.x25519_bytes(),
        );
        let identity = Arc::new(identity);
        let mode = self.cfg.node.mode;
        let strat = self.cfg.strategy();
        let store_a = store.clone();
        let id_a = identity.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((s, addr)) = listener.accept().await {
                    tracing::info!("inbound {addr}");
                    let store = store_a.clone();
                    let identity = id_a.clone();
                    tokio::spawn(async move {
                        let opts = SyncOpts {
                            store: store.as_ref(),
                            identity: identity.as_ref(),
                            mode,
                            default_strategy: strat,
                            metrics: None,
                            bus: None,
                            initiator: false,
                        };
                        let _ = sync_session(opts, s).await;
                    });
                }
            }
        });
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(4));
        loop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                control::clear(self.store.root());
                break;
            }
            tick.tick().await;
            let _ = self.store.gc(unix_now());
            for peer in &static_peers {
                let store = store.clone();
                let identity = identity.clone();
                let addr = *peer;
                tokio::spawn(async move {
                    if let Ok(s) = tokio::net::TcpStream::connect(addr).await {
                        let opts = SyncOpts {
                            store: store.as_ref(),
                            identity: identity.as_ref(),
                            mode,
                            default_strategy: strat,
                            metrics: None,
                            bus: None,
                            initiator: true,
                        };
                        let _ = sync_session(opts, s).await;
                    }
                });
            }
        }
        Ok(())
    }

    pub fn predict_route(&self, dest: &str) -> Result<crate::routing::DeliveryForecast> {
        let book = self.store.load_contacts()?;
        let (pid, _) = book.resolve(dest).or_else(|_| {
            dest.parse::<PeerId>().map(|p| {
                (
                    p,
                    PublicIdentity {
                        version: 2,
                        ed25519_pk: [0; 32],
                        x25519_pk: [0; 32],
                        signature: [0; 64],
                    },
                )
            })
        })?;
        predict_delivery(&self.store, pid, unix_now())
    }

    pub fn events(&self) -> Vec<Event> {
        self.bus.take()
    }

    pub fn set_mode(&mut self, mode: NodeMode) {
        self.cfg.node.mode = mode;
    }
}

#[derive(Debug, Clone)]
pub struct SendOpts {
    pub to: String,
    pub plaintext: Vec<u8>,
    pub public: bool,
    pub ttl: Option<u64>,
    pub priority: Priority,
    pub application: String,
    pub topic: Option<String>,
    pub trusted_only: bool,
    pub seal_until: Option<u64>,
    pub seal_quorum: Option<u32>,
    pub erasure: Option<ErasureSpec>,
}

#[derive(Debug, Clone)]
pub struct InboxItem {
    pub object_id: deaddrop_core::ObjectId,
    pub from: PeerId,
    pub bytes: u64,
    pub application: String,
    pub body: Vec<u8>,
}

fn resolve_object(
    store: &Store,
    spec: &str,
) -> Result<(deaddrop_core::ObjectId, deaddrop_core::DropEnvelope)> {
    if let Ok(id) = spec.parse() {
        if let Some(env) = store.get_envelope(&id)? {
            return Ok((id, env));
        }
    }
    let prefix = spec.rsplit(':').next().unwrap_or(spec).to_ascii_lowercase();
    for id in store.inventory(unix_now())? {
        if deaddrop_core::hex_encode(id.as_bytes()).starts_with(&prefix) {
            if let Some(env) = store.get_envelope(&id)? {
                return Ok((id, env));
            }
        }
    }
    Err(deaddrop_core::DdError::invalid_frame("object not found"))
}

pub fn verify_open(store: &Store, env: &deaddrop_core::DropEnvelope, now: u64) -> Result<()> {
    verify_envelope(env, now)?;
    let _ = store;
    Ok(())
}
