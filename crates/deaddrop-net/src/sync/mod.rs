use crate::routing::strategy_from_kind;
use deaddrop_core::crypto::PrivateIdentity;
use deaddrop_core::event::{Bus, Event, Metrics};
use deaddrop_core::identity::ContactCard;
use deaddrop_core::protocol::{
    BloomFilter, ChunkWant, Message, handshake_initiator, handshake_responder, read_msg,
    verify_envelope, write_msg,
};
use deaddrop_core::store::{Store, unix_now};
use deaddrop_core::{DdError, NodeMode, ObjectId, Ownership, PeerId, Result, RoutingPolicyKind};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::Ordering;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub peer: Option<PeerId>,
    pub envelopes: u32,
    pub chunks: u32,
}

pub struct SyncOpts<'a> {
    pub store: &'a Store,
    pub identity: &'a PrivateIdentity,
    pub mode: NodeMode,
    pub default_strategy: RoutingPolicyKind,
    pub metrics: Option<&'a Metrics>,
    pub bus: Option<&'a Bus>,
    pub initiator: bool,
}

pub async fn sync_session<S>(opts: SyncOpts<'_>, mut stream: S) -> Result<SyncStats>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let session = if opts.initiator {
        handshake_initiator(opts.identity, &mut stream).await?
    } else {
        handshake_responder(opts.identity, &mut stream).await?
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    if let Some(b) = opts.bus {
        b.emit(Event::PeerAuthenticated {
            peer: session.peer.to_string(),
        });
    }
    let _ = opts.store.put_contact(
        ContactCard::from_public(None, session.peer_identity.clone())?,
        deaddrop_core::TrustState::Observed,
    );
    let now = unix_now();
    let local_ids = opts.store.inventory(now)?;
    if session.caps.prefer_inventory() == "bloom-v1" && local_ids.len() > 64 {
        let bloom = BloomFilter::from_ids(&local_ids, 10);
        write_msg(
            &mut writer,
            &Message::InventoryBloom {
                n: bloom.n,
                k: bloom.k,
                bits: bloom.bits,
            },
        )
        .await?;
    } else {
        write_msg(
            &mut writer,
            &Message::InventorySorted {
                object_ids: local_ids.clone(),
            },
        )
        .await?;
    }
    let inv = read_msg(&mut reader).await?;
    let mut want_ids: Vec<ObjectId> = match inv {
        Message::InventorySorted { object_ids } => object_ids
            .into_iter()
            .filter(|id| !local_ids.contains(id))
            .collect(),
        Message::InventoryBloom { n: _, k, bits } => {
            let bloom = BloomFilter { n: 0, k, bits };
            local_ids
                .iter()
                .copied()
                .filter(|id| !bloom.may_contain(id))
                .collect()
        }
        other => {
            return Err(DdError::invalid_frame(format!(
                "expected inventory, got {}",
                other.name()
            )));
        }
    };
    let mut chunk_wants = Vec::new();
    for id in &local_ids {
        if let Ok(mask) = opts.store.present_mask(id) {
            let missing: Vec<u32> = mask
                .iter()
                .enumerate()
                .filter(|(_, p)| !**p)
                .map(|(i, _)| i as u32)
                .collect();
            if !missing.is_empty() {
                chunk_wants.push(ChunkWant {
                    object_id: *id,
                    indices: missing,
                });
            }
        }
    }
    write_msg(
        &mut writer,
        &Message::Want {
            object_ids: want_ids.clone(),
            chunks: chunk_wants.clone(),
        },
    )
    .await?;
    let their_want = match read_msg(&mut reader).await? {
        Message::Want { object_ids, chunks } => (object_ids, chunks),
        other => {
            return Err(DdError::invalid_frame(format!(
                "expected want, got {}",
                other.name()
            )));
        }
    };

    let mut to_send_env: VecDeque<ObjectId> = VecDeque::new();
    let mut to_send_chunks: VecDeque<(ObjectId, u32)> = VecDeque::new();
    let strat = strategy_from_kind(opts.default_strategy);
    for id in &their_want.0 {
        if let Ok(Some(env)) = opts.store.get_envelope(id) {
            let copies = opts.store.replication(id).unwrap_or(1);
            let d = strat.decide(
                &env,
                session.peer,
                opts.identity.peer_id,
                now,
                opts.store,
                opts.mode,
                session.caps.peer_relay,
                copies,
            )?;
            if let Some(m) = opts.metrics {
                m.route_decisions.fetch_add(1, Ordering::Relaxed);
            }
            if d.forward {
                to_send_env.push_back(*id);
                if let Ok(mask) = opts.store.present_mask(id) {
                    for (i, present) in mask.iter().enumerate() {
                        if *present {
                            to_send_chunks.push_back((*id, i as u32));
                        }
                    }
                }
            }
        }
    }
    for w in their_want.1 {
        for idx in w.indices {
            to_send_chunks.push_back((w.object_id, idx));
        }
    }

    let mut needed: HashSet<ObjectId> = want_ids.drain(..).collect();
    let mut we_done = false;
    let mut they_done = false;
    let mut stats = SyncStats {
        peer: Some(session.peer),
        ..Default::default()
    };

    loop {
        if to_send_env.is_empty() && to_send_chunks.is_empty() && !we_done {
            write_msg(&mut writer, &Message::Done).await?;
            we_done = true;
        }
        if we_done && they_done {
            break;
        }
        tokio::select! {
            r = send_one(opts.store, &mut writer, &mut to_send_env, &mut to_send_chunks, &mut stats, now), if !to_send_env.is_empty() || !to_send_chunks.is_empty() => {
                r?;
            }
            incoming = read_msg(&mut reader) => {
                match incoming? {
                    Message::Envelope { envelope, manifest } => {
                        if verify_envelope(&envelope, now).is_ok() {
                            let oid = envelope.object_id;
                            let own = if envelope.destination.includes(&opts.identity.peer_id) {
                                Ownership::Incoming
                            } else {
                                Ownership::Relay
                            };
                            let _ = opts.store.put_object(&envelope, &manifest, &[], own, now);
                            needed.remove(&oid);
                            stats.envelopes += 1;
                        }
                    }
                    Message::ChunkData { object_id, index, data, .. } => {
                        if opts.store.put_chunk(object_id, index, &data).is_ok() {
                            stats.chunks += 1;
                            if let Some(m) = opts.metrics {
                                m.chunks_transferred.fetch_add(1, Ordering::Relaxed);
                                m.bytes_transferred.fetch_add(data.len() as u64, Ordering::Relaxed);
                            }
                        }
                    }
                    Message::Done => they_done = true,
                    Message::Error { code, message } => {
                        return Err(DdError::invalid_frame(format!("{code}: {message}")));
                    }
                    _ => {}
                }
            }
        }
    }
    let ok = true;
    let _ = opts.store.record_encounter(session.peer, now, 0, 0, ok);
    let _ = strat;
    Ok(stats)
}

async fn send_one<S: AsyncWrite + Unpin>(
    store: &Store,
    stream: &mut S,
    envs: &mut VecDeque<ObjectId>,
    chunks: &mut VecDeque<(ObjectId, u32)>,
    stats: &mut SyncStats,
    now: u64,
) -> Result<()> {
    if let Some(id) = envs.pop_front() {
        if let (Ok(Some(env)), Ok(Some(man))) = (store.get_envelope(&id), store.get_manifest(&id)) {
            if verify_envelope(&env, now).is_ok() {
                write_msg(
                    stream,
                    &Message::Envelope {
                        envelope: env,
                        manifest: man,
                    },
                )
                .await?;
                stats.envelopes += 1;
            }
        }
        return Ok(());
    }
    if let Some((id, idx)) = chunks.pop_front() {
        if let Ok(data) = store.load_chunk(&id, idx) {
            if let Ok(refer) = {
                // chunk id from store via load
                use deaddrop_core::HashAlgorithm;
                use deaddrop_core::crypto::{CryptoProvider, DefaultProvider};
                let d = DefaultProvider.hash(HashAlgorithm::Blake3, &data);
                Ok::<_, DdError>(deaddrop_core::ChunkId::blake3(d.0))
            } {
                write_msg(
                    stream,
                    &Message::ChunkData {
                        object_id: id,
                        chunk_id: refer,
                        index: idx,
                        data,
                    },
                )
                .await?;
                stats.chunks += 1;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use deaddrop_core::identity::ContactCard;
    use deaddrop_core::protocol::{CreateDrop, build_drop, open_drop};
    use deaddrop_core::store::Store;
    use deaddrop_core::{Destination, Ownership, Priority, RoutingPolicy};

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ddp2-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn multi_hop_encrypted_carry() {
        let alice_id = PrivateIdentity::generate();
        let bob_id = PrivateIdentity::generate();
        let charlie_id = PrivateIdentity::generate();
        let sa = Store::open(tmp("a"), Default::default()).unwrap();
        let sb = Store::open(tmp("b"), Default::default()).unwrap();
        let sc = Store::open(tmp("c"), Default::default()).unwrap();
        sa.put_contact(
            ContactCard::from_public(None, charlie_id.public.clone()).unwrap(),
            deaddrop_core::TrustState::Known,
        )
        .unwrap();
        let built = build_drop(CreateDrop {
            author: &alice_id,
            recipients: vec![(charlie_id.peer_id, charlie_id.public.clone())],
            destination: Destination::One {
                peer: charlie_id.peer_id,
            },
            plaintext: b"phase-two-secret".to_vec(),
            now: unix_now(),
            ttl_secs: Some(3600),
            priority: Priority::Normal,
            routing: RoutingPolicy {
                kind: deaddrop_core::RoutingPolicyKind::Epidemic,
                replication_budget: 8,
                trusted_only: false,
            },
            application: "dd.file".into(),
            topic: None,
            chunking: deaddrop_core::chunk::default_fixed(),
            compress: false,
            hop_limit: 8,
            public: false,
            seal_until: None,
            seal_quorum: None,
            erasure: None,
        })
        .unwrap();
        let chunks: Vec<_> = built
            .chunks
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, d)| (i as u32, d))
            .collect();
        sa.put_object(
            &built.envelope,
            &built.manifest,
            &chunks,
            Ownership::Local,
            unix_now(),
        )
        .unwrap();

        let (ab, ba) = tokio::io::duplex(1 << 20);
        let oa = SyncOpts {
            store: &sa,
            identity: &alice_id,
            mode: NodeMode::Balanced,
            default_strategy: deaddrop_core::RoutingPolicyKind::Epidemic,
            metrics: None,
            bus: None,
            initiator: true,
        };
        let ob = SyncOpts {
            store: &sb,
            identity: &bob_id,
            mode: NodeMode::Balanced,
            default_strategy: deaddrop_core::RoutingPolicyKind::Epidemic,
            metrics: None,
            bus: None,
            initiator: false,
        };
        let (r1, r2) = tokio::join!(sync_session(oa, ab), sync_session(ob, ba));
        r1.unwrap();
        r2.unwrap();
        assert!(
            sb.get_envelope(&built.envelope.object_id)
                .unwrap()
                .is_some()
        );
        let man = sb.get_manifest(&built.envelope.object_id).unwrap().unwrap();
        let bchunks = sb.load_chunks(&built.envelope.object_id).unwrap();
        assert!(open_drop(&bob_id, &built.envelope, &man, &bchunks).is_err());

        let (bc, cb) = tokio::io::duplex(1 << 20);
        let ob2 = SyncOpts {
            store: &sb,
            identity: &bob_id,
            mode: NodeMode::Balanced,
            default_strategy: deaddrop_core::RoutingPolicyKind::Epidemic,
            metrics: None,
            bus: None,
            initiator: true,
        };
        let oc = SyncOpts {
            store: &sc,
            identity: &charlie_id,
            mode: NodeMode::Balanced,
            default_strategy: deaddrop_core::RoutingPolicyKind::Epidemic,
            metrics: None,
            bus: None,
            initiator: false,
        };
        let (r1, r2) = tokio::join!(sync_session(ob2, bc), sync_session(oc, cb));
        r1.unwrap();
        r2.unwrap();
        let man = sc.get_manifest(&built.envelope.object_id).unwrap().unwrap();
        let cchunks = sc.load_chunks(&built.envelope.object_id).unwrap();
        let pt = open_drop(
            &charlie_id,
            &sc.get_envelope(&built.envelope.object_id).unwrap().unwrap(),
            &man,
            &cchunks,
        )
        .unwrap();
        assert_eq!(pt, b"phase-two-secret");
    }

    /// Two machines on a LAN: TCP listen + one-shot sync, like home PC ↔ laptop.
    #[tokio::test]
    async fn two_computers_over_tcp() {
        use crate::node::Node;
        use deaddrop_core::config::Config;
        use tokio::net::TcpListener;

        let home = tmp("home-pc");
        let laptop = tmp("laptop");
        let sh = Store::open(&home, Default::default()).unwrap();
        let sl = Store::open(&laptop, Default::default()).unwrap();
        let home_id = sh.init_identity(true).unwrap();
        let laptop_id = sl.init_identity(true).unwrap();
        sh.put_contact(
            ContactCard::from_public(Some("laptop".into()), laptop_id.public.clone()).unwrap(),
            deaddrop_core::TrustState::Known,
        )
        .unwrap();
        sl.put_contact(
            ContactCard::from_public(Some("home".into()), home_id.public.clone()).unwrap(),
            deaddrop_core::TrustState::Known,
        )
        .unwrap();

        let home_node = Node::open(&home, Config::default()).unwrap();
        let laptop_node = Node::open(&laptop, Config::default()).unwrap();
        home_node
            .send_payload(
                "laptop",
                b"family-photo".to_vec(),
                false,
                None,
                Priority::Normal,
                "dd.file",
                None,
                false,
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store = laptop_node.store.clone();
        let secrets = (
            laptop_node.identity.ed25519_bytes(),
            laptop_node.identity.x25519_bytes(),
        );
        tokio::spawn(async move {
            let identity = PrivateIdentity::from_secrets(secrets.0, secrets.1);
            let (s, _) = listener.accept().await.unwrap();
            let opts = SyncOpts {
                store: store.as_ref(),
                identity: &identity,
                mode: NodeMode::Balanced,
                default_strategy: deaddrop_core::RoutingPolicyKind::Epidemic,
                metrics: None,
                bus: None,
                initiator: false,
            };
            let _ = sync_session(opts, s).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        home_node.sync_once(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let inbox = laptop_node.inbox().unwrap();
        assert!(
            inbox.iter().any(|i| i.body == b"family-photo"),
            "laptop should decrypt the Drop sent from the home PC"
        );
    }
}
