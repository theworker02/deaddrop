use deaddrop_core::store::{EncounterRow, Store};
use deaddrop_core::{
    Destination, DropEnvelope, NodeMode, PeerId, RelayCapacity, Result, RoutingPolicyKind,
};

#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub forward: bool,
    pub score: f64,
    pub reasons: Vec<(String, f64)>,
}

#[derive(Debug, Clone)]
pub struct ScoreWeights {
    pub destination_probability: f64,
    pub encounter_recency: f64,
    pub encounter_frequency: f64,
    pub delivery_history: f64,
    pub peer_capacity: f64,
    pub object_priority: f64,
    pub remaining_lifetime: f64,
    pub replication_need: f64,
    pub battery_cost: f64,
    pub storage_pressure: f64,
    pub transport_reliability: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            destination_probability: 1.0,
            encounter_recency: 1.0,
            encounter_frequency: 1.0,
            delivery_history: 1.0,
            peer_capacity: 1.0,
            object_priority: 1.0,
            remaining_lifetime: 1.0,
            replication_need: 1.0,
            battery_cost: 0.4,
            storage_pressure: 0.4,
            transport_reliability: 0.5,
        }
    }
}

pub trait RoutingStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn decide(
        &self,
        env: &DropEnvelope,
        peer: PeerId,
        local: PeerId,
        now: u64,
        store: &Store,
        mode: NodeMode,
        peer_relay: RelayCapacity,
        remaining_copies: u32,
    ) -> Result<RouteDecision>;
}

pub struct Direct;
pub struct Epidemic;
pub struct SprayAndWait;
pub struct EncounterBased {
    pub weights: ScoreWeights,
}
pub struct Utility {
    pub weights: ScoreWeights,
}

impl RoutingStrategy for Direct {
    fn name(&self) -> &'static str {
        "direct"
    }
    fn decide(
        &self,
        env: &DropEnvelope,
        peer: PeerId,
        _local: PeerId,
        _now: u64,
        _store: &Store,
        mode: NodeMode,
        peer_relay: RelayCapacity,
        _remaining_copies: u32,
    ) -> Result<RouteDecision> {
        if !mode.unsolicited_relay() && !env.destination.includes(&peer) {
            return Ok(deny("private/offline mode"));
        }
        if peer_relay == RelayCapacity::None && !env.destination.includes(&peer) {
            return Ok(deny("peer relay none"));
        }
        let hit = env.destination.includes(&peer);
        Ok(RouteDecision {
            forward: hit,
            score: if hit { 1.0 } else { 0.0 },
            reasons: vec![(
                "direct destination match".into(),
                if hit { 1.0 } else { 0.0 },
            )],
        })
    }
}

impl RoutingStrategy for Epidemic {
    fn name(&self) -> &'static str {
        "epidemic"
    }
    fn decide(
        &self,
        env: &DropEnvelope,
        peer: PeerId,
        local: PeerId,
        now: u64,
        _store: &Store,
        mode: NodeMode,
        peer_relay: RelayCapacity,
        _remaining_copies: u32,
    ) -> Result<RouteDecision> {
        if blocked(env, peer, local, now, mode, peer_relay) {
            return Ok(deny("ineligible"));
        }
        Ok(RouteDecision {
            forward: true,
            score: 1.0,
            reasons: vec![("epidemic".into(), 1.0)],
        })
    }
}

impl RoutingStrategy for SprayAndWait {
    fn name(&self) -> &'static str {
        "spray"
    }
    fn decide(
        &self,
        env: &DropEnvelope,
        peer: PeerId,
        local: PeerId,
        now: u64,
        _store: &Store,
        mode: NodeMode,
        peer_relay: RelayCapacity,
        remaining_copies: u32,
    ) -> Result<RouteDecision> {
        if blocked(env, peer, local, now, mode, peer_relay) {
            return Ok(deny("ineligible"));
        }
        if env.destination.includes(&peer) {
            return Ok(RouteDecision {
                forward: true,
                score: 1.0,
                reasons: vec![("destination".into(), 1.0)],
            });
        }
        if remaining_copies > 1 {
            Ok(RouteDecision {
                forward: true,
                score: 0.5,
                reasons: vec![("spray budget".into(), remaining_copies as f64)],
            })
        } else {
            Ok(deny("wait: budget 1, peer is not destination"))
        }
    }
}

impl RoutingStrategy for EncounterBased {
    fn name(&self) -> &'static str {
        "encounter"
    }
    fn decide(
        &self,
        env: &DropEnvelope,
        peer: PeerId,
        local: PeerId,
        now: u64,
        store: &Store,
        mode: NodeMode,
        peer_relay: RelayCapacity,
        remaining_copies: u32,
    ) -> Result<RouteDecision> {
        utility_decide(
            &self.weights,
            env,
            peer,
            local,
            now,
            store,
            mode,
            peer_relay,
            remaining_copies,
        )
    }
}

impl RoutingStrategy for Utility {
    fn name(&self) -> &'static str {
        "utility"
    }
    fn decide(
        &self,
        env: &DropEnvelope,
        peer: PeerId,
        local: PeerId,
        now: u64,
        store: &Store,
        mode: NodeMode,
        peer_relay: RelayCapacity,
        remaining_copies: u32,
    ) -> Result<RouteDecision> {
        utility_decide(
            &self.weights,
            env,
            peer,
            local,
            now,
            store,
            mode,
            peer_relay,
            remaining_copies,
        )
    }
}

fn utility_decide(
    w: &ScoreWeights,
    env: &DropEnvelope,
    peer: PeerId,
    local: PeerId,
    now: u64,
    store: &Store,
    mode: NodeMode,
    peer_relay: RelayCapacity,
    remaining_copies: u32,
) -> Result<RouteDecision> {
    if blocked(env, peer, local, now, mode, peer_relay) {
        return Ok(deny("ineligible"));
    }
    if env.destination.includes(&peer) {
        return Ok(RouteDecision {
            forward: true,
            score: 1.0,
            reasons: vec![("destination".into(), 1.0)],
        });
    }
    let enc = store.encounter(peer)?.unwrap_or(EncounterRow {
        first_seen: now,
        last_seen: now,
        encounter_count: 1,
        bytes_sent: 0,
        bytes_received: 0,
        successful_forwards: 0,
        failed_forwards: 0,
    });
    let dest_p = match &env.destination {
        Destination::One { .. } | Destination::Many { .. } => 0.2,
        Destination::Public => 0.5,
        Destination::Group { .. } => 0.15,
    };
    let recency = (1.0 / (1.0 + (now.saturating_sub(enc.last_seen) as f64 / 3600.0))).min(1.0);
    let freq = (enc.encounter_count as f64 / 20.0).min(1.0);
    let hist = if enc.successful_forwards + enc.failed_forwards == 0 {
        0.1
    } else {
        enc.successful_forwards as f64 / (enc.successful_forwards + enc.failed_forwards) as f64
    };
    let cap = match peer_relay {
        RelayCapacity::Full => 1.0,
        RelayCapacity::Low => 0.3,
        RelayCapacity::None => 0.0,
    };
    let pri = (env.priority.as_u8() as f64) / 3.0;
    let life = {
        let total = env.expiration.saturating_sub(env.creation_time).max(1);
        let left = env.expiration.saturating_sub(now);
        (left as f64 / total as f64).clamp(0.0, 1.0)
    };
    let repl =
        (remaining_copies as f64 / env.routing_policy.replication_budget.max(1) as f64).min(1.0);
    let storage = store
        .stats()
        .map(|s| {
            let cap = store.quotas().maximum.max(1);
            1.0 - (s.physical_size as f64 / cap as f64).clamp(0.0, 1.0)
        })
        .unwrap_or(0.5);
    let battery = match mode {
        NodeMode::Battery => 0.25,
        NodeMode::Performance => 1.0,
        _ => 0.7,
    };
    let transport = 0.7; // measured RTT is PLANNED; LAN/TCP assumed moderate
    let mut reasons = vec![
        (
            "destination_probability".into(),
            dest_p * w.destination_probability,
        ),
        ("recent encounters".into(), recency * w.encounter_recency),
        ("encounter frequency".into(), freq * w.encounter_frequency),
        ("successful deliveries".into(), hist * w.delivery_history),
        ("available capacity".into(), cap * w.peer_capacity),
        ("object priority".into(), pri * w.object_priority),
        (
            "expiration urgency".into(),
            (1.0 - life) * w.remaining_lifetime,
        ),
        ("replication need".into(), repl * w.replication_need),
        (
            "local storage headroom".into(),
            storage * w.storage_pressure,
        ),
        ("battery / mode cost".into(), battery * w.battery_cost),
        (
            "transport reliability".into(),
            transport * w.transport_reliability,
        ),
    ];
    if remaining_copies <= 1 {
        reasons.push(("replication penalty".into(), -0.4));
    }
    let score: f64 = reasons.iter().map(|(_, v)| *v).sum::<f64>() / reasons.len() as f64;
    Ok(RouteDecision {
        forward: score >= 0.25,
        score,
        reasons,
    })
}

fn blocked(
    env: &DropEnvelope,
    peer: PeerId,
    local: PeerId,
    now: u64,
    mode: NodeMode,
    peer_relay: RelayCapacity,
) -> bool {
    if env.source == peer {
        return true;
    }
    if env.is_expired(now) {
        return true;
    }
    if env.remaining_hops() == 0 {
        return true;
    }
    if peer == local {
        return true;
    }
    if !mode.unsolicited_relay() && !env.destination.includes(&peer) {
        return true;
    }
    peer_relay == RelayCapacity::None && !env.destination.includes(&peer)
}

fn deny(msg: &str) -> RouteDecision {
    RouteDecision {
        forward: false,
        score: 0.0,
        reasons: vec![(msg.into(), 0.0)],
    }
}

pub fn strategy_from_kind(kind: RoutingPolicyKind) -> Box<dyn RoutingStrategy> {
    match kind {
        RoutingPolicyKind::Direct => Box::new(Direct),
        RoutingPolicyKind::Epidemic => Box::new(Epidemic),
        RoutingPolicyKind::SprayAndWait => Box::new(SprayAndWait),
        RoutingPolicyKind::Encounter => Box::new(EncounterBased {
            weights: ScoreWeights::default(),
        }),
        RoutingPolicyKind::Utility => Box::new(Utility {
            weights: ScoreWeights::default(),
        }),
        RoutingPolicyKind::Adaptive => Box::new(AdaptiveRouter),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeliveryForecast {
    pub destination: String,
    pub p_lt_1h: f64,
    pub p_lt_6h: f64,
    pub p_lt_24h: f64,
    pub p_lt_3d: f64,
    pub confidence: f64,
    pub sample_encounters: u64,
    pub note: String,
}

/// Heuristic from local encounter history. Never a delivery guarantee.
pub fn predict_delivery(store: &Store, dest: PeerId, now: u64) -> Result<DeliveryForecast> {
    let enc = store.encounter(dest)?;
    let hist = store.hour_hist(dest).unwrap_or([0; 24]);
    let hour = ((now % 86_400) / 3600) as usize;
    let hour_weight = hist[hour] as f64 / (hist.iter().sum::<u32>().max(1) as f64);
    let (count, last, first, ok_ratio) = match &enc {
        Some(e) => {
            let tot = e.successful_forwards + e.failed_forwards;
            let ratio = if tot == 0 {
                0.35
            } else {
                e.successful_forwards as f64 / tot as f64
            };
            (e.encounter_count, e.last_seen, e.first_seen, ratio)
        }
        None => (0, 0, now, 0.1),
    };
    let recency = if count == 0 {
        0.05
    } else {
        (1.0 / (1.0 + (now.saturating_sub(last) as f64 / 3600.0))).min(1.0)
    };
    let span_days = ((now.saturating_sub(first)) as f64 / 86_400.0).max(1.0);
    let freq = ((count as f64 / span_days) / 4.0).min(1.0);
    let base =
        (0.15 + 0.4 * recency + 0.3 * freq + 0.15 * ok_ratio + 0.1 * hour_weight).clamp(0.0, 0.97);
    let confidence = ((count as f64 / 12.0) * 0.7 + (hist.iter().sum::<u32>() as f64 / 48.0) * 0.3)
        .clamp(0.05, 0.85);
    Ok(DeliveryForecast {
        destination: dest.to_string(),
        p_lt_1h: (base * recency * 0.55).clamp(0.0, 0.95),
        p_lt_6h: (base * 0.75 + recency * 0.1).clamp(0.0, 0.96),
        p_lt_24h: (base * 0.9 + freq * 0.08).clamp(0.0, 0.97),
        p_lt_3d: (base * 0.95 + 0.04).clamp(0.0, 0.98),
        confidence,
        sample_encounters: count,
        note: "Local estimate from this node's encounter log. Not a guarantee.".into(),
    })
}

/// Local adaptive policy. No central reputation service.
pub struct AdaptiveRouter;

impl RoutingStrategy for AdaptiveRouter {
    fn name(&self) -> &'static str {
        "adaptive"
    }
    #[allow(clippy::too_many_arguments)]
    fn decide(
        &self,
        env: &DropEnvelope,
        peer: PeerId,
        local: PeerId,
        now: u64,
        store: &Store,
        mode: NodeMode,
        peer_relay: RelayCapacity,
        remaining_copies: u32,
    ) -> Result<RouteDecision> {
        if env.routing_policy.trusted_only {
            if let Ok(book) = store.load_contacts() {
                let t = book
                    .get(&peer)
                    .map(|c| c.trust)
                    .unwrap_or(deaddrop_core::TrustState::Unknown);
                if !matches!(
                    t,
                    deaddrop_core::TrustState::Known | deaddrop_core::TrustState::Verified
                ) {
                    return Ok(deny("trusted-only"));
                }
            }
        }
        if env.destination.includes(&peer) {
            return Direct.decide(
                env,
                peer,
                local,
                now,
                store,
                mode,
                peer_relay,
                remaining_copies,
            );
        }
        let n = store.all_encounters()?.len();
        if let deaddrop_core::Destination::One { peer: dest } = &env.destination {
            if let Ok(Some(enc)) = store.encounter(*dest) {
                if enc.encounter_count >= 3 {
                    let mut d = EncounterBased {
                        weights: ScoreWeights::default(),
                    }
                    .decide(
                        env,
                        peer,
                        local,
                        now,
                        store,
                        mode,
                        peer_relay,
                        remaining_copies,
                    )?;
                    d.reasons
                        .insert(0, ("adaptive: dest frequently encountered".into(), 0.2));
                    return Ok(d);
                }
            }
        }
        if n <= 3 {
            let mut d = Epidemic.decide(
                env,
                peer,
                local,
                now,
                store,
                mode,
                peer_relay,
                remaining_copies,
            )?;
            d.reasons
                .insert(0, ("adaptive: small local graph".into(), 0.15));
            return Ok(d);
        }
        let mut d = SprayAndWait.decide(
            env,
            peer,
            local,
            now,
            store,
            mode,
            peer_relay,
            remaining_copies,
        )?;
        d.reasons
            .insert(0, ("adaptive: spray-and-wait default".into(), 0.1));
        Ok(d)
    }
}

pub fn confidence_pct(d: &RouteDecision) -> u8 {
    ((d.score.clamp(0.0, 1.0)) * 100.0).round() as u8
}

pub fn format_explain(peer: PeerId, d: &RouteDecision) -> String {
    let mut s = format!("Candidate: {peer}\n");
    for (k, v) in &d.reasons {
        s.push_str(&format!("{k:<28} {v:+.2}\n"));
    }
    s.push_str(&format!("Final Utility               {:.2}\n", d.score));
    s.push_str(&format!(
        "Route confidence            {}%\n",
        confidence_pct(d)
    ));
    s.push_str(&format!(
        "Decision                    {}\n",
        if d.forward { "FORWARD" } else { "HOLD" }
    ));
    s
}
