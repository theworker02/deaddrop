//! Connection-window aware transfer ordering. Preempts bulk behind urgent Drops.

use deaddrop_core::{DropEnvelope, ObjectId, Priority};

#[derive(Debug, Clone)]
pub struct ScheduledItem {
    pub object: ObjectId,
    pub remaining_bytes: u64,
    pub priority: Priority,
    pub expires_at: u64,
    pub score: f64,
}

/// Estimate a usable contact window from average encounter duration (seconds).
pub fn estimated_window_secs(avg_duration: u64, last_seen_age: u64) -> u64 {
    if last_seen_age > 86_400 {
        return 8;
    }
    avg_duration.clamp(5, 120)
}

pub fn can_finish(remaining_bytes: u64, window_secs: u64, bytes_per_sec: u64) -> bool {
    if window_secs == 0 || bytes_per_sec == 0 {
        return false;
    }
    remaining_bytes <= window_secs.saturating_mul(bytes_per_sec)
}

/// Higher score transfers first. Urgent is never blocked behind a huge bulk object.
pub fn schedule(now: u64, window_secs: u64, items: &mut [ScheduledItem]) {
    for it in items.iter_mut() {
        let life = it.expires_at.saturating_sub(now) as f64;
        let urgency = (it.priority.as_u8() as f64) * 10.0;
        let exp = if life < 3600.0 { 8.0 } else { 1.0 };
        let fits = if can_finish(it.remaining_bytes, window_secs, 250_000) {
            5.0
        } else if it.priority == Priority::Urgent {
            20.0
        } else {
            -2.0
        };
        it.score = urgency + exp + fits - (it.remaining_bytes as f64 / 1_000_000_000.0);
    }
    items.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

pub fn from_envelope(env: &DropEnvelope, remaining_bytes: u64) -> ScheduledItem {
    ScheduledItem {
        object: env.object_id,
        remaining_bytes,
        priority: env.priority,
        expires_at: env.expiration,
        score: 0.0,
    }
}
