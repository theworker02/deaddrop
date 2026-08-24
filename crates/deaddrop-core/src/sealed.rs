//! Sealed Drops: application policy until a condition holds.
//!
//! `dd.seal-until` is **not** a cryptographic time-lock. Honest nodes refuse to
//! decrypt before `until`. A dishonest recipient who already has the CEK wrap
//! can ignore the extension. Prefer key-release / quorum receipts when available.

use crate::store::unix_now;
use crate::{DdError, DropEnvelope, ErrorCode, Result};

pub const SEAL_UNTIL_EXT: &str = "dd.seal-until";
pub const SEAL_QUORUM_EXT: &str = "dd.seal-quorum";

pub fn seal_until(env: &DropEnvelope) -> Option<u64> {
    env.extensions
        .iter()
        .find(|e| e.name == SEAL_UNTIL_EXT)
        .and_then(|e| {
            if e.data.len() == 8 {
                Some(u64::from_be_bytes(e.data.clone().try_into().ok()?))
            } else {
                None
            }
        })
}

pub fn seal_quorum(env: &DropEnvelope) -> Option<u32> {
    env.extensions
        .iter()
        .find(|e| e.name == SEAL_QUORUM_EXT)
        .and_then(|e| {
            if e.data.len() == 4 {
                Some(u32::from_be_bytes(e.data.clone().try_into().ok()?))
            } else {
                None
            }
        })
}

pub fn enforce(env: &DropEnvelope, now: u64, receipt_issuers: u32) -> Result<()> {
    if let Some(until) = seal_until(env)
        && now < until
    {
        return Err(DdError::protocol(
            ErrorCode::Ddp1009Sealed,
            format!("sealed until {until} (policy; not a crypto time-lock)"),
        ));
    }
    if let Some(need) = seal_quorum(env)
        && receipt_issuers < need
    {
        return Err(DdError::protocol(
            ErrorCode::Ddp1009Sealed,
            format!("sealed until {need} receipts (have {receipt_issuers})"),
        ));
    }
    let _ = unix_now;
    Ok(())
}
