//! Optional forward error correction for Drop chunks.
//!
//! `erasure-xor-v1` (parity_shards == 1) uses per-group XOR.
//! `erasure-v1` (parity_shards > 1) uses Reed–Solomon over GF(2^8).
//! Recovered payload is still verified against `payload_hash`.

use super::{ChunkRef, ChunkedPayload, Manifest};
use crate::crypto::{CryptoProvider, DefaultProvider};
use crate::{ChunkId, DdError, ErrorCode, HashAlgorithm, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureSpec {
    pub data_shards: u32,
    pub parity_shards: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureInfo {
    pub spec: ErasureSpec,
    /// Number of original payload chunks (prefix of `manifest.chunks`).
    pub data_count: u32,
}

impl ErasureSpec {
    pub fn validate(self) -> Result<()> {
        if self.data_shards == 0 || self.data_shards > 64 {
            return Err(DdError::protocol(
                ErrorCode::Ddp1006LimitExceeded,
                "erasure data_shards must be 1..=64",
            ));
        }
        if self.parity_shards == 0 || self.parity_shards > 16 {
            return Err(DdError::protocol(
                ErrorCode::Ddp1006LimitExceeded,
                "erasure parity_shards must be 1..=16",
            ));
        }
        Ok(())
    }
}

/// Append parity chunks. Data chunks stay content-addressed and independently verifiable.
pub fn apply_erasure(mut body: ChunkedPayload, spec: ErasureSpec) -> Result<ChunkedPayload> {
    spec.validate()?;
    let data_count = body.chunks.len() as u32;
    if data_count == 0 {
        return Ok(body);
    }
    let p = DefaultProvider;
    let data_n = spec.data_shards as usize;
    let parity_n = spec.parity_shards as usize;
    let data_chunks = body.chunks.clone();
    let mut i = 0usize;
    while i < data_chunks.len() {
        let end = (i + data_n).min(data_chunks.len());
        let group = &data_chunks[i..end];
        let width = group.iter().map(|c| c.len()).max().unwrap_or(0);
        let mut shards = vec![vec![0u8; width]; data_n + parity_n];
        for (s, chunk) in shards.iter_mut().zip(group.iter()) {
            s[..chunk.len()].copy_from_slice(chunk);
        }
        if parity_n == 1 {
            xor_parity(&mut shards, data_n);
        } else {
            let rs = ReedSolomon::new(data_n, parity_n).map_err(|e| {
                DdError::protocol(
                    ErrorCode::Ddp1006LimitExceeded,
                    format!("reed-solomon: {e}"),
                )
            })?;
            rs.encode(&mut shards)
                .map_err(|e| DdError::protocol(ErrorCode::Dds2002CorruptChunk, format!("{e}")))?;
        }
        for shard in shards.iter().skip(data_n) {
            let digest = p.hash(HashAlgorithm::Blake3, shard);
            body.manifest.chunks.push(ChunkRef {
                id: ChunkId::blake3(digest.0),
                length: shard.len() as u32,
            });
            body.chunks.push(shard.clone());
        }
        i = end;
    }
    body.manifest.erasure = Some(ErasureInfo { spec, data_count });
    Ok(body)
}

fn xor_parity(shards: &mut [Vec<u8>], data_n: usize) {
    let width = shards.first().map(|s| s.len()).unwrap_or(0);
    let mut parity = vec![0u8; width];
    for shard in shards.iter().take(data_n) {
        for (p, b) in parity.iter_mut().zip(shard.iter()) {
            *p ^= *b;
        }
    }
    if let Some(slot) = shards.get_mut(data_n) {
        *slot = parity;
    }
}

pub fn can_recover(manifest: &Manifest, present: &[bool]) -> bool {
    let Some(info) = &manifest.erasure else {
        return !present.is_empty() && present.iter().all(|x| *x);
    };
    let data_n = info.spec.data_shards as usize;
    let parity_n = info.spec.parity_shards as usize;
    let data_count = info.data_count as usize;
    let stripe = data_n + parity_n;
    let groups = data_count.div_ceil(data_n);
    for g in 0..groups {
        let data_start = g * data_n;
        let data_end = (data_start + data_n).min(data_count);
        let parity_start = data_count + g * parity_n;
        let mut have = 0usize;
        for i in data_start..data_end {
            if present.get(i).copied() == Some(true) {
                have += 1;
            }
        }
        // Empty padding shards (incomplete last group) count as present.
        have += data_n - (data_end - data_start);
        for p in 0..parity_n {
            if present.get(parity_start + p).copied() == Some(true) {
                have += 1;
            }
        }
        if have < data_n {
            return false;
        }
        let _ = stripe;
    }
    true
}

/// Reconstruct original data chunks. `slots[i]` is `None` when missing.
pub fn reconstruct(manifest: &Manifest, slots: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>> {
    let Some(info) = &manifest.erasure else {
        let mut out = Vec::new();
        for (i, refer) in manifest.chunks.iter().enumerate() {
            let Some(data) = slots.get(i).and_then(|s| s.as_ref()) else {
                return Err(DdError::protocol(
                    ErrorCode::Dds2003MissingChunk,
                    format!("chunk {i}"),
                ));
            };
            super::verify_chunk(&refer.id, data)?;
            out.push(data.clone());
        }
        return Ok(out);
    };
    let data_n = info.spec.data_shards as usize;
    let parity_n = info.spec.parity_shards as usize;
    let data_count = info.data_count as usize;
    let groups = data_count.div_ceil(data_n);
    let mut recovered = vec![Vec::new(); data_count];
    for g in 0..groups {
        let data_start = g * data_n;
        let data_end = (data_start + data_n).min(data_count);
        let parity_start = data_count + g * parity_n;
        let width = (data_start..data_end)
            .filter_map(|i| slots.get(i).and_then(|s| s.as_ref()).map(|d| d.len()))
            .chain((0..parity_n).filter_map(|p| {
                slots
                    .get(parity_start + p)
                    .and_then(|s| s.as_ref())
                    .map(|d| d.len())
            }))
            .max()
            .unwrap_or(0);
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; data_n + parity_n];
        for (off, i) in (data_start..data_end).enumerate() {
            if let Some(Some(d)) = slots.get(i) {
                let mut padded = vec![0u8; width];
                padded[..d.len()].copy_from_slice(d);
                shards[off] = Some(padded);
            }
        }
        #[allow(clippy::needless_range_loop)]
        for off in (data_end - data_start)..data_n {
            shards[off] = Some(vec![0u8; width]);
        }
        for p in 0..parity_n {
            if let Some(Some(d)) = slots.get(parity_start + p) {
                shards[data_n + p] = Some(d.clone());
            }
        }
        if parity_n == 1 {
            recover_xor(&mut shards, data_n, width)?;
        } else {
            let rs = ReedSolomon::new(data_n, parity_n).map_err(|e| {
                DdError::protocol(ErrorCode::Dds2002CorruptChunk, format!("reed-solomon: {e}"))
            })?;
            rs.reconstruct(&mut shards).map_err(|_| {
                DdError::protocol(ErrorCode::Dds2003MissingChunk, "erasure reconstruct")
            })?;
        }
        for (off, i) in (data_start..data_end).enumerate() {
            let shard = shards[off]
                .as_ref()
                .ok_or_else(|| DdError::protocol(ErrorCode::Dds2003MissingChunk, "shard"))?;
            let want = manifest.chunks[i].length as usize;
            recovered[i] = shard[..want].to_vec();
            super::verify_chunk(&manifest.chunks[i].id, &recovered[i])?;
        }
    }
    Ok(recovered)
}

fn recover_xor(shards: &mut [Option<Vec<u8>>], _data_n: usize, width: usize) -> Result<()> {
    let missing: Vec<usize> = shards
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_none())
        .map(|(i, _)| i)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    if missing.len() > 1 {
        return Err(DdError::protocol(
            ErrorCode::Dds2003MissingChunk,
            "xor erasure recovers at most one shard per group",
        ));
    }
    let mut acc = vec![0u8; width];
    for (i, shard) in shards.iter().enumerate() {
        if i == missing[0] {
            continue;
        }
        let Some(s) = shard else {
            return Err(DdError::protocol(
                ErrorCode::Dds2003MissingChunk,
                "xor group incomplete",
            ));
        };
        for (a, b) in acc.iter_mut().zip(s.iter()) {
            *a ^= *b;
        }
    }
    shards[missing[0]] = Some(acc);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::{chunk_payload, default_fixed, reassemble};

    #[test]
    fn xor_recovers_one_missing() {
        let data = vec![9u8; 90_000];
        let raw = chunk_payload(&data, default_fixed()).unwrap();
        let body = apply_erasure(
            raw,
            ErasureSpec {
                data_shards: 2,
                parity_shards: 1,
            },
        )
        .unwrap();
        let mut slots: Vec<Option<Vec<u8>>> = body.chunks.iter().cloned().map(Some).collect();
        slots[0] = None;
        let got = reconstruct(&body.manifest, &slots).unwrap();
        let out = reassemble(
            &Manifest {
                erasure: None,
                chunks: body.manifest.chunks
                    [..body.manifest.erasure.as_ref().unwrap().data_count as usize]
                    .to_vec(),
                ..body.manifest.clone()
            },
            &got,
        )
        .unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn rs_recovers_two_missing() {
        let data = vec![3u8; 200_000];
        let raw = chunk_payload(&data, default_fixed()).unwrap();
        let body = apply_erasure(
            raw,
            ErasureSpec {
                data_shards: 3,
                parity_shards: 2,
            },
        )
        .unwrap();
        let mut slots: Vec<Option<Vec<u8>>> = body.chunks.iter().cloned().map(Some).collect();
        slots[0] = None;
        slots[1] = None;
        let got = reconstruct(&body.manifest, &slots).unwrap();
        assert_eq!(got.iter().map(|c| c.len()).sum::<usize>(), data.len());
        let mut cat = Vec::new();
        for c in got {
            cat.extend_from_slice(&c);
        }
        assert_eq!(cat, data);
    }
}
