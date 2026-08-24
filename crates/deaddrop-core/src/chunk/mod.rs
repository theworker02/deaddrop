mod erasure;

pub use erasure::{ErasureInfo, ErasureSpec, apply_erasure, can_recover, reconstruct};

use crate::crypto::{CryptoProvider, DefaultProvider};
use crate::{
    ChunkId, ContentId, DdError, ErrorCode, FIXED_CHUNK_SIZE, HashAlgorithm,
    MAX_CHUNKS_PER_MANIFEST, ManifestId, Result,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alg", rename_all = "snake_case")]
pub enum ChunkingAlg {
    Fixed { size: u32 },
    CdcV1 { min: u32, avg: u32, max: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    pub id: ChunkId,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub payload_id: ContentId,
    pub total_length: u64,
    pub algorithm: ChunkingAlg,
    pub chunks: Vec<ChunkRef>,
    pub payload_hash: ContentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure: Option<ErasureInfo>,
}

impl Manifest {
    pub fn id(&self) -> ManifestId {
        let p = DefaultProvider;
        let mut buf = Vec::from(&b"ddp-manifest-v2"[..]);
        buf.extend_from_slice(self.payload_id.as_bytes());
        buf.extend_from_slice(&self.total_length.to_be_bytes());
        for c in &self.chunks {
            buf.extend_from_slice(c.id.as_bytes());
            buf.extend_from_slice(&c.length.to_be_bytes());
        }
        if let Some(e) = &self.erasure {
            buf.extend_from_slice(b"erasure-v1");
            buf.extend_from_slice(&e.data_count.to_be_bytes());
            buf.extend_from_slice(&e.spec.data_shards.to_be_bytes());
            buf.extend_from_slice(&e.spec.parity_shards.to_be_bytes());
        }
        ManifestId::blake3(p.hash(HashAlgorithm::Blake3, &buf).0)
    }

    pub fn missing_indices(&self, present: &[bool]) -> Vec<u32> {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(i, _)| present.get(*i).copied() != Some(true))
            .map(|(i, _)| i as u32)
            .collect()
    }
}

pub struct ChunkedPayload {
    pub manifest: Manifest,
    pub chunks: Vec<Vec<u8>>,
}

pub fn chunk_payload(data: &[u8], alg: ChunkingAlg) -> Result<ChunkedPayload> {
    let slices = match alg {
        ChunkingAlg::Fixed { size } => split_fixed(data, size as usize),
        ChunkingAlg::CdcV1 { min, avg, max } => {
            split_cdc(data, min as usize, avg as usize, max as usize)
        }
    };
    if slices.len() as u32 > MAX_CHUNKS_PER_MANIFEST {
        return Err(DdError::protocol(
            ErrorCode::Ddp1006LimitExceeded,
            "too many chunks",
        ));
    }
    let p = DefaultProvider;
    let mut refs = Vec::new();
    let mut stored = Vec::new();
    for s in slices {
        let digest = p.hash(HashAlgorithm::Blake3, &s);
        refs.push(ChunkRef {
            id: ChunkId::blake3(digest.0),
            length: s.len() as u32,
        });
        stored.push(s);
    }
    let payload_digest = p.hash(HashAlgorithm::Blake3, data);
    let payload_id = ContentId::blake3(payload_digest.0);
    Ok(ChunkedPayload {
        manifest: Manifest {
            payload_id,
            total_length: data.len() as u64,
            algorithm: alg,
            chunks: refs,
            payload_hash: payload_id,
            erasure: None,
        },
        chunks: stored,
    })
}

fn split_fixed(data: &[u8], size: usize) -> Vec<Vec<u8>> {
    let size = size.max(1);
    if data.is_empty() {
        return vec![Vec::new()];
    }
    data.chunks(size).map(|c| c.to_vec()).collect()
}

/// Gear-style content-defined chunking. Deterministic; not a patented FastCDC clone.
fn split_cdc(data: &[u8], min: usize, avg: usize, max: usize) -> Vec<Vec<u8>> {
    let min = min.max(64);
    let max = max.max(min + 1);
    let mask = (avg.next_power_of_two().saturating_sub(1)).max(1);
    let mut table = [0u32; 256];
    let mut x: u32 = 0x9e37_79b9;
    for t in &mut table {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        *t = x;
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut hash: u32 = 0;
    for (i, b) in data.iter().enumerate() {
        hash = (hash << 1).wrapping_add(table[*b as usize]);
        let len = i + 1 - start;
        if (len >= min && (hash as usize & mask) == 0) || len >= max {
            out.push(data[start..=i].to_vec());
            start = i + 1;
            hash = 0;
        }
    }
    if start < data.len() {
        out.push(data[start..].to_vec());
    }
    if out.is_empty() {
        out.push(data.to_vec());
    }
    out
}

pub fn verify_chunk(id: &ChunkId, data: &[u8]) -> Result<()> {
    let p = DefaultProvider;
    let got = ChunkId::blake3(p.hash(HashAlgorithm::Blake3, data).0);
    if &got != id {
        return Err(DdError::protocol(
            ErrorCode::Dds2002CorruptChunk,
            "chunk content id mismatch",
        ));
    }
    Ok(())
}

pub fn reassemble(manifest: &Manifest, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    let data_n = manifest
        .erasure
        .as_ref()
        .map(|e| e.data_count as usize)
        .unwrap_or(manifest.chunks.len());
    if chunks.len() != data_n {
        return Err(DdError::protocol(
            ErrorCode::Dds2003MissingChunk,
            "chunk count",
        ));
    }
    let mut out = Vec::with_capacity(manifest.total_length as usize);
    for (data, refer) in chunks.iter().zip(manifest.chunks.iter().take(data_n)) {
        verify_chunk(&refer.id, data)?;
        if data.len() as u32 != refer.length {
            return Err(DdError::protocol(
                ErrorCode::Dds2002CorruptChunk,
                "chunk length",
            ));
        }
        out.extend_from_slice(data);
    }
    let p = DefaultProvider;
    let hash = ContentId::blake3(p.hash(HashAlgorithm::Blake3, &out).0);
    if hash != manifest.payload_hash {
        return Err(DdError::protocol(
            ErrorCode::Dds2002CorruptChunk,
            "payload hash mismatch",
        ));
    }
    Ok(out)
}

pub fn default_fixed() -> ChunkingAlg {
    ChunkingAlg::Fixed {
        size: FIXED_CHUNK_SIZE,
    }
}

/// Pick a chunk size from object length, estimated contact window, and transport name.
/// Bluetooth sizes are documented defaults; BLE is PLANNED as a transport.
pub fn adaptive_chunk_size(object_len: u64, window_secs: u32, transport: &str) -> u32 {
    let t = transport.to_ascii_lowercase();
    if t.contains("blue") || t == "ble" {
        return 64 * 1024;
    }
    if window_secs > 0 && window_secs < 20 && object_len > 8 * 1024 * 1024 {
        return 256 * 1024;
    }
    if (t.contains("lan") || t.contains("quic") || t.contains("tcp"))
        && object_len >= 50 * 1024 * 1024
    {
        return 1024 * 1024;
    }
    FIXED_CHUNK_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_roundtrip() {
        let data = vec![7u8; 200_000];
        let c = chunk_payload(&data, default_fixed()).unwrap();
        let out = reassemble(&c.manifest, &c.chunks).unwrap();
        assert_eq!(out, data);
        let mut bad = c.chunks[0].clone();
        bad[0] ^= 1;
        assert!(verify_chunk(&c.manifest.chunks[0].id, &bad).is_err());
    }

    #[test]
    fn cdc_reuse_prefix() {
        let a = vec![1u8; 80_000];
        let mut b = a.clone();
        b.extend_from_slice(&[2u8; 1000]);
        let ca = chunk_payload(
            &a,
            ChunkingAlg::CdcV1 {
                min: 2048,
                avg: 8192,
                max: 32768,
            },
        )
        .unwrap();
        let cb = chunk_payload(
            &b,
            ChunkingAlg::CdcV1 {
                min: 2048,
                avg: 8192,
                max: 32768,
            },
        )
        .unwrap();
        let shared = ca
            .manifest
            .chunks
            .iter()
            .filter(|x| cb.manifest.chunks.iter().any(|y| y.id == x.id))
            .count();
        assert!(shared >= 1);
    }

    #[test]
    #[ignore]
    fn bench_fixed_chunk_1mb() {
        let data = vec![3u8; 1_048_576];
        let t = std::time::Instant::now();
        let c = chunk_payload(&data, default_fixed()).unwrap();
        let elapsed = t.elapsed();
        assert_eq!(c.manifest.total_length, data.len() as u64);
        eprintln!("fixed chunk 1MiB in {elapsed:?}");
    }
}
