use crate::crypto::{CryptoProvider, DefaultProvider};
use crate::{HashAlgorithm, ObjectId, Result};

pub struct BloomFilter {
    pub n: u32,
    pub k: u8,
    pub bits: Vec<u8>,
}

impl BloomFilter {
    pub fn from_ids(ids: &[ObjectId], bits_per: usize) -> Self {
        let m_bits = (ids.len().max(1) * bits_per).max(64);
        let bytes = m_bits.div_ceil(8);
        let k = 4u8;
        let mut bits = vec![0u8; bytes];
        for id in ids {
            for i in 0..k {
                let idx = bit_index(id, i, m_bits);
                bits[idx / 8] |= 1 << (idx % 8);
            }
        }
        Self {
            n: ids.len() as u32,
            k,
            bits,
        }
    }

    pub fn may_contain(&self, id: &ObjectId) -> bool {
        let m_bits = self.bits.len() * 8;
        if m_bits == 0 {
            return false;
        }
        (0..self.k).all(|i| {
            let idx = bit_index(id, i, m_bits);
            self.bits[idx / 8] & (1 << (idx % 8)) != 0
        })
    }
}

fn bit_index(id: &ObjectId, i: u8, m_bits: usize) -> usize {
    let p = DefaultProvider;
    let mut buf = Vec::from(id.as_bytes().as_slice());
    buf.push(i);
    let h = p.hash(HashAlgorithm::Blake3, &buf);
    let v = u64::from_le_bytes(h.0[..8].try_into().unwrap());
    (v as usize) % m_bits
}

pub enum InventoryAlgo {
    Sorted,
    Bloom,
}

pub fn choose_inventory(local_count: usize, peer_supports_bloom: bool) -> InventoryAlgo {
    if peer_supports_bloom && local_count > 64 {
        InventoryAlgo::Bloom
    } else {
        InventoryAlgo::Sorted
    }
}

pub fn want_from_sorted(peer_ids: &[ObjectId], local: &[ObjectId]) -> Vec<ObjectId> {
    let set: std::collections::HashSet<_> = local.iter().copied().collect();
    peer_ids
        .iter()
        .copied()
        .filter(|id| !set.contains(id))
        .collect()
}

pub fn want_from_bloom(local: &[ObjectId], bloom: &BloomFilter) -> Vec<ObjectId> {
    // Receiver of a bloom cannot list peer IDs; this returns local IDs the peer may lack.
    local
        .iter()
        .copied()
        .filter(|id| !bloom.may_contain(id))
        .collect()
}

pub fn _ok() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObjectId;

    #[test]
    fn bloom_no_false_negative() {
        let ids: Vec<_> = (0u8..40)
            .map(|i| {
                let mut d = [0u8; 32];
                d[0] = i;
                ObjectId::blake3(d)
            })
            .collect();
        let b = BloomFilter::from_ids(&ids, 10);
        for id in &ids {
            assert!(b.may_contain(id));
        }
    }
}
