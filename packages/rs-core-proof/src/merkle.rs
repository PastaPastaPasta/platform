use crate::{sha256d, Hash, Reader, Result};
use serde::{Deserialize, Serialize};
const MAX_LEAVES: u32 = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    pub index: u32,
    pub count: u32,
    /// Exactly one sibling at each level, including odd self-duplication.
    pub siblings: Vec<Hash>,
}

impl MerklePath {
    pub fn verify(&self, mut leaf: Hash, root: &Hash) -> Result<()> {
        if self.count == 0 || self.count > MAX_LEAVES || self.index >= self.count {
            return Err("Merkle position");
        }
        let mut width = self.count;
        let mut index = self.index;
        let mut it = self.siblings.iter();
        while width > 1 {
            let sibling = it.next().ok_or("short Merkle path")?;
            let odd = index ^ 1 >= width;
            if (odd && sibling != &leaf) || (!odd && sibling == &leaf) {
                return Err("mutated Merkle path");
            }
            let mut pair = [0; 64];
            if index & 1 == 0 {
                pair[..32].copy_from_slice(&leaf);
                pair[32..].copy_from_slice(sibling);
            } else {
                pair[..32].copy_from_slice(sibling);
                pair[32..].copy_from_slice(&leaf);
            }
            leaf = sha256d(&pair);
            index /= 2;
            width = width.div_ceil(2);
        }
        if it.next().is_some() || leaf != *root {
            return Err("Merkle root/path");
        }
        Ok(())
    }
    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let index = r.u32()?;
        let count = r.u32()?;
        let n = r.u8()? as usize;
        if n > 17 {
            return Err("Merkle depth limit");
        }
        let mut siblings = Vec::with_capacity(n);
        for _ in 0..n {
            siblings.push(r.array()?);
        }
        Ok(Self {
            index,
            count,
            siblings,
        })
    }
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.siblings.len() > 17 {
            return Err("Merkle depth limit");
        }
        out.extend(self.index.to_le_bytes());
        out.extend(self.count.to_le_bytes());
        out.push(self.siblings.len() as u8);
        for hash in &self.siblings {
            out.extend(hash);
        }
        Ok(())
    }
}
