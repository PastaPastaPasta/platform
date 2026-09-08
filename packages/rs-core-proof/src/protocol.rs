//! Canonical statement and bounded wire primitives. Hash bytes use Core's wire
//! order, which is the reverse of its RPC display order.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::merkle::MerklePath;

pub type Hash = [u8; 32];
pub type Result<T> = core::result::Result<T, &'static str>;
pub const MAX_WITNESS: usize = 1024 * 1024;
pub const MAX_STEPS: usize = 4096;

pub fn sha256d(bytes: &[u8]) -> Hash {
    Sha256::digest(&Sha256::digest(bytes)).into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// 0 = mainnet, 1 = testnet. Other networks are deliberately unsupported.
    pub network: u8,
    pub height: u32,
    pub block_hash: Hash,
    pub masternode_root: Hash,
    pub quorum_root: Hash,
}

impl State {
    pub fn validate(&self) -> Result<()> {
        // v20 is buried at these heights. This program handles the Basic BLS,
        // coinbase-v3 era only, not legacy BLS or future consensus versions.
        let start = match self.network {
            0 => 1_987_776,
            1 => 905_100,
            _ => return Err("unsupported network"),
        };
        if self.height <= start || self.height > i32::MAX as u32 {
            return Err("height outside supported era");
        }
        if self.block_hash == [0; 32] || self.quorum_root == [0; 32] {
            return Err("empty authenticated state");
        }
        Ok(())
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.network);
        out.extend(self.height.to_le_bytes());
        out.extend(self.block_hash);
        out.extend(self.masternode_root);
        out.extend(self.quorum_root);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let state = Self {
            network: r.u8()?,
            height: r.u32()?,
            block_hash: r.array()?,
            masternode_root: r.array()?,
            quorum_root: r.array()?,
        };
        state.validate()?;
        Ok(state)
    }
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or("length overflow")?;
        let v = self.bytes.get(self.pos..end).ok_or("truncated input")?;
        self.pos = end;
        Ok(v)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| "array size")
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err("trailing bytes")
        }
    }
    /// Core CompactSize, including canonical encoding and allocation bounds.
    pub fn compact(&mut self, max: u64) -> Result<usize> {
        let tag = self.u8()?;
        let n = match tag {
            253 => {
                let n = self.u16()? as u64;
                if n < 253 {
                    return Err("noncanonical CompactSize");
                }
                n
            }
            254 => {
                let n = self.u32()? as u64;
                if n <= 0xffff {
                    return Err("noncanonical CompactSize");
                }
                n
            }
            255 => {
                let n = self.u64()?;
                if n <= 0xffff_ffff {
                    return Err("noncanonical CompactSize");
                }
                n
            }
            n => n as u64,
        };
        if n > max {
            return Err("CompactSize limit");
        }
        usize::try_from(n).map_err(|_| "length overflow")
    }
    pub fn blob(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return Err("blob limit");
        }
        self.take(n)
    }
}

pub fn write_blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let n = u32::try_from(bytes.len()).map_err(|_| "blob limit")?;
    out.extend(n.to_le_bytes());
    out.extend(bytes);
    Ok(())
}
