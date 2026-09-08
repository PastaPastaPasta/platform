//! Atomic verification of a chain and consensus record openings.
use crate::{clear::ClearProof, sha256d, MerklePath, Reader, Result, State, MAX_WITNESS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Quorum,
    Masternode,
}

pub struct VerifiedRecord<'a> {
    pub kind: RecordKind,
    pub leaf: &'a [u8],
}

/// Constructible only by successful verification.
pub struct VerifiedBootstrap<'a> {
    state: State,
    records: Vec<VerifiedRecord<'a>>,
}
impl<'a> VerifiedBootstrap<'a> {
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn records(&self) -> &[VerifiedRecord<'a>] {
        &self.records
    }
}

pub fn verify<'a>(
    bytes: &'a [u8],
    anchor: &State,
    minimum_height: u32,
) -> Result<VerifiedBootstrap<'a>> {
    if bytes.len() > MAX_WITNESS {
        return Err("bootstrap limit");
    }
    let mut reader = Reader::new(bytes);
    let proof = ClearProof::decode(reader.blob(MAX_WITNESS)?)?;
    let state = proof.verify(anchor)?;
    if state.height < minimum_height {
        return Err("stale target");
    }
    let count = reader.u8()?;
    if !(1..=16).contains(&count) {
        return Err("record count");
    }
    let mut records = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (kind, root) = match reader.u8()? {
            0 => (RecordKind::Quorum, &state.quorum_root),
            1 => (RecordKind::Masternode, &state.masternode_root),
            _ => return Err("record kind"),
        };
        let leaf = reader.blob(4096)?;
        if leaf.is_empty() || leaf.len() == 64 {
            return Err("record leaf size");
        }
        MerklePath::decode(&mut reader)?.verify(sha256d(leaf), root)?;
        records.push(VerifiedRecord { kind, leaf });
    }
    reader.finish()?;
    Ok(VerifiedBootstrap { state, records })
}
