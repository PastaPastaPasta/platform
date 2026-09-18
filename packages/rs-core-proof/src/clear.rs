//! Ordinary Dash certificate chain. Intermediate hops authenticate the next
//! signer through its mining transaction and explicitly linked ancestor headers.
//! This retains the historical-certificate trust model, not full DKG replay.
use crate::protocol::{
    sha256d, write_blob, MerklePath, Reader, Result, State, MAX_STEPS, MAX_WITNESS,
};
use crate::{
    chainlock_sign_hash, coinbase_roots, header_hash, parse_commitment, verify_bls, Commitment,
};
use serde::{Deserialize, Serialize};

pub const CLEAR_MAGIC: &[u8; 8] = b"DASHNC02";
/// Total extra headers across the complete proof, bounded before allocation.
pub const MAX_ANCESTOR_HEADERS: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub height: u32,
    pub header: Vec<u8>,
    pub signature: Vec<u8>,
}
impl Certificate {
    fn verify(&self, signer: &Commitment, minimum: u32) -> Result<[u8; 32]> {
        if self.height <= minimum {
            return Err("non-increasing certificate");
        }
        let hash = header_hash(
            self.header
                .as_slice()
                .try_into()
                .map_err(|_| "header length")?,
        );
        let message = chainlock_sign_hash(signer.kind, &signer.quorum_hash, self.height, &hash)?;
        verify_bls(
            &signer.public_key,
            self.signature
                .as_slice()
                .try_into()
                .map_err(|_| "signature length")?,
            &message,
        )?;
        Ok(hash)
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.header.len() != 80 || self.signature.len() != 96 {
            return Err("certificate length");
        }
        out.extend(self.height.to_le_bytes());
        out.extend(&self.header);
        out.extend(&self.signature);
        Ok(())
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            height: r.u32()?,
            header: r.take(80)?.to_vec(),
            signature: r.take(96)?.to_vec(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProof {
    pub transaction: Vec<u8>,
    pub path: MerklePath,
}
impl TransactionProof {
    fn verify(&self, header: &[u8]) -> Result<()> {
        if header.len() != 80 {
            return Err("header length");
        }
        // Exclude a 64-byte internal Merkle node masquerading as a transaction.
        if self.transaction.len() == 64 || self.transaction.len() > 100_000 {
            return Err("transaction size");
        }
        self.path.verify(
            sha256d(&self.transaction),
            &header[36..68].try_into().map_err(|_| "header root")?,
        )
    }
    fn roots(&self, cert: &Certificate) -> Result<([u8; 32], [u8; 32])> {
        if self.path.index != 0 {
            return Err("coinbase position");
        }
        self.verify(&cert.header)?;
        coinbase_roots(&self.transaction, cert.height)
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        write_blob(out, &self.transaction)?;
        self.path.encode(out)
    }
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            transaction: r.blob(100_000)?.to_vec(),
            path: MerklePath::decode(r)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiningWitness {
    pub proof: TransactionProof,
    /// Oldest first: mining block through the certified block's parent.
    pub ancestors: Vec<Vec<u8>>,
}
impl MiningWitness {
    fn commitment(&self, cert: &Certificate) -> Result<Commitment> {
        if self.ancestors.len() > MAX_ANCESTOR_HEADERS {
            return Err("ancestor limit");
        }
        let height = cert
            .height
            .checked_sub(self.ancestors.len() as u32)
            .ok_or("mining height")?;
        if height == 0 || self.proof.path.index == 0 {
            return Err("mining position/height");
        }
        let mut descendant = cert.header.as_slice();
        for ancestor in self.ancestors.iter().rev() {
            let hash = header_hash(
                ancestor
                    .as_slice()
                    .try_into()
                    .map_err(|_| "ancestor length")?,
            );
            if descendant.get(4..36) != Some(hash.as_slice()) {
                return Err("ancestor continuity");
            }
            descendant = ancestor;
        }
        self.proof.verify(descendant)?;
        mining_commitment(&self.proof.transaction, height)
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.ancestors.len() > MAX_ANCESTOR_HEADERS {
            return Err("ancestor limit");
        }
        self.proof.encode(out)?;
        out.extend((self.ancestors.len() as u16).to_le_bytes());
        for h in &self.ancestors {
            if h.len() != 80 {
                return Err("ancestor length");
            }
            out.extend(h);
        }
        Ok(())
    }
    fn decode(r: &mut Reader<'_>, remaining_headers: &mut usize) -> Result<Self> {
        let proof = TransactionProof::decode(r)?;
        let count = r.u16()? as usize;
        *remaining_headers = remaining_headers
            .checked_sub(count)
            .ok_or("total ancestor limit")?;
        // Check that all headers exist before allocating the vector.
        let raw = r.take(count * 80)?;
        let ancestors = raw.chunks_exact(80).map(|h| h.to_vec()).collect();
        Ok(Self { proof, ancestors })
    }
}

/// Consume a serialized transaction's inputs, outputs and lock time. Consensus
/// only requires a special transaction version and type for a mined commitment;
/// the inputs, outputs and lock time are unconstrained (Core commit 725f7221bf),
/// so this reads whatever shape a miner produced. The blob is bounded by
/// [`crate::MAX_TX`] before this runs.
fn skip_inputs_outputs_locktime(r: &mut Reader<'_>) -> Result<()> {
    for _ in 0..r.compact(crate::MAX_TX as u64)? {
        r.take(36)?; // prevout hash and index
        let n = r.compact(crate::MAX_TX as u64)?;
        r.take(n)?; // scriptSig
        r.u32()?; // sequence
    }
    for _ in 0..r.compact(crate::MAX_TX as u64)? {
        r.u64()?; // value
        let n = r.compact(crate::MAX_TX as u64)?;
        r.take(n)?; // scriptPubKey
    }
    r.u32()?; // lock time
    Ok(())
}

/// Core's quorum special transaction: any special-transaction version (>= 3),
/// type 6, and a v1 payload containing the mining height and complete final
/// commitment. Its inputs, outputs and lock time are not consensus-constrained.
fn mining_commitment(bytes: &[u8], height: u32) -> Result<Commitment> {
    let mut r = Reader::new(bytes);
    // Core's nVersion is int16_t: 0x8000..=0xFFFF are negative and not special.
    if (r.u16()? as i16) < 3 || r.u16()? != 6 {
        return Err("quorum transaction envelope");
    }
    skip_inputs_outputs_locktime(&mut r)?;
    // Payload = version (2) + height (4) + commitment; Core caps the commitment at 1024.
    let size = r.compact(1024 + 6)?;
    let payload = r.take(size)?;
    r.finish()?;
    let mut p = Reader::new(payload);
    if p.u16()? != 1 || p.u32()? != height {
        return Err("quorum payload height/version");
    }
    parse_commitment(&payload[6..])
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Link {
    pub certificate: Certificate,
    pub witness: MiningWitness,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearProof {
    pub anchor: State,
    pub seed_commitment: Vec<u8>,
    pub seed_path: MerklePath,
    pub links: Vec<Link>,
    pub target: Certificate,
    pub target_coinbase: TransactionProof,
}
impl ClearProof {
    fn check_limits(&self) -> Result<()> {
        if self.links.len() >= MAX_STEPS {
            return Err("link count");
        }
        let mut remaining = MAX_ANCESTOR_HEADERS;
        for link in &self.links {
            remaining = remaining
                .checked_sub(link.witness.ancestors.len())
                .ok_or("total ancestor limit")?;
        }
        Ok(())
    }
    /// Authenticate a transition from an independently supplied trusted snapshot.
    pub fn verify(&self, trusted: &State) -> Result<State> {
        if &self.anchor != trusted {
            return Err("untrusted snapshot");
        }
        self.check_limits()?;
        self.anchor.validate()?;
        let kind = if self.anchor.network == 0 { 2 } else { 1 };
        let mut signer = parse_commitment(&self.seed_commitment)?;
        self.seed_path
            .verify(sha256d(&self.seed_commitment), &self.anchor.quorum_root)?;
        let mut height = self.anchor.height;
        for link in &self.links {
            if signer.kind != kind {
                return Err("ChainLock quorum type");
            }
            link.certificate.verify(&signer, height)?;
            let next = link.witness.commitment(&link.certificate)?;
            if next.quorum_hash == signer.quorum_hash {
                return Err("redundant signer");
            }
            signer = next;
            height = link.certificate.height;
        }
        if signer.kind != kind {
            return Err("ChainLock quorum type");
        }
        let block_hash = self.target.verify(&signer, height)?;
        let (masternode_root, quorum_root) = self.target_coinbase.roots(&self.target)?;
        let state = State {
            network: self.anchor.network,
            height: self.target.height,
            block_hash,
            masternode_root,
            quorum_root,
        };
        state.validate()?;
        Ok(state)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check_limits()?;
        let mut out = CLEAR_MAGIC.to_vec();
        self.anchor.encode(&mut out);
        write_blob(&mut out, &self.seed_commitment)?;
        self.seed_path.encode(&mut out)?;
        out.extend((self.links.len() as u16).to_le_bytes());
        for link in &self.links {
            link.certificate.encode(&mut out)?;
            link.witness.encode(&mut out)?;
        }
        self.target.encode(&mut out)?;
        self.target_coinbase.encode(&mut out)?;
        if out.len() > MAX_WITNESS {
            return Err("witness limit");
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_WITNESS {
            return Err("witness limit");
        }
        let mut r = Reader::new(bytes);
        if r.take(8)? != CLEAR_MAGIC {
            return Err("clear version");
        }
        let anchor = State::decode(&mut r)?;
        let seed_commitment = r.blob(1024)?.to_vec();
        let seed_path = MerklePath::decode(&mut r)?;
        let n = r.u16()? as usize;
        if n >= MAX_STEPS {
            return Err("link count");
        }
        let mut links = Vec::with_capacity(n);
        let mut remaining_headers = MAX_ANCESTOR_HEADERS;
        for _ in 0..n {
            links.push(Link {
                certificate: Certificate::decode(&mut r)?,
                witness: MiningWitness::decode(&mut r, &mut remaining_headers)?,
            });
        }
        let target = Certificate::decode(&mut r)?;
        let target_coinbase = TransactionProof::decode(&mut r)?;
        r.finish()?;
        Ok(Self {
            anchor,
            seed_commitment,
            seed_path,
            links,
            target,
            target_coinbase,
        })
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::*;

    fn fixture() -> ClearProof {
        serde_json::from_str(include_str!("../tests/data/short.json")).unwrap()
    }

    /// Split a real mined commitment into (payload, mining height) by parsing
    /// the fixture's canonical empty-vin/vout shape.
    fn fixture_commitment() -> (Vec<u8>, u32, [u8; 32]) {
        let proof = fixture();
        let link = &proof.links[0];
        let height = link.certificate.height - link.witness.ancestors.len() as u32;
        let tx = &link.witness.proof.transaction;
        // version(2) type(2) vin(1)=0 vout(1)=0 locktime(4) payload_len(compact)
        assert_eq!(
            &tx[4..6],
            &[0, 0],
            "fixture commitment must have empty vin/vout"
        );
        let mut r = Reader::new(tx);
        r.take(10).unwrap();
        let n = r.compact(2048).unwrap();
        let payload = r.take(n).unwrap().to_vec();
        let expected = mining_commitment(tx, height).unwrap().quorum_hash;
        (payload, height, expected)
    }

    fn compact(out: &mut Vec<u8>, n: usize) {
        match n {
            0..=252 => out.push(n as u8),
            253..=65_535 => {
                out.push(253);
                out.extend((n as u16).to_le_bytes());
            }
            _ => unreachable!("test helper only encodes counts up to u16::MAX"),
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn accepts_every_consensus_valid_commitment_shape() {
        // Core commit 725f7221bf: consensus only requires a special version and
        // TRANSACTION_QUORUM_COMMITMENT; vin, vout and lock time are free.
        let (payload, height, expected) = fixture_commitment();
        let mut tx = Vec::new();
        tx.extend(4u16.to_le_bytes()); // any special version >= 3
        tx.extend(6u16.to_le_bytes());
        compact(&mut tx, 1); // one input
        tx.extend([0xAB; 32]);
        tx.extend(1u32.to_le_bytes());
        compact(&mut tx, 3);
        tx.extend([0x51, 0x52, 0x53]);
        tx.extend(0xFFFF_FFFEu32.to_le_bytes());
        compact(&mut tx, 2); // two outputs
        for _ in 0..2 {
            tx.extend(1_000u64.to_le_bytes());
            compact(&mut tx, 1);
            tx.push(0x6a);
        }
        tx.extend(7u32.to_le_bytes()); // nonzero lock time
        compact(&mut tx, payload.len());
        tx.extend(&payload);
        assert_eq!(
            mining_commitment(&tx, height).unwrap().quorum_hash,
            expected
        );

        // Still rejected: legacy (non-special) version, wrong type, wrong height.
        let mut legacy = tx.clone();
        legacy[0..2].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            mining_commitment(&legacy, height).unwrap_err(),
            "quorum transaction envelope"
        );
        let mut wrong_type = tx.clone();
        wrong_type[2..4].copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(
            mining_commitment(&wrong_type, height).unwrap_err(),
            "quorum transaction envelope"
        );
        assert_eq!(
            mining_commitment(&tx, height + 1).unwrap_err(),
            "quorum payload height/version"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn accepts_coinbase_with_more_than_4096_outputs_and_any_special_version() {
        let proof = fixture();
        let height = proof.target.height;
        let tx = &proof.target_coinbase.transaction;
        let expected = coinbase_roots(tx, height).unwrap();

        // Re-serialize the real coinbase: version 4, 4,097 empty outputs, same input/payload.
        let mut r = Reader::new(tx);
        r.take(4).unwrap(); // version + type
        r.compact(1).unwrap();
        let input = r.take(36).unwrap().to_vec();
        let script_len = r.compact(100).unwrap();
        let script = r.take(script_len).unwrap().to_vec();
        let sequence = r.u32().unwrap();
        let outputs = r.compact(100_000).unwrap();
        for _ in 0..outputs {
            r.u64().unwrap();
            let n = r.compact(100_000).unwrap();
            r.take(n).unwrap();
        }
        let lock_time = r.u32().unwrap();
        let n = r.compact(100_000).unwrap();
        let payload = r.take(n).unwrap().to_vec();

        let mut out = Vec::new();
        out.extend(4u16.to_le_bytes());
        out.extend(5u16.to_le_bytes());
        compact(&mut out, 1);
        out.extend(&input);
        compact(&mut out, script.len());
        out.extend(&script);
        out.extend(sequence.to_le_bytes());
        compact(&mut out, 4097);
        for _ in 0..4097 {
            out.extend(0u64.to_le_bytes());
            compact(&mut out, 0);
        }
        out.extend(lock_time.to_le_bytes());
        compact(&mut out, payload.len());
        out.extend(&payload);
        assert_eq!(coinbase_roots(&out, height).unwrap(), expected);

        // Still rejected: legacy version, zero outputs, oversized scriptSig.
        let mut legacy = out.clone();
        legacy[0..2].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            coinbase_roots(&legacy, height).unwrap_err(),
            "coinbase transaction type/version"
        );
    }
}
