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

/// Core's quorum special transaction has empty vin/vout, locktime zero, and
/// a v1 payload containing the mining height and complete final commitment.
fn mining_commitment(bytes: &[u8], height: u32) -> Result<Commitment> {
    let mut r = Reader::new(bytes);
    if r.u16()? != 3 || r.u16()? != 6 || r.compact(0)? != 0 || r.compact(0)? != 0 || r.u32()? != 0 {
        return Err("quorum transaction envelope");
    }
    let size = r.compact(1024)?;
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
