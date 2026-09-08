//! Exact Dash byte/crypto checks under the checkpoint-and-certificate trust
//! model. This does NOT independently reconstruct Core's DKG or signer choice.
use blst::{
    min_pk::{PublicKey, Signature},
    BLST_ERROR,
};
pub use protocol::{sha256d, Hash, Reader, Result, State, MAX_STEPS, MAX_WITNESS};
pub mod bootstrap;
mod merkle;
mod protocol;

pub mod clear;

const MAX_TX: usize = 100_000;
pub use protocol::MerklePath;

pub fn header_hash(header: &[u8; 80]) -> Hash {
    // The dependency unconditionally reads 80 bytes; the array type is required
    // for memory safety, including when handling attacker-controlled input.
    dash_core_proof_x11::hash(header)
}

pub fn chainlock_sign_hash(kind: u8, quorum: &Hash, height: u32, block: &Hash) -> Result<Hash> {
    if height > i32::MAX as u32 {
        return Err("ChainLock height");
    }
    let mut request = b"\x05clsig".to_vec();
    request.extend(height.to_le_bytes());
    let mut sign = vec![kind];
    sign.extend(quorum);
    sign.extend(sha256d(&request));
    sign.extend(block);
    Ok(sha256d(&sign))
}

const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

fn validated_public_key(key: &[u8; 48]) -> Result<PublicKey> {
    // key_validate enforces subgroup membership and rejects infinity.
    let pk = PublicKey::key_validate(key).map_err(|_| "BLS public key")?;
    if pk.compress() != *key {
        return Err("BLS noncanonical public key");
    }
    Ok(pk)
}

pub fn verify_bls(key: &[u8; 48], signature: &[u8; 96], message: &Hash) -> Result<()> {
    let pk = validated_public_key(key)?;
    // true additionally rejects infinity; subgroup membership is always checked.
    let sig = Signature::sig_validate(signature, true).map_err(|_| "BLS signature")?;
    if sig.compress() != *signature {
        return Err("BLS noncanonical signature");
    }
    // Basic/NUL with no augmentation, using the SDK's existing BLS backend.
    // Both inputs were fully validated above, so verification need not repeat it.
    if sig.verify(false, message, BLS_DST, &[], &pk, false) != BLST_ERROR::BLST_SUCCESS {
        return Err("BLS verification");
    }
    Ok(())
}

#[derive(Debug)]
pub struct Commitment {
    pub kind: u8,
    pub quorum_hash: Hash,
    pub public_key: [u8; 48],
}

pub fn parse_commitment(bytes: &[u8]) -> Result<Commitment> {
    let mut r = Reader::new(bytes);
    let version = r.u16()?;
    if version != 3 && version != 4 {
        return Err("unsupported commitment version/scheme");
    }
    let kind = r.u8()?;
    let (size, threshold, rotated) = match kind {
        1 => (50, 30, false),
        2 => (400, 240, false),
        3 => (400, 340, false),
        4 => (100, 67, false),
        5 => (60, 45, true),
        6 => (25, 17, false),
        _ => return Err("unsupported quorum type"),
    };
    if (version == 4) != rotated {
        return Err("commitment rotation version");
    }
    let quorum_hash = r.array()?;
    if rotated && r.u16()? >= 32 {
        return Err("quorum index");
    }
    for _ in 0..2 {
        let bits = r.compact(400)?;
        if bits != size {
            return Err("quorum bit count");
        }
        let packed = r.take(bits.div_ceil(8))?;
        if bits % 8 != 0 && packed[packed.len() - 1] >> (bits % 8) != 0 {
            return Err("bitset padding");
        }
        if packed.iter().map(|b| b.count_ones()).sum::<u32>() < threshold {
            return Err("null/undersized quorum");
        }
    }
    let public_key = r.array()?;
    validated_public_key(&public_key)?;
    if quorum_hash == [0; 32] {
        return Err("null quorum");
    }
    r.take(32 + 96 + 96)?; // vvec hash and BOTH signatures are included in the leaf hash.
    r.finish()?;
    Ok(Commitment {
        kind,
        quorum_hash,
        public_key,
    })
}

/// Parse a complete v3 special coinbase, not a server-selected payload slice.
pub fn coinbase_roots(bytes: &[u8], height: u32) -> Result<(Hash, Hash)> {
    if bytes.len() > MAX_TX {
        return Err("coinbase size");
    }
    let mut r = Reader::new(bytes);
    if r.u16()? != 3 || r.u16()? != 5 {
        return Err("coinbase transaction type/version");
    }
    if r.compact(1)? != 1 || r.array::<32>()? != [0; 32] || r.u32()? != u32::MAX {
        return Err("coinbase input");
    }
    let script_len = r.compact(100)?;
    if script_len == 0 {
        return Err("coinbase script length");
    }
    r.take(script_len)?;
    r.u32()?;
    let outputs = r.compact(4096)?;
    if outputs == 0 {
        return Err("coinbase outputs");
    }
    for _ in 0..outputs {
        r.u64()?;
        let n = r.compact(MAX_TX as u64)?;
        r.take(n)?;
    }
    r.u32()?;
    let n = r.compact(1024)?;
    let mut payload = Reader::new(r.take(n)?);
    r.finish()?;
    if payload.u16()? != 3 || payload.u32()? != height {
        return Err("coinbase payload version/height");
    }
    let mn = payload.array()?;
    let quorums = payload.array()?;
    let diff = payload.compact(u32::MAX as u64)?;
    if diff >= height as usize {
        return Err("coinbase ChainLock height");
    }
    payload.take(96)?;
    payload.u64()?;
    payload.finish()?;
    Ok((mn, quorums))
}

#[cfg(test)]
mod bls_tests {
    use super::*;
    use blst::min_pk::SecretKey;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn rejects_infinity_noncanonical_and_torsion_encodings() {
        let secret = SecretKey::key_gen(&[42u8; 32], &[]).unwrap();
        let key = secret.sk_to_pk().compress();
        let message = [0u8; 32];
        let signature = secret.sign(&message, BLS_DST, &[]).compress();
        verify_bls(&key, &signature, &message).unwrap();
        assert!(verify_bls(&key, &signature, &[1u8; 32]).is_err());
        let mut infinity_key = [0u8; 48];
        infinity_key[0] = 0xc0;
        let mut infinity_signature = [0u8; 96];
        infinity_signature[0] = 0xc0;
        assert!(verify_bls(&infinity_key, &infinity_signature, &message).is_err());
        assert!(verify_bls(&key, &infinity_signature, &message).is_err());
        assert!(verify_bls(&infinity_key, &signature, &message).is_err());
        // (0, 2) lies on G1 but has order 3, outside the prime-order subgroup.
        let mut torsion_key = [0u8; 48];
        torsion_key[0] = 0x80;
        assert!(verify_bls(&torsion_key, &signature, &message).is_err());
        let mut field_modulus: [u8; 48] = hex::decode(
            "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"
        ).unwrap().try_into().unwrap();
        field_modulus[0] |= 0x80;
        assert!(verify_bls(&field_modulus, &signature, &message).is_err());
        assert!(verify_bls(&[0xff; 48], &signature, &message).is_err());
        assert!(verify_bls(&key, &[0xff; 96], &message).is_err());
    }
}
