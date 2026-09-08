use dash_core_proof::{bootstrap, clear::ClearProof, State};

fn fixture() -> ClearProof {
    serde_json::from_str(include_str!("data/short.json")).unwrap()
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn verifies_real_core_history_and_atomic_record_openings() {
    let proof = fixture();
    let bytes = proof.encode().unwrap();
    assert_eq!(bytes.len(), 3469);
    let decoded = ClearProof::decode(&bytes).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("data/short.json")).unwrap();
    let target: State =
        serde_json::from_value(expected["provenance"]["expected_target"].clone()).unwrap();
    assert_eq!(decoded.verify(&proof.anchor).unwrap(), target);
    let envelope = include_bytes!("data/bootstrap.bin");
    assert_eq!(envelope.len(), 4506);
    let verified = bootstrap::verify(envelope, &proof.anchor, target.height).unwrap();
    assert_eq!(verified.state(), &target);
    assert_eq!(verified.records().len(), 2);
    assert!(bootstrap::verify(envelope, &proof.anchor, target.height + 1).is_err());
    let mut wrong = proof.anchor.clone();
    wrong.quorum_root[0] ^= 1;
    assert!(bootstrap::verify(envelope, &wrong, 0).is_err());
    let mut corrupt = envelope.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(bootstrap::verify(&corrupt, &proof.anchor, 0).is_err());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_truncation_retired_format_and_link_tampering() {
    let proof = fixture();
    let bytes = proof.encode().unwrap();
    for n in 0..bytes.len() {
        assert!(ClearProof::decode(&bytes[..n]).is_err(), "truncation {n}");
    }
    let mut old = bytes.clone();
    old[7] = b'1';
    assert!(ClearProof::decode(&old).is_err());
    let mut bad = proof.clone();
    bad.target.signature[0] ^= 1;
    assert!(bad.verify(&fixture().anchor).is_err());
    let mut bad = proof.clone();
    bad.links[1].witness.ancestors.clear();
    assert!(bad.verify(&fixture().anchor).is_err());
    let mut bad = proof.clone();
    bad.target.height = bad.anchor.height;
    assert!(bad.verify(&fixture().anchor).is_err());
    let mut bad = proof;
    bad.seed_commitment[20] ^= 1;
    assert!(bad.verify(&fixture().anchor).is_err());
}
