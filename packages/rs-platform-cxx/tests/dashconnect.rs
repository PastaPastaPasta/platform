// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! DashConnect surface: the `dash-st:` parser and the rebuild builders it
//! feeds (identity update, token direct purchase, generic documents).
//!
//! The parser is exercised round-trip against transitions the builders in
//! this crate produce, in both framings a dApp may send (the full tagged
//! `StateTransition` and the bare inner transition), plus the rejection
//! cases a wallet must never approve. Signatures on the rebuilt transitions
//! are recovered and checked against the vector keys.

use dash_platform_cxx::parse::{self, BATCH_VARIANT_TAG, IDENTITY_UPDATE_VARIANT_TAG};
use dash_platform_cxx::provider;
use dash_platform_cxx::st::{self, IdentityKeyToRegister};
use dash_platform_cxx::types::{KeyInfo, ParsedStateTransition};
use dpp::dashcore::hashes::{sha256, Hash};
use dpp::dashcore::signer as dash_signer;
use dpp::data_contract::accessors::v0::DataContractV0Getters;
use dpp::data_contract::DataContractFactory;
use dpp::platform_value::{platform_value, Identifier, Value};
use dpp::serialization::{PlatformDeserializable, Signable};
use dpp::state_transition::StateTransition;
use platform_version::version::PlatformVersion;
use serde_json::Value as Json;

fn hexv(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("bad hex in test vector")
}

fn hex32(hex: &str) -> [u8; 32] {
    hexv(hex).try_into().expect("expected 32 bytes")
}

fn vectors() -> Json {
    serde_json::from_str(include_str!("../test_data/dpp_st_vectors.json"))
        .expect("parse dpp_st_vectors.json")
}

const OWNER: [u8; 32] = [0x15; 32];
/// Key id of the CRITICAL purchase key the wallet registers (Core layout:
/// 0 MASTER, 1 HIGH, 2 CRITICAL).
const CRITICAL_KEY_ID: u32 = 2;
const CRITICAL_SK: [u8; 32] = [0x44; 32];
/// The app-derived encryption key (registered as a full pubkey, so it must
/// prove ownership) and its id in the identity update.
const ENCRYPTION_KEY_ID: u32 = 4;
const ENCRYPTION_SK: [u8; 32] = [0x55; 32];

fn pubkey(sk: &[u8; 32]) -> Vec<u8> {
    let secp = dpp::dashcore::secp256k1::Secp256k1::new();
    let sk = dpp::dashcore::secp256k1::SecretKey::from_slice(sk).unwrap();
    dpp::dashcore::secp256k1::PublicKey::from_secret_key(&secp, &sk)
        .serialize()
        .to_vec()
}

/// Routes vector keys by identity key id and records the digests signed.
struct TestSigner {
    master_sk: [u8; 32],
    high_sk: [u8; 32],
}

impl TestSigner {
    fn from_vectors(doc: &Json) -> Self {
        TestSigner {
            master_sk: hex32(doc["keys"]["master"]["private_key_hex"].as_str().unwrap()),
            high_sk: hex32(doc["keys"]["high"]["private_key_hex"].as_str().unwrap()),
        }
    }

    fn sign(&self, key_id: u32, digest: [u8; 32]) -> Option<Vec<u8>> {
        let sk = match key_id {
            0 => self.master_sk,
            1 => self.high_sk,
            CRITICAL_KEY_ID => CRITICAL_SK,
            ENCRYPTION_KEY_ID => ENCRYPTION_SK,
            _ => return None,
        };
        dash_signer::sign_hash(&digest, &sk)
            .ok()
            .map(|s| s.to_vec())
    }
}

fn key_info(doc: &Json, id: u32, security_level: u8, data: Vec<u8>) -> KeyInfo {
    let _ = doc;
    KeyInfo {
        id,
        purpose: 0, // AUTHENTICATION
        security_level,
        key_type: 0, // ECDSA_SECP256K1
        read_only: false,
        data,
        disabled_at: None,
    }
}

fn master_key(doc: &Json) -> KeyInfo {
    key_info(
        doc,
        0,
        0,
        hexv(doc["keys"]["master"]["public_key_hex"].as_str().unwrap()),
    )
}

fn high_key(doc: &Json) -> KeyInfo {
    key_info(
        doc,
        1,
        2,
        hexv(doc["keys"]["high"]["public_key_hex"].as_str().unwrap()),
    )
}

fn critical_key(doc: &Json) -> KeyInfo {
    key_info(doc, CRITICAL_KEY_ID, 1, pubkey(&CRITICAL_SK))
}

/// Asserts the outer signature recovers to `expected_pubkey` over the
/// transition's signable bytes.
fn assert_signed_by(bytes: &[u8], expected_pubkey: &[u8], expected_key_id: u32) {
    let st = StateTransition::deserialize_from_bytes(bytes).expect("built bytes deserialize");
    let signable = st.signable_bytes().unwrap();
    let signature = st.signature().expect("signed transition").to_vec();
    dash_signer::verify_data_signature(&signable, &signature, expected_pubkey)
        .expect("outer signature verifies against the expected key");
    assert_eq!(st.signature_public_key_id(), Some(expected_key_id));
}

fn registration_keys() -> Vec<IdentityKeyToRegister> {
    let auth_pubkey = pubkey(&[0x66; 32]);
    vec![
        IdentityKeyToRegister {
            id: 3,
            key_type: 2,       // ECDSA_HASH160
            purpose: 0,        // AUTHENTICATION
            security_level: 2, // HIGH
            read_only: false,
            data: dash_signer::ripemd160_sha256(&auth_pubkey),
        },
        IdentityKeyToRegister {
            id: ENCRYPTION_KEY_ID,
            key_type: 0,       // ECDSA_SECP256K1
            purpose: 1,        // ENCRYPTION
            security_level: 3, // MEDIUM
            read_only: false,
            data: pubkey(&ENCRYPTION_SK),
        },
    ]
}

#[test]
fn identity_update_builds_signs_and_parses() {
    let doc = vectors();
    let signer = TestSigner::from_vectors(&doc);
    let built = st::build_identity_update(
        &OWNER,
        2,
        7,
        &registration_keys(),
        &[],
        &master_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    )
    .expect("build identity update");
    assert_eq!(built.hash, sha256::Hash::hash(&built.bytes).to_byte_array());
    assert_signed_by(
        &built.bytes,
        &hexv(doc["keys"]["master"]["public_key_hex"].as_str().unwrap()),
        0,
    );

    // The encryption key carries an ownership proof by its own key; the
    // hash160 auth key does not (it cannot: the proof would reveal the key).
    let st = StateTransition::deserialize_from_bytes(&built.bytes).unwrap();
    let signable = st.signable_bytes().unwrap();
    let StateTransition::IdentityUpdate(update) = &st else {
        panic!("expected identity update");
    };
    use dpp::state_transition::identity_update_transition::accessors::IdentityUpdateTransitionAccessorsV0;
    use dpp::state_transition::public_key_in_creation::accessors::IdentityPublicKeyInCreationV0Getters;
    let keys = update.public_keys_to_add();
    assert!(
        keys[0].signature().is_empty(),
        "hash160 key must have no proof"
    );
    dash_signer::verify_data_signature(
        &signable,
        keys[1].signature().as_slice(),
        &pubkey(&ENCRYPTION_SK),
    )
    .expect("encryption key proof verifies");

    // Parse round trip, tagged framing.
    let ParsedStateTransition::IdentityUpdate(parsed) =
        parse::parse_state_transition(&built.bytes).expect("parse tagged")
    else {
        panic!("expected identity update");
    };
    assert_eq!(parsed.identity_id, OWNER);
    assert_eq!(parsed.revision, 2);
    assert_eq!(parsed.nonce, 7);
    assert_eq!(parsed.add_public_keys.len(), 2);
    assert_eq!(parsed.add_public_keys[0].key_type, 2);
    assert_eq!(parsed.add_public_keys[0].security_level, 2);
    assert_eq!(parsed.add_public_keys[1].purpose, 1);
    assert_eq!(parsed.add_public_keys[1].data, pubkey(&ENCRYPTION_SK));
    assert!(parsed.disable_public_key_ids.is_empty());

    // Tagless framing: the bare inner transition, as Yappr sends it.
    assert_eq!(built.bytes[0], IDENTITY_UPDATE_VARIANT_TAG);
    let tagless = &built.bytes[1..];
    let ParsedStateTransition::IdentityUpdate(parsed_tagless) =
        parse::parse_state_transition(tagless).expect("parse tagless")
    else {
        panic!("expected identity update");
    };
    assert_eq!(parsed_tagless, parsed);
}

#[test]
fn identity_update_rejects_non_master_signing_key() {
    let doc = vectors();
    let signer = TestSigner::from_vectors(&doc);
    let err = st::build_identity_update(
        &OWNER,
        2,
        7,
        &registration_keys(),
        &[],
        &high_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    )
    .unwrap_err();
    assert!(
        err.contains("security level") || err.contains("Security"),
        "{err}"
    );
}

#[test]
fn identity_update_rejects_bad_key_data_sizes() {
    let doc = vectors();
    let signer = TestSigner::from_vectors(&doc);
    let mut keys = registration_keys();
    keys[0].data = vec![0u8; 33]; // hash160 key with a 33-byte payload
    let err = st::build_identity_update(
        &OWNER,
        2,
        7,
        &keys,
        &[],
        &master_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    )
    .unwrap_err();
    assert!(err.contains("key data size"), "{err}");
}

const TOKEN_CONTRACT: [u8; 32] = [0x9a; 32];

#[test]
fn token_purchase_builds_signs_and_parses() {
    let doc = vectors();
    let signer = TestSigner::from_vectors(&doc);
    let token_id = dpp::tokens::calculate_token_id(&TOKEN_CONTRACT, 0);
    let built = st::build_token_direct_purchase(
        &OWNER,
        &TOKEN_CONTRACT,
        &token_id,
        0,
        100,
        100_000_000,
        5,
        &critical_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    )
    .expect("build token purchase");
    assert_signed_by(&built.bytes, &pubkey(&CRITICAL_SK), CRITICAL_KEY_ID);

    let ParsedStateTransition::TokenDirectPurchase(parsed) =
        parse::parse_state_transition(&built.bytes).expect("parse tagged")
    else {
        panic!("expected token purchase");
    };
    assert_eq!(parsed.owner_id, OWNER);
    assert_eq!(parsed.data_contract_id, TOKEN_CONTRACT);
    assert_eq!(parsed.token_id, token_id);
    assert_eq!(parsed.token_contract_position, 0);
    assert_eq!(parsed.token_count, 100);
    assert_eq!(parsed.total_agreed_price, 100_000_000);
    assert_eq!(parsed.identity_contract_nonce, 5);

    // Tagless framing of a batch is accepted too.
    assert_eq!(built.bytes[0], BATCH_VARIANT_TAG);
    let ParsedStateTransition::TokenDirectPurchase(parsed_tagless) =
        parse::parse_state_transition(&built.bytes[1..]).expect("parse tagless")
    else {
        panic!("expected token purchase");
    };
    assert_eq!(parsed_tagless, parsed);
}

#[test]
fn token_purchase_rejects_high_key_and_bad_token_id() {
    let doc = vectors();
    let signer = TestSigner::from_vectors(&doc);
    let token_id = dpp::tokens::calculate_token_id(&TOKEN_CONTRACT, 0);
    let err = st::build_token_direct_purchase(
        &OWNER,
        &TOKEN_CONTRACT,
        &token_id,
        0,
        100,
        1,
        5,
        &high_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    )
    .unwrap_err();
    assert!(
        err.contains("security level") || err.contains("Security"),
        "{err}"
    );

    let err = st::build_token_direct_purchase(
        &OWNER,
        &TOKEN_CONTRACT,
        &[0x01; 32],
        0,
        100,
        1,
        5,
        &critical_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    )
    .unwrap_err();
    assert!(err.contains("token id"), "{err}");
}

#[test]
fn parse_rejects_other_kinds_and_garbage() {
    let doc = vectors();
    // A DPNS preorder is a document batch: not something a wallet approves
    // from a dApp.
    let preorder = hexv(doc["dpns_preorder"]["serialized_hex"].as_str().unwrap());
    let err = parse::parse_state_transition(&preorder).unwrap_err();
    assert!(err.contains("TokenDirectPurchase"), "{err}");

    let create = hexv(
        doc["identity_create_chain"]["serialized_hex"]
            .as_str()
            .unwrap(),
    );
    let err = parse::parse_state_transition(&create).unwrap_err();
    assert!(err.contains("unsupported"), "{err}");

    assert!(parse::parse_state_transition(&[]).is_err());
    assert!(parse::parse_state_transition(&[0xff; 40]).is_err());
}

/// The DashConnect key-exchange contract's `loginKeyResponse` type, as
/// deployed by Yappr (contracts/key-exchange-v2.json).
fn key_exchange_contract() -> dpp::data_contract::DataContract {
    let version = PlatformVersion::latest();
    let factory = DataContractFactory::new(version.protocol_version).unwrap();
    let documents = platform_value!({
        "loginKeyResponse": {
            "type": "object",
            "indices": [
                {"name": "byOwnerAndContract", "unique": true,
                 "properties": [{"$ownerId": "asc"}, {"contractId": "asc"}]},
                {"name": "byContractAndEphemeralKey", "unique": true,
                 "properties": [{"contractId": "asc"}, {"appEphemeralPubKeyHash": "asc"}]}
            ],
            "required": ["contractId", "appEphemeralPubKeyHash", "walletEphemeralPubKey",
                         "encryptedPayload", "keyIndex"],
            "additionalProperties": false,
            "properties": {
                "contractId": {"type": "array", "byteArray": true, "minItems": 32, "maxItems": 32,
                               "position": 0, "contentMediaType": "application/x.dash.dpp.identifier"},
                "appEphemeralPubKeyHash": {"type": "array", "byteArray": true, "minItems": 20,
                                           "maxItems": 20, "position": 1},
                "walletEphemeralPubKey": {"type": "array", "byteArray": true, "minItems": 33,
                                          "maxItems": 33, "position": 2},
                "encryptedPayload": {"type": "array", "byteArray": true, "minItems": 60,
                                     "maxItems": 60, "position": 3},
                "keyIndex": {"type": "integer", "minimum": 0, "maximum": 4294967295u32, "position": 4}
            }
        }
    });
    factory
        .create(Identifier::from([0x77; 32]), 1, documents, None, None)
        .expect("create key-exchange contract")
        .data_contract_owned()
}

fn login_key_response_properties() -> Vec<u8> {
    let props = Value::Map(vec![
        (
            Value::Text("contractId".into()),
            Value::Identifier([0xab; 32]),
        ),
        (
            Value::Text("appEphemeralPubKeyHash".into()),
            Value::Bytes(vec![0x11; 20]),
        ),
        (
            Value::Text("walletEphemeralPubKey".into()),
            Value::Bytes(pubkey(&[0x22; 32])),
        ),
        (
            Value::Text("encryptedPayload".into()),
            Value::Bytes(vec![0x33; 60]),
        ),
        (Value::Text("keyIndex".into()), Value::U32(0)),
    ]);
    props.to_cbor_buffer().unwrap()
}

#[test]
fn generic_document_create_and_replace_against_registered_contract() {
    provider::set_context("test", 0).unwrap();
    let doc = vectors();
    let signer = TestSigner::from_vectors(&doc);
    let contract = key_exchange_contract();
    let contract_id = contract.id().to_buffer();

    // The provider is process-global and other tests register the same
    // contract, so the negative case uses an id nothing ever registers.
    let unknown = st::build_generic_document_create(
        &[0xee; 32],
        "loginKeyResponse",
        &OWNER,
        1,
        &login_key_response_properties(),
        &[0x42; 32],
        &high_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    );
    assert!(unknown.unwrap_err().contains("never fetched"));

    provider::register_data_contract(contract.clone());

    let built = st::build_generic_document_create(
        &contract_id,
        "loginKeyResponse",
        &OWNER,
        1,
        &login_key_response_properties(),
        &[0x42; 32],
        &high_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    )
    .expect("build document create");
    assert_signed_by(
        &built.bytes,
        &hexv(doc["keys"]["high"]["public_key_hex"].as_str().unwrap()),
        1,
    );

    let document_id = dpp::document::Document::generate_document_id_v0(
        &contract.id(),
        &Identifier::from(OWNER),
        "loginKeyResponse",
        &[0x42; 32],
    );
    let replaced = st::build_generic_document_replace(
        &contract_id,
        "loginKeyResponse",
        &document_id.to_buffer(),
        &OWNER,
        2,
        2,
        &login_key_response_properties(),
        &high_key(&doc),
        &|key_id, digest| signer.sign(key_id, digest),
    )
    .expect("build document replace");
    assert_signed_by(
        &replaced.bytes,
        &hexv(doc["keys"]["high"]["public_key_hex"].as_str().unwrap()),
        1,
    );
    assert_ne!(built.bytes, replaced.bytes);

    // Neither transition is something the parser lets a wallet approve.
    assert!(parse::parse_state_transition(&built.bytes).is_err());
}

#[test]
fn decode_stored_document_round_trips_properties() {
    use dpp::document::serialization_traits::DocumentPlatformConversionMethodsV0;
    use dpp::document::{Document, DocumentV0};

    provider::set_context("test", 0).unwrap();
    let contract = key_exchange_contract();
    provider::register_data_contract(contract.clone());
    let version = PlatformVersion::latest();
    let document_type = contract.document_type_for_name("loginKeyResponse").unwrap();

    let properties: Vec<(Value, Value)> = {
        let cbor: ciborium::Value =
            ciborium::de::from_reader(login_key_response_properties().as_slice()).unwrap();
        match Value::try_from(cbor).unwrap() {
            Value::Map(map) => map,
            _ => panic!("map"),
        }
    };
    let mut props = std::collections::BTreeMap::new();
    for (k, v) in properties {
        props.insert(k.to_text().unwrap(), v);
    }
    let document = Document::V0(DocumentV0 {
        id: Identifier::from([0x01; 32]),
        owner_id: Identifier::from(OWNER),
        properties: props,
        revision: Some(3),
        ..Default::default()
    });
    let bytes = document
        .serialize(document_type, &contract, version)
        .unwrap();

    let stored = dash_platform_cxx::decode::decode_stored_document(
        &contract.id().to_buffer(),
        "loginKeyResponse",
        &bytes,
    )
    .expect("decode stored document");
    assert_eq!(stored.document_id, [0x01; 32]);
    assert_eq!(stored.owner_id, OWNER);
    assert_eq!(stored.revision, 3);
    let cbor: ciborium::Value =
        ciborium::de::from_reader(stored.properties_cbor.as_slice()).unwrap();
    let ciborium::Value::Map(map) = cbor else {
        panic!("map")
    };
    let key_index = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("keyIndex"))
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(key_index, ciborium::Value::Integer(0.into()));
    let contract_field = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("contractId"))
        .map(|(_, v)| v.clone())
        .unwrap();
    assert_eq!(contract_field, ciborium::Value::Bytes(vec![0xab; 32]));
}
