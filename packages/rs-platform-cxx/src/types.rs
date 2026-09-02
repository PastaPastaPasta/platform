// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Plain-Rust result types shared by the core modules. The cxx bridge in
//! `lib.rs` converts these into the flat shared structs C++ sees.

/// One identity public key, flattened for FFI use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub id: u32,
    pub purpose: u8,
    pub security_level: u8,
    pub key_type: u8,
    pub read_only: bool,
    pub data: Vec<u8>,
    pub disabled_at: Option<u64>,
}

/// Decoded contested-resource vote state (getContestedResourceVoteState,
/// result type VoteTally with locked and abstaining tallies).
#[derive(Debug, Clone, Default)]
pub struct ContestedVoteState {
    pub contest_found: bool,
    /// identity -> votes
    pub contenders: Vec<([u8; 32], Option<u32>)>,
    pub abstain_votes: Option<u32>,
    pub lock_votes: Option<u32>,
    pub finished: bool,
    pub locked: bool,
    pub winner: Option<[u8; 32]>,
    pub finished_at_time_ms: u64,
}

/// Decoded identity.
#[derive(Debug, Clone)]
pub struct IdentityInfo {
    pub id: [u8; 32],
    pub balance: u64,
    pub revision: u64,
    pub keys: Vec<KeyInfo>,
}

/// Decoded DPNS `domain` document fields exposed through this binding.
#[derive(Debug, Clone, Default)]
pub struct DpnsName {
    pub label: String,
    pub normalized_label: String,
    /// normalizedParentDomainName ("dash")
    pub parent_domain: String,
    pub identity: [u8; 32],
    pub document_id: [u8; 32],
    pub owner_id: [u8; 32],
}

/// Decoded DashPay `profile` document.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub document_id: [u8; 32],
    pub owner_id: [u8; 32],
    pub display_name: String,
    pub public_message: String,
    pub avatar_url: String,
    pub avatar_hash: Vec<u8>,
    pub avatar_fingerprint: Vec<u8>,
    pub created_at: u64,
    pub updated_at: u64,
    pub revision: u64,
}

/// Decoded DashPay `contactRequest` document.
#[derive(Debug, Clone, Default)]
pub struct ContactRequest {
    pub document_id: [u8; 32],
    pub owner_id: [u8; 32],
    pub to_user_id: [u8; 32],
    pub encrypted_public_key: Vec<u8>,
    pub sender_key_index: u32,
    pub recipient_key_index: u32,
    pub account_reference: u32,
    pub encrypted_account_label: Vec<u8>,
    pub core_height_created_at: u32,
    pub created_at: u64,
}

/// The authenticated ResponseMetadata fields of a proved DAPI response. The
/// Tenderdash quorum signature covers all of them (they enter the StateId /
/// CanonicalVote sign bytes), so after `FromProof` verification succeeds the
/// C++ freshness tracker can trust them.
#[derive(Debug, Clone, Default)]
pub struct Meta {
    pub height: u64,
    pub core_chain_locked_height: u32,
    pub time_ms: u64,
    pub protocol_version: u32,
    pub chain_id: String,
}

/// One public key an `IdentityUpdateTransition` asks to add, as parsed from
/// a dApp-supplied payload. `contract_bounds_kind`: 0 = none,
/// 1 = single contract, 2 = single contract + document type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeyToAdd {
    pub id: u32,
    pub key_type: u8,
    pub purpose: u8,
    pub security_level: u8,
    pub read_only: bool,
    /// Key data: 33-byte compressed pubkey for ECDSA_SECP256K1, 20-byte
    /// hash for ECDSA_HASH160.
    pub data: Vec<u8>,
    pub contract_bounds_kind: u8,
    pub contract_bounds_id: [u8; 32],
    pub contract_bounds_document_type: String,
}

/// Inspectable fields of a parsed `IdentityUpdateTransition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIdentityUpdate {
    pub identity_id: [u8; 32],
    pub revision: u64,
    pub nonce: u64,
    pub add_public_keys: Vec<IdentityKeyToAdd>,
    pub disable_public_key_ids: Vec<u32>,
    /// Whatever the producer left in the outer signature slot (dApps leave 0).
    pub signature_public_key_id: u32,
}

/// Inspectable fields of a `BatchTransition` carrying exactly one
/// `TokenDirectPurchase`: everything the rebuild needs plus what the user
/// must see (the identity that will be charged and the total price).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTokenPurchase {
    pub owner_id: [u8; 32],
    pub data_contract_id: [u8; 32],
    pub token_id: [u8; 32],
    pub token_contract_position: u16,
    pub token_count: u64,
    /// Credits the owner would agree to pay in total.
    pub total_agreed_price: u64,
    pub identity_contract_nonce: u64,
}

/// A parsed dApp-supplied state transition, discriminated by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedStateTransition {
    IdentityUpdate(ParsedIdentityUpdate),
    TokenDirectPurchase(ParsedTokenPurchase),
}

/// Header of a stored document decoded against a known contract:
/// identifiers, revision and the property map re-encoded as canonical CBOR
/// so the embedder can read it without a DPP dependency.
#[derive(Debug, Clone, Default)]
pub struct StoredDocument {
    pub document_id: [u8; 32],
    pub owner_id: [u8; 32],
    pub revision: u64,
    pub properties_cbor: Vec<u8>,
}

/// A built, signed state transition.
#[derive(Debug, Clone)]
pub struct BuiltTransition {
    /// Serialized signed state transition.
    pub bytes: Vec<u8>,
    /// sha256(bytes) - the wait handle for waitForStateTransitionResult.
    pub hash: [u8; 32],
}

pub fn id32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{what} must be 32 bytes, got {}", bytes.len()))
}
