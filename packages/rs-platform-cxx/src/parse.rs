// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Reads the *intent* out of a raw DPP state transition a dApp handed the
//! wallet (DashConnect `dash-st:` links / QRs).
//!
//! The wallet never signs opaque bytes a web page produced. This module only
//! projects the payload into the fields a user must see before approving;
//! after approval the embedder rebuilds the operation through the normal
//! builders in [`crate::st`], so it only ever signs a transition it
//! constructed itself. There is deliberately no "sign these bytes" entry
//! point in this crate.
//!
//! Two kinds are recognised: an `IdentityUpdateTransition` (DashConnect
//! key registration) and a `BatchTransition` carrying exactly one
//! `TokenDirectPurchase` (a dApp token purchase). Both arrive through the
//! same `dash-st:` channel and are only distinguishable after
//! deserialization, so one parser reports a discriminant instead of making
//! the caller probe kind-specific parsers.

use std::borrow::Cow;

use dpp::identity::identity_public_key::contract_bounds::ContractBounds;
use dpp::serialization::PlatformDeserializable;
use dpp::state_transition::batch_transition::accessors::DocumentsBatchTransitionAccessorsV0;
use dpp::state_transition::batch_transition::batched_transition::token_transition::TokenTransition;
use dpp::state_transition::batch_transition::batched_transition::BatchedTransitionRef;
use dpp::state_transition::batch_transition::token_base_transition::token_base_transition_accessors::TokenBaseTransitionAccessors;
use dpp::state_transition::batch_transition::token_base_transition::v0::v0_methods::TokenBaseTransitionV0Methods;
use dpp::state_transition::batch_transition::token_direct_purchase_transition::v0::v0_methods::TokenDirectPurchaseTransitionV0Methods;
use dpp::state_transition::batch_transition::BatchTransition;
use dpp::state_transition::identity_update_transition::accessors::IdentityUpdateTransitionAccessorsV0;
use dpp::state_transition::identity_update_transition::IdentityUpdateTransition;
use dpp::state_transition::public_key_in_creation::accessors::IdentityPublicKeyInCreationV0Getters;
use dpp::state_transition::{StateTransition, StateTransitionIdentitySigned, StateTransitionOwned};

use crate::types::{
    IdentityKeyToAdd, ParsedIdentityUpdate, ParsedStateTransition, ParsedTokenPurchase,
};

/// Positional bincode variant tag of `StateTransition::Batch`.
pub const BATCH_VARIANT_TAG: u8 = 2;
/// Positional bincode variant tag of `StateTransition::IdentityUpdate`.
pub const IDENTITY_UPDATE_VARIANT_TAG: u8 = 6;

/// Variant tags tried when the payload appears to use a tagless framing.
/// `IdentityUpdate` first: Yappr's key registration sends the bare inner
/// transition (`IdentityUpdateTransition.toBytes()`), while its purchase
/// sends the full `StateTransition`.
const TAGLESS_FRAMING_CANDIDATES: &[(u8, &str)] = &[
    (IDENTITY_UPDATE_VARIANT_TAG, "IdentityUpdate"),
    (BATCH_VARIANT_TAG, "Batch"),
];

/// Deserializes `bytes` as a `StateTransition`, tolerating both normal
/// tagged DPP framing and a tagless inner-transition framing, where the
/// positional bincode enum variant tag has to be prepended first.
///
/// A leading known variant tag usually means the payload is already framed
/// as a state transition, and a tagless body needs a candidate tag
/// prepended. Neither test is conclusive (a tagless body can start with a
/// tag byte by coincidence), so the likelier framing is only tried first and
/// the others are still tried before the payload is rejected.
pub fn deserialize_with_flexible_framing(bytes: &[u8]) -> Result<StateTransition, String> {
    if bytes.is_empty() {
        return Err("state transition bytes are empty".to_string());
    }
    let leads_with_candidate_tag = TAGLESS_FRAMING_CANDIDATES
        .iter()
        .any(|(tag, _)| *tag == bytes[0]);

    let as_is = (Cow::Borrowed(bytes), "as-is".to_string());
    let prepended = TAGLESS_FRAMING_CANDIDATES.iter().map(|(tag, name)| {
        let mut prefixed = Vec::with_capacity(bytes.len() + 1);
        prefixed.push(*tag);
        prefixed.extend_from_slice(bytes);
        (
            Cow::Owned(prefixed),
            format!("{name} variant tag prepended"),
        )
    });

    let mut attempts: Vec<(Cow<'_, [u8]>, String)> = Vec::with_capacity(3);
    if leads_with_candidate_tag {
        attempts.push(as_is);
        attempts.extend(prepended);
    } else {
        attempts.extend(prepended);
        attempts.push(as_is);
    }

    let mut failures = Vec::with_capacity(attempts.len());
    for (payload, label) in &attempts {
        match StateTransition::deserialize_from_bytes(payload) {
            Ok(state_transition) => return Ok(state_transition),
            Err(error) => failures.push(format!("{label}: {error}")),
        }
    }
    Err(format!(
        "unable to deserialize state transition in any supported framing ({})",
        failures.join("; ")
    ))
}

fn key_to_add(
    key: &dpp::state_transition::public_key_in_creation::IdentityPublicKeyInCreation,
) -> IdentityKeyToAdd {
    let (contract_bounds_kind, contract_bounds_id, contract_bounds_document_type) =
        match key.contract_bounds() {
            None => (0, [0u8; 32], String::new()),
            Some(ContractBounds::SingleContract { id }) => (1, id.to_buffer(), String::new()),
            Some(ContractBounds::SingleContractDocumentType {
                id,
                document_type_name,
            }) => (2, id.to_buffer(), document_type_name.clone()),
        };
    IdentityKeyToAdd {
        id: key.id(),
        key_type: key.key_type() as u8,
        purpose: key.purpose() as u8,
        security_level: key.security_level() as u8,
        read_only: key.read_only(),
        data: key.data().to_vec(),
        contract_bounds_kind,
        contract_bounds_id,
        contract_bounds_document_type,
    }
}

fn project_identity_update(transition: &IdentityUpdateTransition) -> ParsedIdentityUpdate {
    ParsedIdentityUpdate {
        identity_id: transition.identity_id().to_buffer(),
        revision: transition.revision(),
        nonce: transition.nonce(),
        add_public_keys: transition
            .public_keys_to_add()
            .iter()
            .map(key_to_add)
            .collect(),
        disable_public_key_ids: transition.public_key_ids_to_disable().to_vec(),
        signature_public_key_id: transition.signature_public_key_id(),
    }
}

/// Projects the single `TokenDirectPurchase` out of `batch`.
///
/// Anything other than exactly one direct purchase is rejected: the approval
/// dialog shows the user one purchase, so a multi-transition or mixed batch
/// would execute more than the user approved, and the rebuild path can only
/// reproduce a single purchase anyway.
fn project_token_purchase(
    batch: &BatchTransition,
    description: &str,
) -> Result<ParsedTokenPurchase, String> {
    let transitions_len = batch.transitions_len();
    if transitions_len != 1 {
        return Err(format!(
            "refusing a batch of {transitions_len} transitions as a token purchase; the user \
             can only approve exactly one TokenDirectPurchase ({description})"
        ));
    }
    let Some(BatchedTransitionRef::Token(TokenTransition::DirectPurchase(purchase))) =
        batch.first_transition()
    else {
        return Err(format!(
            "expected a batch carrying a single TokenDirectPurchase, got {description}"
        ));
    };
    let base = purchase.base();
    // DirectPurchase is not group-gated and the rebuild path submits it
    // without group info, so a payload that smuggles group info in would be
    // approved as one thing and signed as another.
    if base.using_group_info().is_some() {
        return Err(
            "TokenDirectPurchase carries group-action info, which the rebuild-and-sign path \
             does not support"
                .to_string(),
        );
    }
    Ok(ParsedTokenPurchase {
        owner_id: batch.owner_id().to_buffer(),
        data_contract_id: base.data_contract_id().to_buffer(),
        token_id: base.token_id().to_buffer(),
        token_contract_position: base.token_contract_position(),
        token_count: purchase.token_count(),
        total_agreed_price: purchase.total_agreed_price(),
        identity_contract_nonce: base.identity_contract_nonce(),
    })
}

/// Deserializes a raw state transition into its inspectable parts. Does not
/// sign and does not broadcast.
pub fn parse_state_transition(bytes: &[u8]) -> Result<ParsedStateTransition, String> {
    let state_transition = deserialize_with_flexible_framing(bytes)?;
    let description = state_transition.name();
    match &state_transition {
        StateTransition::IdentityUpdate(transition) => Ok(ParsedStateTransition::IdentityUpdate(
            project_identity_update(transition),
        )),
        StateTransition::Batch(batch) => Ok(ParsedStateTransition::TokenDirectPurchase(
            project_token_purchase(batch, &description)?,
        )),
        _ => Err(format!(
            "unsupported state transition kind {description}; only IdentityUpdate and a \
             single TokenDirectPurchase batch can be approved"
        )),
    }
}
