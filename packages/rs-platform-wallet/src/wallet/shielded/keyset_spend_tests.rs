//! The keyset entry points of the shielded transfer and withdrawal.
//!
//! A caller that holds only an account's `OrchardKeySet` (never the seed)
//! spends through [`PlatformWallet::shielded_transfer_to_with_keyset`] and
//! [`PlatformWallet::shielded_withdraw_to_with_keyset`]. Each drives the
//! real path: a bound wallet, a spendable note in a commitment tree, the
//! recorded anchor from the (mock) SDK, a real Halo 2 proof, the
//! coordinator's dispatch hook, then the broadcast.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dpp::serialization::PlatformDeserializableTrusted;
use dpp::state_transition::shielded_transfer_transition::ShieldedTransferTransition;
use dpp::state_transition::shielded_withdrawal_transition::ShieldedWithdrawalTransition;
use dpp::state_transition::StateTransition;
use grovedb_commitment_tree::{ExtractedNoteCommitment, Note, NoteValue, RandomSeed, Rho};

use super::dispatch::{
    DispatchRefused, DispatchedNote, ShieldedDispatch, ShieldedDispatchKind,
    ShieldedDispatchPayload,
};
use super::keys::OrchardKeySet;
use super::store::ShieldedStore;
use super::viewing_key_bind_tests::{
    coordinator_at, platform_wallet_on, temp_dir, CapturingPersistence,
};
use super::{CachedOrchardProver, NetworkShieldedCoordinator, ShieldedNote, SubwalletId};
use crate::error::PlatformWalletError;
use crate::wallet::platform_wallet::{PlatformWallet, WalletId};

const SEED: [u8; 64] = [0x42; 64];
const OTHER_SEED: [u8; 64] = [0x43; 64];
const ACCOUNT: u32 = 0;
const NOTE_VALUE: u64 = 1_000_000_000_000;
const AMOUNT: u64 = 100_000_000;
const MEMO: [u8; 36] = [0; 36];
const CORE_FEE_PER_BYTE: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Transfer,
    Withdraw,
}

const KINDS: [Kind; 2] = [Kind::Transfer, Kind::Withdraw];

impl Kind {
    fn dispatch_kind(self) -> ShieldedDispatchKind {
        match self {
            Kind::Transfer => ShieldedDispatchKind::Transfer,
            Kind::Withdraw => ShieldedDispatchKind::Withdraw,
        }
    }
}

/// What the hook saw at one `dispatch`.
#[derive(Clone, Debug)]
struct Seen {
    payload: ShieldedDispatchPayload,
    /// The durable `unsent` flag of the spend's redrive row while the hook
    /// ran: `Some(true)` means armed and not yet broadcast.
    durable_unsent: Option<bool>,
}

struct TestHook {
    db_path: PathBuf,
    accept: bool,
    seen: Mutex<Vec<Seen>>,
}

impl TestHook {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ShieldedDispatch for TestHook {
    async fn dispatch(&self, payload: ShieldedDispatchPayload) -> Result<(), DispatchRefused> {
        let id = SubwalletId::new(payload.wallet_id, payload.account_index);
        let durable_unsent = durable_unsent(&self.db_path, id, &payload.activity_id);
        self.seen.lock().unwrap().push(Seen {
            payload,
            durable_unsent,
        });
        if self.accept {
            Ok(())
        } else {
            Err(DispatchRefused::new("refused by the test hook"))
        }
    }

    async fn admit(
        &self,
        _wallet_id: WalletId,
        _account_index: u32,
        _activity_id: [u8; 32],
        _st_hash: [u8; 32],
    ) -> Result<(), DispatchRefused> {
        Err(DispatchRefused::new("no rebroadcast in these tests"))
    }
}

/// The durable `unsent` flag of `id`'s redrive row for `activity_id`,
/// read through a connection of its own.
fn durable_unsent(path: &Path, id: SubwalletId, activity_id: &[u8; 32]) -> Option<bool> {
    let conn = rusqlite::Connection::open(path).expect("raw connection");
    conn.query_row(
        "SELECT unsent FROM shielded_pending_spends \
         WHERE wallet_id = ?1 AND account_index = ?2 AND activity_id = ?3",
        rusqlite::params![
            id.wallet_id.as_slice(),
            id.account_index,
            activity_id.as_slice()
        ],
        |row| row.get::<_, bool>(0),
    )
    .ok()
}

fn pending_spend_rows(path: &Path) -> i64 {
    let conn = rusqlite::Connection::open(path).expect("raw connection");
    conn.query_row("SELECT COUNT(*) FROM shielded_pending_spends", [], |row| {
        row.get(0)
    })
    .expect("count pending spends")
}

fn keyset(seed: &[u8], account: u32) -> OrchardKeySet {
    OrchardKeySet::from_seed(seed, dash_sdk::Sdk::new_mock().network, account)
        .expect("ZIP-32 derivation from a fixed seed")
}

/// One real, spendable Orchard note of `keys`' default address, as the
/// wallet stores it after a scan.
fn owned_note(keys: &OrchardKeySet) -> ShieldedNote {
    let rho = (1u16..=u16::MAX)
        .find_map(|n| {
            let mut b = [0u8; 32];
            b[0..2].copy_from_slice(&n.to_le_bytes());
            Rho::from_bytes(&b).into_option()
        })
        .expect("a canonical rho exists");
    let rseed = (1u16..=u16::MAX)
        .find_map(|m| {
            let mut b = [0u8; 32];
            b[2..4].copy_from_slice(&m.to_le_bytes());
            RandomSeed::from_bytes(b, &rho).into_option()
        })
        .expect("a canonical rseed exists");
    let note = Note::from_parts(
        keys.default_address,
        NoteValue::from_raw(NOTE_VALUE),
        rho,
        rseed,
    )
    .into_option()
    .expect("valid note parts");
    let mut note_data = Vec::with_capacity(115);
    note_data.extend_from_slice(&note.recipient().to_raw_address_bytes());
    note_data.extend_from_slice(&note.value().inner().to_le_bytes());
    note_data.extend_from_slice(&note.rho().to_bytes());
    note_data.extend_from_slice(note.rseed().as_bytes());
    ShieldedNote {
        position: 0,
        cmx: ExtractedNoteCommitment::from(note.commitment()).to_bytes(),
        nullifier: note.nullifier(&keys.full_viewing_key).to_bytes(),
        block_height: 1,
        is_spent: false,
        value: NOTE_VALUE,
        note_data,
    }
}

/// A coordinator with `hook` set whose tree holds `note` at a block
/// boundary. Returns the tree's anchor.
async fn hooked_coordinator(
    tag: &str,
    note: &ShieldedNote,
    hook_accepts: bool,
) -> (Arc<NetworkShieldedCoordinator>, Arc<TestHook>, [u8; 32]) {
    let coordinator = coordinator_at(&temp_dir(&format!("keyset_spend_{tag}")));
    let anchor = {
        let mut store = coordinator.store().write().await;
        store.append_commitment(&note.cmx, true).unwrap();
        store.checkpoint_tree(1).unwrap();
        store.tree_anchor().unwrap()
    };
    let hook = Arc::new(TestHook {
        db_path: coordinator.db_path().to_path_buf(),
        accept: hook_accepts,
        seen: Mutex::new(Vec::new()),
    });
    coordinator
        .set_shielded_dispatch(Arc::clone(&hook) as Arc<dyn ShieldedDispatch>)
        .await
        .expect("set the hook");
    (coordinator, hook, anchor)
}

/// A wallet bound to `SEED`'s `ACCOUNT` on `coordinator`, whose SDK reports
/// `anchor` as recorded, holding `note` in each of `stores`.
async fn bound_wallet(
    coordinator: &Arc<NetworkShieldedCoordinator>,
    anchor: [u8; 32],
    note: &ShieldedNote,
    stores: &[&Arc<NetworkShieldedCoordinator>],
) -> (PlatformWallet, Arc<CapturingPersistence>) {
    use dash_sdk::query_types::{NoParamQuery, ShieldedAnchors};
    // Pinned, so the anchor response can't move the protocol version between
    // the fee the spend reserves and the fee its builder applies.
    let mut sdk = dash_sdk::SdkBuilder::new_mock()
        .with_version(dpp::version::PlatformVersion::latest())
        .build()
        .expect("mock sdk");
    sdk.mock()
        .expect_fetch(NoParamQuery {}, Some(ShieldedAnchors(vec![anchor])))
        .await
        .expect("anchor expectation");
    let persister = Arc::new(CapturingPersistence::default());
    let wallet = platform_wallet_on(Arc::clone(&persister), Arc::new(sdk)).await;
    wallet
        .bind_shielded(&SEED, &[ACCOUNT], coordinator)
        .await
        .expect("seed bind");
    let id = SubwalletId::new(wallet.wallet_id(), ACCOUNT);
    for holder in stores {
        holder
            .store()
            .write()
            .await
            .save_note(id, note)
            .expect("save the note");
    }
    (wallet, persister)
}

fn recipient() -> [u8; 43] {
    keyset(&OTHER_SEED, 0)
        .default_address
        .to_raw_address_bytes()
}

fn core_address() -> String {
    let key: dashcore::PublicKey =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .expect("a valid public key");
    dashcore::Address::p2pkh(&key, dash_sdk::Sdk::new_mock().network).to_string()
}

async fn spend_with_keyset(
    wallet: &PlatformWallet,
    coordinator: &Arc<NetworkShieldedCoordinator>,
    keys: &OrchardKeySet,
    account: u32,
    kind: Kind,
) -> Result<(), PlatformWalletError> {
    let prover = CachedOrchardProver::new();
    match kind {
        Kind::Transfer => {
            wallet
                .shielded_transfer_to_with_keyset(
                    coordinator,
                    keys,
                    account,
                    &recipient(),
                    AMOUNT,
                    MEMO,
                    &prover,
                )
                .await
        }
        Kind::Withdraw => {
            wallet
                .shielded_withdraw_to_with_keyset(
                    coordinator,
                    keys,
                    account,
                    &core_address(),
                    AMOUNT,
                    CORE_FEE_PER_BYTE,
                    &prover,
                )
                .await
        }
    }
}

async fn spend_with_seed(
    wallet: &PlatformWallet,
    coordinator: &Arc<NetworkShieldedCoordinator>,
    kind: Kind,
) -> Result<(), PlatformWalletError> {
    let prover = CachedOrchardProver::new();
    match kind {
        Kind::Transfer => {
            wallet
                .shielded_transfer_to(
                    coordinator,
                    &SEED,
                    ACCOUNT,
                    &recipient(),
                    AMOUNT,
                    MEMO,
                    &prover,
                )
                .await
        }
        Kind::Withdraw => {
            wallet
                .shielded_withdraw_to(
                    coordinator,
                    &SEED,
                    ACCOUNT,
                    &core_address(),
                    AMOUNT,
                    CORE_FEE_PER_BYTE,
                    &prover,
                )
                .await
        }
    }
}

/// Nothing of a spend reached the store, the persister or the hook.
async fn assert_nothing_written(
    wallet: &PlatformWallet,
    coordinator: &Arc<NetworkShieldedCoordinator>,
    hook: &TestHook,
    persister: &CapturingPersistence,
    stored_before: usize,
    context: &str,
) {
    let id = SubwalletId::new(wallet.wallet_id(), ACCOUNT);
    {
        let store = coordinator.store().read().await;
        assert!(
            store.pending_redrives(id).unwrap().is_empty(),
            "{context}: no redrive row"
        );
        assert_eq!(
            store.spendable_balance(id).unwrap(),
            NOTE_VALUE,
            "{context}: no note reserved"
        );
        assert!(
            store.dispositions(wallet.wallet_id()).unwrap().is_empty(),
            "{context}: no disposition"
        );
    }
    assert_eq!(
        pending_spend_rows(coordinator.db_path()),
        0,
        "{context}: no pending spend row on disk"
    );
    assert!(hook.seen().is_empty(), "{context}: dispatch never called");
    assert_eq!(
        persister.stored_count(),
        stored_before,
        "{context}: no activity handed to the persister"
    );
}

/// Another seed's keyset for the same account, or the same seed's keyset
/// for another account, is refused with the typed mismatch on both kinds,
/// before anything is reserved, armed, stored or handed to the hook.
#[tokio::test]
async fn a_mismatched_keyset_is_refused_and_writes_nothing() {
    for kind in KINDS {
        for (what, wrong) in [
            ("another seed", keyset(&OTHER_SEED, ACCOUNT)),
            ("another account", keyset(&SEED, ACCOUNT + 1)),
        ] {
            let own = keyset(&SEED, ACCOUNT);
            let note = owned_note(&own);
            let (coordinator, hook, anchor) =
                hooked_coordinator(&format!("mismatch_{kind:?}"), &note, true).await;
            let (wallet, persister) =
                bound_wallet(&coordinator, anchor, &note, &[&coordinator]).await;
            let stored_before = persister.stored_count();

            let result = spend_with_keyset(&wallet, &coordinator, &wrong, ACCOUNT, kind).await;

            assert!(
                matches!(
                    result,
                    Err(PlatformWalletError::ShieldedKeysetMismatch { account: ACCOUNT })
                ),
                "{kind:?} {what}: refused as a keyset mismatch, got {result:?}"
            );
            assert_nothing_written(
                &wallet,
                &coordinator,
                &hook,
                &persister,
                stored_before,
                &format!("{kind:?} {what}"),
            )
            .await;
        }
    }
}

/// The keyset check runs before the recipient is parsed: a mismatched
/// keyset with an unparsable recipient is still refused as a mismatch.
#[tokio::test]
async fn a_mismatched_keyset_is_refused_before_the_recipient_is_parsed() {
    let own = keyset(&SEED, ACCOUNT);
    let note = owned_note(&own);
    let (coordinator, hook, anchor) = hooked_coordinator("mismatch_parse", &note, true).await;
    let (wallet, persister) = bound_wallet(&coordinator, anchor, &note, &[&coordinator]).await;
    let stored_before = persister.stored_count();
    let other = keyset(&OTHER_SEED, ACCOUNT);
    let prover = CachedOrchardProver::new();

    let transfer = wallet
        .shielded_transfer_to_with_keyset(
            &coordinator,
            &other,
            ACCOUNT,
            &[0xFF; 43],
            AMOUNT,
            MEMO,
            &prover,
        )
        .await;
    let withdraw = wallet
        .shielded_withdraw_to_with_keyset(
            &coordinator,
            &other,
            ACCOUNT,
            "not a core address",
            AMOUNT,
            CORE_FEE_PER_BYTE,
            &prover,
        )
        .await;

    for result in [transfer, withdraw] {
        assert!(
            matches!(
                result,
                Err(PlatformWalletError::ShieldedKeysetMismatch { account: ACCOUNT })
            ),
            "refused as a keyset mismatch, got {result:?}"
        );
    }
    assert_nothing_written(
        &wallet,
        &coordinator,
        &hook,
        &persister,
        stored_before,
        "unparsable recipient",
    )
    .await;

    // Control: with the matching keyset, the same recipients fail to parse.
    let transfer = wallet
        .shielded_transfer_to_with_keyset(
            &coordinator,
            &own,
            ACCOUNT,
            &[0xFF; 43],
            AMOUNT,
            MEMO,
            &prover,
        )
        .await;
    let withdraw = wallet
        .shielded_withdraw_to_with_keyset(
            &coordinator,
            &own,
            ACCOUNT,
            "not a core address",
            AMOUNT,
            CORE_FEE_PER_BYTE,
            &prover,
        )
        .await;
    for result in [transfer, withdraw] {
        assert!(
            matches!(result, Err(PlatformWalletError::ShieldedBuildError(_))),
            "an unparsable recipient fails to parse, got {result:?}"
        );
    }
}

/// A wrong seed on the seed wrapper keeps its own error, not the keyset
/// path's mismatch, and writes nothing.
#[tokio::test]
async fn a_wrong_seed_keeps_its_error_on_the_seed_path() {
    for kind in KINDS {
        let own = keyset(&SEED, ACCOUNT);
        let note = owned_note(&own);
        let (coordinator, hook, anchor) =
            hooked_coordinator(&format!("wrong_seed_{kind:?}"), &note, true).await;
        let (wallet, persister) = bound_wallet(&coordinator, anchor, &note, &[&coordinator]).await;
        let stored_before = persister.stored_count();
        let prover = CachedOrchardProver::new();

        let result = match kind {
            Kind::Transfer => {
                wallet
                    .shielded_transfer_to(
                        &coordinator,
                        &OTHER_SEED,
                        ACCOUNT,
                        &recipient(),
                        AMOUNT,
                        MEMO,
                        &prover,
                    )
                    .await
            }
            Kind::Withdraw => {
                wallet
                    .shielded_withdraw_to(
                        &coordinator,
                        &OTHER_SEED,
                        ACCOUNT,
                        &core_address(),
                        AMOUNT,
                        CORE_FEE_PER_BYTE,
                        &prover,
                    )
                    .await
            }
        };
        assert!(
            matches!(
                result,
                Err(PlatformWalletError::ShieldedKeyDerivation(ref message))
                    if message == "seed does not derive the bound viewing key for shielded account 0"
            ),
            "{kind:?}: the seed path's own error, got {result:?}"
        );
        assert_nothing_written(
            &wallet,
            &coordinator,
            &hook,
            &persister,
            stored_before,
            &format!("{kind:?} wrong seed"),
        )
        .await;
    }
}

/// An unbound account, or a wallet with no shielded sub-wallet, is refused
/// on the keyset path with the seed path's errors.
#[tokio::test]
async fn an_unbound_account_is_refused_on_the_keyset_path() {
    for kind in KINDS {
        let own = keyset(&SEED, ACCOUNT);
        let note = owned_note(&own);
        let (coordinator, hook, anchor) =
            hooked_coordinator(&format!("unbound_{kind:?}"), &note, true).await;
        let (wallet, persister) = bound_wallet(&coordinator, anchor, &note, &[&coordinator]).await;
        let stored_before = persister.stored_count();

        let result = spend_with_keyset(&wallet, &coordinator, &keyset(&SEED, 5), 5, kind).await;
        assert!(
            matches!(
                result,
                Err(PlatformWalletError::ShieldedKeyDerivation(ref message))
                    if message == "shielded account 5 not bound"
            ),
            "{kind:?}: unbound account refused, got {result:?}"
        );
        assert_nothing_written(
            &wallet,
            &coordinator,
            &hook,
            &persister,
            stored_before,
            &format!("{kind:?} unbound account"),
        )
        .await;

        let unbound = platform_wallet_on(
            Arc::new(CapturingPersistence::default()),
            Arc::new(dash_sdk::Sdk::new_mock()),
        )
        .await;
        let result = spend_with_keyset(&unbound, &coordinator, &own, ACCOUNT, kind).await;
        assert!(
            matches!(result, Err(PlatformWalletError::ShieldedNotBound)),
            "{kind:?}: unbound wallet refused, got {result:?}"
        );
        assert!(hook.seen().is_empty(), "{kind:?}: dispatch never called");
    }
}

/// `seen`'s artifact is `kind`'s spend of exactly `note` by `wallet`'s
/// `ACCOUNT` against `anchor`, armed and not yet broadcast.
fn assert_artifact(
    seen: &Seen,
    kind: Kind,
    wallet: &PlatformWallet,
    note: &ShieldedNote,
    anchor: [u8; 32],
) {
    let payload = &seen.payload;
    assert_eq!(payload.kind, kind.dispatch_kind(), "{kind:?}: kind");
    assert_eq!(payload.wallet_id, wallet.wallet_id(), "{kind:?}: wallet");
    assert_eq!(payload.account_index, ACCOUNT, "{kind:?}: account");
    assert_eq!(payload.anchor, anchor, "{kind:?}: anchor");
    assert_eq!(
        payload.selected_notes,
        vec![DispatchedNote {
            nullifier: note.nullifier,
            cmx: note.cmx,
            value: note.value,
            position: note.position,
        }],
        "{kind:?}: selected notes"
    );
    assert!(
        payload.published_nullifiers.contains(&note.nullifier),
        "{kind:?}: the note's nullifier is published"
    );
    assert_eq!(
        payload.st_hash,
        dpp::util::hash::hash_single(&payload.st_bytes),
        "{kind:?}: st_hash keys the bytes"
    );
    assert_eq!(
        seen.durable_unsent,
        Some(true),
        "{kind:?}: armed durably and not yet broadcast while the hook ran"
    );
}

/// A matching keyset reaches the hook on both kinds: `dispatch` sees the
/// spend's artifact while it is armed and unsent, and only once it returns
/// `Ok` is the record claimed for broadcast and the transition sent.
#[tokio::test]
async fn a_matching_keyset_reaches_the_hook_before_the_send() {
    for kind in KINDS {
        let own = keyset(&SEED, ACCOUNT);
        let note = owned_note(&own);
        let (coordinator, hook, anchor) =
            hooked_coordinator(&format!("match_{kind:?}"), &note, true).await;
        let (wallet, _persister) = bound_wallet(&coordinator, anchor, &note, &[&coordinator]).await;

        let result = spend_with_keyset(&wallet, &coordinator, &own, ACCOUNT, kind).await;

        let seen = hook.seen();
        assert_eq!(seen.len(), 1, "{kind:?}: one dispatch");
        assert_artifact(&seen[0], kind, &wallet, &note, anchor);
        let id = SubwalletId::new(wallet.wallet_id(), ACCOUNT);
        assert_eq!(
            durable_unsent(coordinator.db_path(), id, &seen[0].payload.activity_id),
            Some(false),
            "{kind:?}: claimed for broadcast after the hook's Ok"
        );
        // The mock SDK has no broadcast expectation, so the send itself is
        // what fails, and it fails as an unconfirmed send.
        assert!(
            matches!(
                result,
                Err(PlatformWalletError::ShieldedSpendUnconfirmed { ref reason, .. })
                    if reason.contains("mock expectation not found")
            ),
            "{kind:?}: the transition was sent after dispatch, got {result:?}"
        );
    }
}

/// The deterministic fields of a transition of `kind`: everything but the
/// proof, the binding signature and the actions, whose order and contents
/// the builder randomizes.
fn deterministic_fields(kind: Kind, st_bytes: &[u8]) -> String {
    let st = StateTransition::deserialize_from_bytes_trusted(st_bytes).expect("decode transition");
    match (kind, st) {
        (Kind::Transfer, StateTransition::ShieldedTransfer(ShieldedTransferTransition::V0(v0))) => {
            format!(
                "transfer actions {} value_balance {} anchor {:?}",
                v0.actions.len(),
                v0.value_balance,
                v0.anchor,
            )
        }
        (
            Kind::Withdraw,
            StateTransition::ShieldedWithdrawal(ShieldedWithdrawalTransition::V0(v0)),
        ) => format!(
            "withdraw actions {} amount {} anchor {:?} core_fee_per_byte {} pooling {:?} \
             output_script {:?}",
            v0.actions.len(),
            v0.unshielding_amount,
            v0.anchor,
            v0.core_fee_per_byte,
            v0.pooling,
            v0.output_script,
        ),
        (kind, st) => panic!("{kind:?}: unexpected transition {st:?}"),
    }
}

/// For the same wallet, account, note, anchor and arguments, the seed
/// wrapper and the keyset path hand the hook the same artifact. The proof,
/// binding signature and output notes are randomized per build, so
/// `st_bytes`, `st_hash`, `activity_id` and the padding nullifier differ;
/// every other payload field and every deterministic transition field match.
#[tokio::test]
async fn the_seed_and_keyset_paths_hand_the_hook_the_same_artifact() {
    for kind in KINDS {
        let own = keyset(&SEED, ACCOUNT);
        let note = owned_note(&own);
        let (by_seed, seed_hook, anchor) =
            hooked_coordinator(&format!("same_seed_{kind:?}"), &note, false).await;
        let (by_keyset, keyset_hook, keyset_anchor) =
            hooked_coordinator(&format!("same_keyset_{kind:?}"), &note, false).await;
        assert_eq!(anchor, keyset_anchor, "the same tree");
        let (wallet, _persister) =
            bound_wallet(&by_seed, anchor, &note, &[&by_seed, &by_keyset]).await;

        let seed_result = spend_with_seed(&wallet, &by_seed, kind).await;
        let keyset_result = spend_with_keyset(&wallet, &by_keyset, &own, ACCOUNT, kind).await;

        for (path, result) in [("seed", &seed_result), ("keyset", &keyset_result)] {
            assert!(
                matches!(
                    result,
                    Err(PlatformWalletError::ShieldedDispatchRefused { .. })
                ),
                "{kind:?} {path}: refused by the hook, got {result:?}"
            );
        }
        let (seed_seen, keyset_seen) = (seed_hook.seen(), keyset_hook.seen());
        assert_eq!(seed_seen.len(), 1, "{kind:?}: seed path dispatched once");
        assert_eq!(
            keyset_seen.len(),
            1,
            "{kind:?}: keyset path dispatched once"
        );
        assert_artifact(&seed_seen[0], kind, &wallet, &note, anchor);
        assert_artifact(&keyset_seen[0], kind, &wallet, &note, anchor);

        let (seed, keyset) = (&seed_seen[0].payload, &keyset_seen[0].payload);
        assert_eq!(seed.kind, keyset.kind, "{kind:?}: kind");
        assert_eq!(seed.wallet_id, keyset.wallet_id, "{kind:?}: wallet");
        assert_eq!(
            seed.account_index, keyset.account_index,
            "{kind:?}: account"
        );
        assert_eq!(seed.anchor, keyset.anchor, "{kind:?}: anchor");
        assert_eq!(
            seed.selected_notes, keyset.selected_notes,
            "{kind:?}: selected notes"
        );
        assert_eq!(
            seed.published_nullifiers.len(),
            keyset.published_nullifiers.len(),
            "{kind:?}: action count"
        );
        assert_eq!(
            deterministic_fields(kind, &seed.st_bytes),
            deterministic_fields(kind, &keyset.st_bytes),
            "{kind:?}: deterministic transition fields"
        );
    }
}
