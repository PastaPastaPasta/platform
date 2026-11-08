//! A sync pass against a wallet that is removed and re-added around it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use drive_proof_verifier::types::{
    ShieldedEncryptedNote, ShieldedEncryptedNotes, ShieldedEncryptedNotesQuery,
};

use super::balance_tests::{register, tree_path};
use super::store::disposition_contract::{arm_reserved, note, spend};
use super::store::{ShieldedSpendDisposition, UnresolvedReason};
use super::sync::pass_pause::{self, Point};
use super::SubwalletId;
use super::{FileBackedShieldedStore, NetworkShieldedCoordinator, OrchardKeySet, ShieldedStore};
use crate::changeset::{
    ClientStartState, PersistenceError, PlatformWalletChangeSet, PlatformWalletPersistence,
    ShieldedChangeSet, ShieldedSubwalletStartState, ShieldedSyncStartState,
};
use crate::wallet::persister::WalletPersister;

/// The chain's notes in this test, by position. None decrypts for any
/// wallet; each carries the nullifier its action spent.
const POOL_SIZE: u64 = 2100;
/// Where the restored note's spend landed.
const SPENT_AT: u64 = 1500;
/// The wallet's live watermark before it is removed: past the spend.
const LIVE_WATERMARK: u64 = 2100;
/// The older snapshot's watermark: before the spend.
const SNAPSHOT_WATERMARK: u64 = 1000;

const WALLET: [u8; 32] = [0x5A; 32];
/// An input whose transition executed: Platform has its nullifier.
const SPENT_NULLIFIER: [u8; 32] = [0x4E; 32];
/// A healthy note nothing holds.
const UNSPENT_NULLIFIER: [u8; 32] = [0x4F; 32];
/// An input whose transition never executed.
const NEVER_SPENT_NULLIFIER: [u8; 32] = [0x50; 32];

fn pool_nullifier(position: u64) -> [u8; 32] {
    if position == SPENT_AT {
        return SPENT_NULLIFIER;
    }
    let mut nullifier = [0xC0; 32];
    nullifier[..8].copy_from_slice(&position.to_le_bytes());
    nullifier
}

fn pool_note(position: u64) -> ShieldedEncryptedNote {
    let mut cmx = [0u8; 32];
    cmx[..8].copy_from_slice(&(position + 1).to_le_bytes());
    ShieldedEncryptedNote {
        cmx: cmx.to_vec(),
        nullifier: pool_nullifier(position).to_vec(),
        cv_net: vec![0; 32],
        encrypted_note: Vec::new(),
    }
}

/// A mock network serving the pool to a pass starting at any chunk.
async fn pool_sdk() -> dash_sdk::Sdk {
    let mut sdk = dash_sdk::Sdk::new_mock();
    let count = 2048
        * u32::from(
            sdk.version()
                .drive_abci
                .query
                .shielded_queries
                .max_query_chunks,
        );
    let notes: Vec<_> = (0..POOL_SIZE).map(pool_note).collect();
    let mut starts = BTreeSet::new();
    for first in (0..POOL_SIZE).step_by(2048) {
        for window in 0..20 {
            starts.insert(first + u64::from(count) * window);
        }
    }
    for start in starts {
        let from = start.min(POOL_SIZE) as usize;
        let to = (start + u64::from(count)).min(POOL_SIZE) as usize;
        sdk.mock()
            .expect_fetch(
                ShieldedEncryptedNotesQuery {
                    start_index: start,
                    count,
                },
                Some(ShieldedEncryptedNotes {
                    notes: notes[from..to].to_vec(),
                    total_count: POOL_SIZE,
                }),
            )
            .await
            .expect("mock pool response");
    }
    sdk
}

async fn unspent(coordinator: &NetworkShieldedCoordinator, id: SubwalletId) -> BTreeSet<[u8; 32]> {
    super::store::disposition_contract::unspent(&*coordinator.store().read().await, id)
}

async fn spendable(coordinator: &NetworkShieldedCoordinator, id: SubwalletId) -> u64 {
    coordinator
        .store()
        .read()
        .await
        .spendable_balance(id)
        .unwrap()
}

fn spent(nullifier: [u8; 32]) -> super::ShieldedNote {
    super::ShieldedNote {
        is_spent: true,
        ..note(nullifier)
    }
}

/// The host's older snapshot of `notes`, scanned up to [`SNAPSHOT_WATERMARK`].
fn older_snapshot(id: SubwalletId, notes: &[super::ShieldedNote]) -> ShieldedSyncStartState {
    ShieldedSyncStartState {
        per_subwallet: BTreeMap::from([(
            id,
            ShieldedSubwalletStartState {
                notes: notes.to_vec(),
                has_sync_state: true,
                last_synced_index: SNAPSHOT_WATERMARK,
                ..Default::default()
            },
        )]),
        ..Default::default()
    }
}

fn coordinator_on(sdk: dash_sdk::Sdk, path: &std::path::Path) -> Arc<NetworkShieldedCoordinator> {
    Arc::new(NetworkShieldedCoordinator::new(
        Arc::new(sdk),
        dashcore::Network::Testnet,
        path.to_path_buf(),
        FileBackedShieldedStore::open_path(path, 100).unwrap(),
    ))
}

fn remove_store_files(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm", ".lock"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let _ = std::fs::remove_file(file);
    }
}

/// A wallet removed while a pass sits between its watermark read and its
/// scan, then re-added from a snapshot older than its live state: the next
/// pass still scans the restored input's spend, which landed between the
/// snapshot's watermark and the live one, and the input is not selectable
/// before that.
#[tokio::test]
async fn a_removal_during_a_pass_leaves_the_restored_spend_scannable() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register(&coordinator, WALLET, &[0]).await;
    coordinator.mark_hydrated(WALLET, true).await;
    {
        let mut store = coordinator.store().write().await;
        let executed = spend(0x61, &[SPENT_NULLIFIER]);
        arm_reserved(&mut *store, id, &executed);
        store
            .resolve_redrive(
                id,
                &executed.activity_id,
                ShieldedSpendDisposition::Executed,
            )
            .unwrap();
        // The live wallet already scanned the spend.
        store.mark_spent(id, &SPENT_NULLIFIER).unwrap();
        store
            .set_last_synced_note_index(id, LIVE_WATERMARK)
            .unwrap();
    }

    let pause = pass_pause::arm(pass_pause::key(coordinator.store()));
    let pass = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.sync(true).await }
    });
    pause.reached.acquire().await.unwrap().forget();
    let mut removal = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.unregister_wallet(WALLET).await }
    });
    let removed_during_pause = tokio::time::timeout(Duration::from_secs(2), &mut removal)
        .await
        .is_ok();
    pause.resume.add_permits(1);
    pass.await.unwrap();
    if !removed_during_pause {
        removal.await.unwrap();
    }

    register(&coordinator, WALLET, &[0]).await;
    coordinator
        .restore_for_wallet(
            WALLET,
            &older_snapshot(id, &[note(SPENT_NULLIFIER), note(UNSPENT_NULLIFIER)]),
        )
        .await
        .unwrap();
    coordinator.mark_hydrated(WALLET, true).await;
    assert_eq!(
        unspent(&coordinator, id).await,
        BTreeSet::from([UNSPENT_NULLIFIER]),
        "the executed input is not selectable before a scan"
    );

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert_eq!(
        unspent(&coordinator, id).await,
        BTreeSet::from([UNSPENT_NULLIFIER]),
        "the spend between the snapshot's watermark and the live one must be scanned"
    );
    assert!(coordinator
        .store()
        .read()
        .await
        .get_all_notes(id)
        .unwrap()
        .iter()
        .any(|stored| stored.nullifier == SPENT_NULLIFIER && stored.is_spent));
    drop(coordinator);
    remove_store_files(&path);
}

/// The host's persister for the wallet: commits each `store` inline and
/// records what it took.
struct Host {
    saved: Mutex<Vec<ShieldedChangeSet>>,
}

impl Host {
    fn inline() -> Arc<Self> {
        Arc::new(Self {
            saved: Mutex::new(Vec::new()),
        })
    }

    /// Whether any changeset the host took touches `id`.
    fn took_any_for(&self, id: SubwalletId) -> bool {
        self.saved.lock().unwrap().iter().any(|changeset| {
            changeset.notes_saved.contains_key(&id)
                || changeset.nullifiers_spent.contains_key(&id)
                || changeset.synced_indices.contains_key(&id)
        })
    }
}

impl PlatformWalletPersistence for Host {
    fn store_commits_inline(&self) -> bool {
        true
    }

    fn store(
        &self,
        _wallet_id: [u8; 32],
        changeset: PlatformWalletChangeSet,
    ) -> Result<(), PersistenceError> {
        if let Some(shielded) = changeset.shielded {
            self.saved.lock().unwrap().push(shielded);
        }
        Ok(())
    }

    fn flush(&self, _wallet_id: [u8; 32]) -> Result<(), PersistenceError> {
        Ok(())
    }

    fn load(&self) -> Result<ClientStartState, PersistenceError> {
        Ok(ClientStartState::default())
    }
}

/// Register [`WALLET`]'s account 0 with `host` as its persister, under the
/// keys `register` uses.
async fn register_with(coordinator: &NetworkShieldedCoordinator, host: &Arc<Host>) {
    let views = BTreeMap::from([(
        0,
        OrchardKeySet::from_seed(&[42; 64], dashcore::Network::Testnet, 0)
            .expect("test viewing key")
            .viewing_keys(),
    )]);
    coordinator
        .register_wallet(WALLET, views, WalletPersister::new(WALLET, host.clone()))
        .await
        .expect("register test wallet");
}

/// Hold the wallet's inputs: an executed spend of [`SPENT_NULLIFIER`] and an
/// unresolved one of [`NEVER_SPENT_NULLIFIER`]. Returns their keys.
async fn hold_inputs(coordinator: &NetworkShieldedCoordinator, id: SubwalletId) -> Vec<[u8; 32]> {
    let mut store = coordinator.store().write().await;
    let mut keys = Vec::new();
    for (redrive, disposition) in [
        (
            spend(0x62, &[SPENT_NULLIFIER]),
            ShieldedSpendDisposition::Executed,
        ),
        (
            spend(0x63, &[NEVER_SPENT_NULLIFIER]),
            ShieldedSpendDisposition::Unresolved(UnresolvedReason::Cancelled),
        ),
    ] {
        arm_reserved(&mut *store, id, &redrive);
        store
            .resolve_redrive(id, &redrive.activity_id, disposition)
            .unwrap();
        keys.push(redrive.st_hash());
    }
    keys
}

/// The older snapshot in which both held inputs and the healthy note are
/// unspent.
fn snapshot_with_inputs_unspent(id: SubwalletId) -> ShieldedSyncStartState {
    older_snapshot(
        id,
        &[
            note(SPENT_NULLIFIER),
            note(NEVER_SPENT_NULLIFIER),
            note(UNSPENT_NULLIFIER),
        ],
    )
}

/// Neither held input is selectable or counted; the healthy note is.
async fn assert_inputs_held(coordinator: &NetworkShieldedCoordinator, id: SubwalletId, why: &str) {
    assert_eq!(
        unspent(coordinator, id).await,
        BTreeSet::from([UNSPENT_NULLIFIER]),
        "{why}"
    );
    assert_eq!(spendable(coordinator, id).await, 1_000, "{why}");
}

/// A pass with an inline host lifts the holds the removal left, so the
/// never-executed input becomes selectable: the holds were still waiting for
/// a scan.
async fn assert_holds_wait_for_a_scan(coordinator: &NetworkShieldedCoordinator, id: SubwalletId) {
    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert_eq!(
        unspent(coordinator, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "the holds still wait for the wallet's next scan"
    );
}

async fn wait_for(pause: &pass_pause::Pause) {
    tokio::time::timeout(Duration::from_secs(60), pause.reached.acquire())
        .await
        .expect("the pass reaches its pause point")
        .unwrap()
        .forget();
}

/// A wallet removed after a pass took its subwallet list but before the pass
/// took the store guard, and optionally added again under the same id and
/// keys before the pass resumes: the pass writes no watermark and lifts no
/// hold for it, and hands its host nothing. Restored from the older snapshot,
/// neither held input is selectable or counted, and the holds still wait for
/// the wallet's next scan.
async fn removal_before_the_pass_guard(re_add_during_the_pause: bool) {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    hold_inputs(&coordinator, id).await;

    let pause = pass_pause::arm_at(
        pass_pause::key(coordinator.store()),
        Point::AfterListSnapshot,
    );
    let pass = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.sync(true).await }
    });
    wait_for(&pause).await;
    tokio::time::timeout(
        Duration::from_secs(60),
        coordinator.unregister_wallet(WALLET),
    )
    .await
    .expect("a removal does not wait for a pass that holds no lock");
    let host = Host::inline();
    if re_add_during_the_pause {
        register_with(&coordinator, &host).await;
    }
    pause.resume.add_permits(1);
    pass.await.unwrap();

    assert_eq!(
        coordinator
            .store()
            .read()
            .await
            .last_synced_note_index(id)
            .unwrap(),
        0,
        "the pass writes no watermark for the removed wallet"
    );
    assert!(
        !host.took_any_for(id),
        "the pass hands the re-added wallet's host nothing"
    );

    if !re_add_during_the_pause {
        register_with(&coordinator, &host).await;
    }
    coordinator
        .restore_for_wallet(WALLET, &snapshot_with_inputs_unspent(id))
        .await
        .unwrap();
    coordinator.mark_hydrated(WALLET, true).await;
    assert_inputs_held(
        &coordinator,
        id,
        "held inputs are not selectable before a pass",
    )
    .await;
    assert_holds_wait_for_a_scan(&coordinator, id).await;
    drop(coordinator);
    remove_store_files(&path);
}

#[tokio::test]
async fn a_removal_before_the_pass_guard_leaves_the_wallet_unscanned() {
    removal_before_the_pass_guard(false).await;
}

#[tokio::test]
async fn a_same_key_re_add_before_the_pass_guard_leaves_the_wallet_unscanned() {
    removal_before_the_pass_guard(true).await;
}

/// A wallet removed and added again from an older host snapshot keeps its
/// inputs held until its first pass: before it, neither the executed input
/// nor the never-executed one is selectable or counted, even beside a
/// healthy note. The pass marks the executed input spent and lifts both
/// holds, so the never-executed input becomes selectable, and it stays so
/// after a reopen.
#[tokio::test]
async fn a_re_added_wallet_keeps_its_holds_until_its_first_pass() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register(&coordinator, WALLET, &[0]).await;
    coordinator.mark_hydrated(WALLET, true).await;
    {
        let mut store = coordinator.store().write().await;
        for (redrive, disposition) in [
            (
                spend(0x62, &[SPENT_NULLIFIER]),
                ShieldedSpendDisposition::Executed,
            ),
            (
                spend(0x63, &[NEVER_SPENT_NULLIFIER]),
                ShieldedSpendDisposition::Unresolved(UnresolvedReason::Cancelled),
            ),
        ] {
            arm_reserved(&mut *store, id, &redrive);
            store
                .resolve_redrive(id, &redrive.activity_id, disposition)
                .unwrap();
        }
    }
    coordinator.unregister_wallet(WALLET).await;

    register(&coordinator, WALLET, &[0]).await;
    let snapshot = older_snapshot(
        id,
        &[
            note(SPENT_NULLIFIER),
            note(NEVER_SPENT_NULLIFIER),
            note(UNSPENT_NULLIFIER),
        ],
    );
    coordinator
        .restore_for_wallet(WALLET, &snapshot)
        .await
        .unwrap();
    coordinator.mark_hydrated(WALLET, true).await;
    assert_eq!(
        unspent(&coordinator, id).await,
        BTreeSet::from([UNSPENT_NULLIFIER]),
        "held inputs are not selectable before the first pass"
    );
    assert_eq!(spendable(&coordinator, id).await, 1_000);

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert_eq!(
        unspent(&coordinator, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "the pass marks the executed input spent and releases the other"
    );
    assert_eq!(spendable(&coordinator, id).await, 2_000);
    let dispositions = coordinator
        .store()
        .read()
        .await
        .dispositions(WALLET)
        .unwrap();
    assert_eq!(dispositions.len(), 2, "the dispositions stay");
    assert!(dispositions
        .iter()
        .all(|record| record.held_nullifiers.is_empty()));
    drop(coordinator);

    let reopened = coordinator_on(dash_sdk::Sdk::new_mock(), &path);
    register(&reopened, WALLET, &[0]).await;
    let host_rows = older_snapshot(
        id,
        &[
            spent(SPENT_NULLIFIER),
            note(NEVER_SPENT_NULLIFIER),
            note(UNSPENT_NULLIFIER),
        ],
    );
    reopened
        .restore_for_wallet(WALLET, &host_rows)
        .await
        .unwrap();
    assert_eq!(
        unspent(&reopened, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "the lifted hold stays lifted after a reopen"
    );
    drop(reopened);
    remove_store_files(&path);
}
