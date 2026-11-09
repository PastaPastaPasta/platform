//! A sync pass against a wallet that is removed and re-added around it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
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
    ClientStartState, PersistenceError, PersistenceErrorKind, PlatformWalletChangeSet,
    PlatformWalletPersistence, ShieldedChangeSet, ShieldedSubwalletStartState,
    ShieldedSyncStartState,
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
/// A snapshot watermark on a chunk boundary, so a pass from it starts there.
const CHUNK_WATERMARK: u64 = 2048;
/// A spend above [`CHUNK_WATERMARK`].
const SPENT_ABOVE_CHUNK: u64 = 2060;

const WALLET: [u8; 32] = [0x5A; 32];
/// An input whose transition executed: Platform has its nullifier.
const SPENT_NULLIFIER: [u8; 32] = [0x4E; 32];
/// A healthy note nothing holds.
const UNSPENT_NULLIFIER: [u8; 32] = [0x4F; 32];
/// An input whose transition never executed.
const NEVER_SPENT_NULLIFIER: [u8; 32] = [0x50; 32];

fn pool_nullifier(position: u64, spent_at: u64) -> [u8; 32] {
    if position == spent_at {
        return SPENT_NULLIFIER;
    }
    let mut nullifier = [0xC0; 32];
    nullifier[..8].copy_from_slice(&position.to_le_bytes());
    nullifier
}

fn pool_note(position: u64, spent_at: u64) -> ShieldedEncryptedNote {
    let mut cmx = [0u8; 32];
    cmx[..8].copy_from_slice(&(position + 1).to_le_bytes());
    ShieldedEncryptedNote {
        cmx: cmx.to_vec(),
        nullifier: pool_nullifier(position, spent_at).to_vec(),
        cv_net: vec![0; 32],
        encrypted_note: Vec::new(),
    }
}

/// A mock network serving the pool, with the spend at [`SPENT_AT`], to a pass
/// starting at any chunk.
async fn pool_sdk() -> dash_sdk::Sdk {
    pool_sdk_from(SPENT_AT, 0).await
}

/// A mock network serving the pool, with the spend at `spent_at`, only to a
/// pass starting at a chunk at or after `first_start`.
async fn pool_sdk_from(spent_at: u64, first_start: u64) -> dash_sdk::Sdk {
    let mut sdk = dash_sdk::Sdk::new_mock();
    let count = 2048
        * u32::from(
            sdk.version()
                .drive_abci
                .query
                .shielded_queries
                .max_query_chunks,
        );
    let notes: Vec<_> = (0..POOL_SIZE)
        .map(|position| pool_note(position, spent_at))
        .collect();
    let mut starts = BTreeSet::new();
    for first in (first_start..POOL_SIZE).step_by(2048) {
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
    snapshot_at(id, notes, SNAPSHOT_WATERMARK)
}

/// The host's snapshot of `notes`, scanned up to `watermark`.
fn snapshot_at(
    id: SubwalletId,
    notes: &[super::ShieldedNote],
    watermark: u64,
) -> ShieldedSyncStartState {
    ShieldedSyncStartState {
        per_subwallet: BTreeMap::from([(
            id,
            ShieldedSubwalletStartState {
                notes: notes.to_vec(),
                has_sync_state: true,
                last_synced_index: watermark,
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

/// The host's persister for the wallet: commits each `store` inline or only
/// buffers it, and can refuse it.
struct Host {
    inline: bool,
    refuse: AtomicBool,
    saved: Mutex<Vec<ShieldedChangeSet>>,
}

impl Host {
    fn inline() -> Arc<Self> {
        Self::new(true)
    }

    fn buffering() -> Arc<Self> {
        Self::new(false)
    }

    fn new(inline: bool) -> Arc<Self> {
        Arc::new(Self {
            inline,
            refuse: AtomicBool::new(false),
            saved: Mutex::new(Vec::new()),
        })
    }

    fn refuse(&self, refuse: bool) {
        self.refuse.store(refuse, Ordering::SeqCst);
    }

    /// Whether any changeset the host took touches `id`.
    fn took_any_for(&self, id: SubwalletId) -> bool {
        self.saved.lock().unwrap().iter().any(|changeset| {
            changeset.notes_saved.contains_key(&id)
                || changeset.nullifiers_spent.contains_key(&id)
                || changeset.synced_indices.contains_key(&id)
        })
    }

    /// Whether the host took `nullifier` as spent for `id`.
    fn took_spent(&self, id: SubwalletId, nullifier: [u8; 32]) -> bool {
        self.saved.lock().unwrap().iter().any(|changeset| {
            changeset
                .nullifiers_spent
                .get(&id)
                .is_some_and(|spent| spent.contains(&nullifier))
        })
    }
}

impl PlatformWalletPersistence for Host {
    fn store_commits_inline(&self) -> bool {
        self.inline
    }

    fn store(
        &self,
        _wallet_id: [u8; 32],
        changeset: PlatformWalletChangeSet,
    ) -> Result<(), PersistenceError> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(PersistenceError::backend_with_kind(
                PersistenceErrorKind::Fatal,
                "the host refused the changeset",
            ));
        }
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
    register_keys(coordinator, host, &[42; 64]).await;
}

/// Register [`WALLET`]'s account 0 with `host` as its persister, under the
/// keys of `seed`.
async fn register_keys(
    coordinator: &NetworkShieldedCoordinator,
    host: &Arc<Host>,
    seed: &[u8; 64],
) {
    let views = BTreeMap::from([(
        0,
        OrchardKeySet::from_seed(seed, dashcore::Network::Testnet, 0)
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

/// Add the wallet again with `host` and restore `snapshot`.
async fn re_add(
    coordinator: &NetworkShieldedCoordinator,
    host: &Arc<Host>,
    snapshot: &ShieldedSyncStartState,
) {
    register_with(coordinator, host).await;
    coordinator
        .restore_for_wallet(WALLET, snapshot)
        .await
        .unwrap();
    coordinator.mark_hydrated(WALLET, true).await;
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

/// A wallet removed and added again under the same keys after a pass marked
/// its holds as scanned and the host took the changeset, but before the
/// lift: the lift skips it, and the holds the removal marked again wait for
/// the re-added wallet's own scan.
#[tokio::test]
async fn a_removal_before_the_scan_lift_keeps_the_holds() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;
    re_add(
        &coordinator,
        &Host::inline(),
        &snapshot_with_inputs_unspent(id),
    )
    .await;

    let pause = pass_pause::arm_at(pass_pause::key(coordinator.store()), Point::BeforeScanLift);
    let pass = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.sync(true).await }
    });
    wait_for(&pause).await;
    coordinator.unregister_wallet(WALLET).await;
    let host = Host::inline();
    register_with(&coordinator, &host).await;
    pause.resume.add_permits(1);
    pass.await.unwrap();

    coordinator
        .restore_for_wallet(WALLET, &snapshot_with_inputs_unspent(id))
        .await
        .unwrap();
    coordinator.mark_hydrated(WALLET, true).await;
    assert_inputs_held(
        &coordinator,
        id,
        "the lift skips a wallet removed since its list",
    )
    .await;
    assert_holds_wait_for_a_scan(&coordinator, id).await;
    drop(coordinator);
    remove_store_files(&path);
}

/// A wallet removed and added again under the same keys after a pass marked
/// its holds as scanned, but before the pass hands its host the changeset:
/// the re-added wallet's host gets nothing from that pass, and the holds the
/// removal marked again wait for the re-added wallet's own scan.
#[tokio::test]
async fn a_removal_before_the_host_save_hands_the_new_host_nothing() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;
    re_add(
        &coordinator,
        &Host::inline(),
        &snapshot_with_inputs_unspent(id),
    )
    .await;

    let pause = pass_pause::arm_at(pass_pause::key(coordinator.store()), Point::BeforeHostSave);
    let pass = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.sync(true).await }
    });
    wait_for(&pause).await;
    coordinator.unregister_wallet(WALLET).await;
    let host = Host::inline();
    re_add(&coordinator, &host, &snapshot_with_inputs_unspent(id)).await;
    pause.resume.add_permits(1);
    pass.await.unwrap();

    assert!(
        !host.took_any_for(id),
        "the pass hands the re-added wallet's host nothing"
    );
    assert_inputs_held(
        &coordinator,
        id,
        "the pass lifts no hold for a wallet removed since its list",
    )
    .await;
    assert_holds_wait_for_a_scan(&coordinator, id).await;
    drop(coordinator);
    remove_store_files(&path);
}

/// A wallet re-added from a snapshot at the tip, so its first pass finds
/// nothing past the snapshot's watermark: the holds the removal left lift
/// when the host commits inline, and stay when it only buffers.
async fn re_add_at_the_tip(host: Arc<Host>) {
    let path = tree_path();
    let id = SubwalletId::new(WALLET, 0);
    {
        let live = coordinator_on(pool_sdk().await, &path);
        register_with(&live, &Host::inline()).await;
        live.mark_hydrated(WALLET, true).await;
        let outcome = live.sync(true).await;
        assert_eq!(outcome.success_count(), 1, "{outcome:?}");
        hold_inputs(&live, id).await;
        live.unregister_wallet(WALLET).await;
    }

    let coordinator = coordinator_on(pool_sdk_from(SPENT_AT, CHUNK_WATERMARK).await, &path);
    let snapshot = snapshot_at(
        id,
        &[
            spent(SPENT_NULLIFIER),
            note(NEVER_SPENT_NULLIFIER),
            note(UNSPENT_NULLIFIER),
        ],
        POOL_SIZE,
    );
    re_add(&coordinator, &host, &snapshot).await;
    assert_inputs_held(
        &coordinator,
        id,
        "held inputs are not selectable before the pass",
    )
    .await;

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert!(!host.took_spent(id, SPENT_NULLIFIER));
    if host.inline {
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
            "an inline host's pass lifts the holds"
        );
    } else {
        assert_inputs_held(&coordinator, id, "a buffering host's pass lifts nothing").await;
    }
    drop(coordinator);
    remove_store_files(&path);
}

#[tokio::test]
async fn a_re_add_at_the_tip_lifts_the_holds_on_an_inline_host() {
    re_add_at_the_tip(Host::inline()).await;
}

#[tokio::test]
async fn a_re_add_at_the_tip_keeps_the_holds_on_a_buffering_host() {
    re_add_at_the_tip(Host::buffering()).await;
}

/// The wallet re-bound under new keys after a pass took its subwallet list
/// but before the pass took the store guard: the pass writes nothing under
/// the old keys, and hands the new registration's host nothing.
#[tokio::test]
async fn a_re_key_before_the_pass_guard_writes_nothing_for_the_old_key() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;

    let pause = pass_pause::arm_at(
        pass_pause::key(coordinator.store()),
        Point::AfterListSnapshot,
    );
    let pass = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.sync(true).await }
    });
    wait_for(&pause).await;
    let host = Host::inline();
    register_keys(&coordinator, &host, &[43; 64]).await;
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
        "the pass writes no watermark under the old key"
    );
    assert!(
        !host.took_any_for(id),
        "the pass hands the new registration's host nothing"
    );
    drop(coordinator);
    remove_store_files(&path);
}

/// A Clear after a pass took its subwallet list but before the pass took the
/// store guard: the pass writes nothing into the reset store, so the wallet
/// bound again after it still starts from index 0. A restore never rewinds a
/// watermark, and the pass's changeset found no persister, so a watermark it
/// wrote would leave the host without the notes below it.
#[tokio::test]
async fn a_clear_before_the_pass_guard_leaves_the_store_reset() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;

    let pause = pass_pause::arm_at(
        pass_pause::key(coordinator.store()),
        Point::AfterListSnapshot,
    );
    let pass = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.sync(true).await }
    });
    wait_for(&pause).await;
    tokio::time::timeout(Duration::from_secs(60), coordinator.clear())
        .await
        .expect("a Clear does not wait for a pass that holds no lock")
        .unwrap();
    pause.resume.add_permits(1);
    pass.await.unwrap();

    register_with(&coordinator, &Host::inline()).await;
    coordinator
        .restore_for_wallet(WALLET, &ShieldedSyncStartState::default())
        .await
        .unwrap();
    {
        let store = coordinator.store().read().await;
        assert_eq!(
            store.last_synced_note_index(id).unwrap(),
            0,
            "the wallet bound again after the Clear starts from index 0"
        );
        assert_eq!(store.tree_size().unwrap(), 0, "the tree stays reset");
    }
    assert!(unspent(&coordinator, id).await.is_empty(), "no stale note");
    drop(coordinator);
    remove_store_files(&path);
}

/// A Clear whose reset fails while a pass that already scanned waits to
/// hand its host the changeset: nothing was reset, so the pass goes on as if
/// there had been no Clear. Its inline host takes the changeset, the holds
/// the pass scanned lift, and the wallet stays registered.
#[tokio::test]
async fn a_failed_clear_leaves_a_scanned_pass_to_save_and_lift() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;
    let host = Host::inline();
    re_add(&coordinator, &host, &snapshot_with_inputs_unspent(id)).await;

    let pause = pass_pause::arm_at(pass_pause::key(coordinator.store()), Point::BeforeHostSave);
    let pass = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.sync(true).await }
    });
    wait_for(&pause).await;
    // The subwallet purge fails on a missing table, so the Clear fails.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("ALTER TABLE shielded_pending_spends RENAME TO unavailable_pending_spends;")
        .unwrap();
    assert!(coordinator.clear().await.is_err());
    conn.execute_batch("ALTER TABLE unavailable_pending_spends RENAME TO shielded_pending_spends;")
        .unwrap();
    drop(conn);
    pause.resume.add_permits(1);
    let outcome = pass.await.unwrap();
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");

    assert!(
        host.took_spent(id, SPENT_NULLIFIER),
        "the host takes the pass's changeset"
    );
    assert_eq!(
        unspent(&coordinator, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "the holds the pass scanned lift"
    );
    assert_eq!(
        coordinator.registered_subwallets().await,
        vec![id],
        "a failed Clear keeps the registration"
    );
    drop(coordinator);
    remove_store_files(&path);
}

/// A pass that starts after a Clear reset the store but before it cleared
/// the registries: it lists the wallets only after the Clear, so it leaves
/// no watermark or commitment in the reset store.
#[tokio::test]
async fn a_pass_listing_during_a_clear_writes_nothing_into_the_reset_store() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;

    let key = pass_pause::key(coordinator.store());
    let reset = pass_pause::arm_at(key, Point::AfterClearReset);
    let clear = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.clear().await }
    });
    wait_for(&reset).await;
    let listed = pass_pause::arm_at(key, Point::AfterListSnapshot);
    let mut pass = Box::pin(coordinator.sync(true));
    // One poll takes the pass as far as it can go now: to its list, unless
    // the Clear still holds `accounts`.
    let polled = std::future::Future::poll(
        pass.as_mut(),
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
    );
    assert!(polled.is_pending());
    let listed_during_the_clear = listed.reached.try_acquire().is_ok();
    reset.resume.add_permits(1);
    clear.await.unwrap().unwrap();
    listed.resume.add_permits(1);
    pass.await;

    assert!(
        !listed_during_the_clear,
        "no pass lists the wallets while the Clear holds them"
    );
    let store = coordinator.store().read().await;
    assert_eq!(
        store.last_synced_note_index(id).unwrap(),
        0,
        "no pass leaves a watermark in the reset store"
    );
    assert_eq!(store.tree_size().unwrap(), 0, "the tree stays reset");
    drop(store);
    drop(coordinator);
    remove_store_files(&path);
}

/// A wallet removed and added again from an older host snapshot keeps its
/// inputs held until its first pass: before it, neither the executed input
/// nor the never-executed one is selectable or counted, even beside a
/// healthy note. The pass marks the executed input spent, and once its host
/// has committed that pass's changeset inline, both holds are lifted, so the
/// never-executed input becomes selectable, and it stays so after a reopen.
#[tokio::test]
async fn a_re_added_wallet_keeps_its_holds_until_its_first_pass() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;

    let host = Host::inline();
    re_add(&coordinator, &host, &snapshot_with_inputs_unspent(id)).await;
    assert_inputs_held(
        &coordinator,
        id,
        "held inputs are not selectable before the first pass",
    )
    .await;

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert!(
        host.took_spent(id, SPENT_NULLIFIER),
        "the host has the executed input's spent state"
    );
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
    register_with(&reopened, &Host::inline()).await;
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

/// After the reopen the host restores the older snapshot again, since it
/// never took the pass's spent state: both inputs are still held.
async fn assert_held_after_a_reopen(path: &std::path::Path, id: SubwalletId) {
    let reopened = coordinator_on(dash_sdk::Sdk::new_mock(), path);
    re_add(
        &reopened,
        &Host::inline(),
        &snapshot_with_inputs_unspent(id),
    )
    .await;
    assert_inputs_held(
        &reopened,
        id,
        "the holds survive a reopen and the old snapshot",
    )
    .await;
    drop(reopened);
}

/// A re-added wallet's first pass scans the executed input spent, but its
/// host refuses the changeset: the holds stay, in session and after a reopen
/// in which the host restores the older snapshot.
#[tokio::test]
async fn a_refused_host_save_keeps_the_scanned_holds() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;
    let host = Host::inline();
    host.refuse(true);
    re_add(&coordinator, &host, &snapshot_with_inputs_unspent(id)).await;

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert!(!host.took_any_for(id));
    assert_inputs_held(&coordinator, id, "a refused save lifts nothing").await;
    drop(coordinator);

    assert_held_after_a_reopen(&path, id).await;
    remove_store_files(&path);
}

/// A re-added wallet's first pass scans the executed input spent, and the
/// process ends before the host gets the changeset: after a reopen in which
/// the host restores the older snapshot, both inputs are still held.
#[tokio::test]
async fn a_crash_before_the_host_save_keeps_the_scanned_holds() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;
    let host = Host::inline();
    re_add(&coordinator, &host, &snapshot_with_inputs_unspent(id)).await;

    let pause = pass_pause::arm_at(pass_pause::key(coordinator.store()), Point::BeforeHostSave);
    let pass = tokio::spawn({
        let coordinator = coordinator.clone();
        async move { coordinator.sync(true).await }
    });
    wait_for(&pause).await;
    pass.abort();
    assert!(pass.await.unwrap_err().is_cancelled());
    assert!(!host.took_any_for(id));
    drop(coordinator);

    assert_held_after_a_reopen(&path, id).await;
    remove_store_files(&path);
}

/// A first pass whose save the host refuses, then a second pass whose save
/// it commits inline: the second pass's changeset does not carry the first
/// pass's spent state, so the holds stay until their dispositions are
/// acknowledged.
#[tokio::test]
async fn a_later_save_leaves_the_holds_an_earlier_pass_scanned() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    let keys = hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;
    let host = Host::inline();
    host.refuse(true);
    re_add(&coordinator, &host, &snapshot_with_inputs_unspent(id)).await;

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    host.refuse(false);
    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert!(
        host.took_any_for(id),
        "the host takes the second pass's changeset"
    );
    assert!(!host.took_spent(id, SPENT_NULLIFIER));
    assert_inputs_held(&coordinator, id, "a later pass's save lifts nothing").await;

    {
        let mut store = coordinator.store().write().await;
        for key in &keys {
            assert!(store.ack_disposition(id, key).unwrap());
        }
    }
    assert_eq!(
        unspent(&coordinator, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "an ack lifts the holds"
    );
    drop(coordinator);
    remove_store_files(&path);
}

/// A host that only buffers the pass's changeset: the scanned holds stay, in
/// session and after a reopen, until their dispositions are acknowledged.
#[tokio::test]
async fn a_buffered_host_save_keeps_the_scanned_holds_until_ack() {
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    let keys = hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;
    let host = Host::buffering();
    re_add(&coordinator, &host, &snapshot_with_inputs_unspent(id)).await;

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert!(host.took_spent(id, SPENT_NULLIFIER));
    assert_inputs_held(&coordinator, id, "a buffered save lifts nothing").await;
    drop(coordinator);

    let reopened = coordinator_on(dash_sdk::Sdk::new_mock(), &path);
    let host_rows = older_snapshot(
        id,
        &[
            spent(SPENT_NULLIFIER),
            note(NEVER_SPENT_NULLIFIER),
            note(UNSPENT_NULLIFIER),
        ],
    );
    re_add(&reopened, &Host::buffering(), &host_rows).await;
    assert_inputs_held(&reopened, id, "the holds survive a reopen").await;
    {
        let mut store = reopened.store().write().await;
        for key in &keys {
            assert!(store.ack_disposition(id, key).unwrap());
        }
    }
    assert_eq!(
        unspent(&reopened, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "an ack lifts the holds"
    );
    drop(reopened);
    remove_store_files(&path);
}

/// A wallet re-added from a snapshot whose watermark sits on a chunk
/// boundary, after the live wallet had scanned the whole pool: its first
/// pass starts at that boundary (the network serves no earlier chunk), scans
/// the executed input's spend above it, and lifts the holds, although the
/// restored inputs were received below it.
#[tokio::test]
async fn a_pass_from_a_restored_chunk_watermark_scans_the_spend_above_it() {
    let path = tree_path();
    let id = SubwalletId::new(WALLET, 0);
    {
        let live = coordinator_on(pool_sdk_from(SPENT_ABOVE_CHUNK, 0).await, &path);
        register_with(&live, &Host::inline()).await;
        live.mark_hydrated(WALLET, true).await;
        let outcome = live.sync(true).await;
        assert_eq!(outcome.success_count(), 1, "{outcome:?}");
        assert_eq!(
            live.store().read().await.tree_size().unwrap(),
            POOL_SIZE,
            "the live wallet scanned the whole pool"
        );
        hold_inputs(&live, id).await;
        live.unregister_wallet(WALLET).await;
    }

    let coordinator = coordinator_on(
        pool_sdk_from(SPENT_ABOVE_CHUNK, CHUNK_WATERMARK).await,
        &path,
    );
    let snapshot = snapshot_at(
        id,
        &[
            note(SPENT_NULLIFIER),
            note(NEVER_SPENT_NULLIFIER),
            note(UNSPENT_NULLIFIER),
        ],
        CHUNK_WATERMARK,
    );
    assert!(snapshot.per_subwallet[&id]
        .notes
        .iter()
        .all(|restored| restored.position < CHUNK_WATERMARK));
    let host = Host::inline();
    re_add(&coordinator, &host, &snapshot).await;
    assert_inputs_held(
        &coordinator,
        id,
        "held inputs are not selectable before the pass",
    )
    .await;

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert!(host.took_spent(id, SPENT_NULLIFIER));
    assert_eq!(
        unspent(&coordinator, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "the spend above the watermark is scanned and the holds lift"
    );
    drop(coordinator);
    remove_store_files(&path);
}

/// A pass over a re-added wallet that holds both the inputs its removal left
/// for the scan and an ordinary input held after the re-add: the pass lifts
/// only the first two, and the ordinary hold stays, also after a reopen.
#[tokio::test]
async fn a_pass_leaves_an_ordinary_hold_on_the_same_subwallet() {
    const ORDINARY_NULLIFIER: [u8; 32] = [0x51; 32];
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    let id = SubwalletId::new(WALLET, 0);
    register_with(&coordinator, &Host::inline()).await;
    coordinator.mark_hydrated(WALLET, true).await;
    hold_inputs(&coordinator, id).await;
    coordinator.unregister_wallet(WALLET).await;
    let host = Host::inline();
    re_add(&coordinator, &host, &snapshot_with_inputs_unspent(id)).await;
    {
        let mut store = coordinator.store().write().await;
        let ordinary = spend(0x64, &[ORDINARY_NULLIFIER]);
        arm_reserved(&mut *store, id, &ordinary);
        store
            .resolve_redrive(
                id,
                &ordinary.activity_id,
                ShieldedSpendDisposition::Unresolved(UnresolvedReason::Cancelled),
            )
            .unwrap();
    }
    assert_inputs_held(&coordinator, id, "every input is held before the pass").await;

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert_eq!(
        unspent(&coordinator, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "the pass lifts the removal's holds and leaves the ordinary one"
    );
    drop(coordinator);

    let reopened = coordinator_on(dash_sdk::Sdk::new_mock(), &path);
    let host_rows = older_snapshot(
        id,
        &[
            spent(SPENT_NULLIFIER),
            note(NEVER_SPENT_NULLIFIER),
            note(UNSPENT_NULLIFIER),
            note(ORDINARY_NULLIFIER),
        ],
    );
    re_add(&reopened, &Host::inline(), &host_rows).await;
    assert_eq!(
        unspent(&reopened, id).await,
        BTreeSet::from([NEVER_SPENT_NULLIFIER, UNSPENT_NULLIFIER]),
        "the ordinary hold stays after a reopen"
    );
    drop(reopened);
    remove_store_files(&path);
}

/// What the coordinator lists and holds for the dispositions the release
/// paths write, across a wallet removal, a dropped account and a Clear, and
/// what an ack frees.
mod release_holds {
    use super::*;
    use crate::wallet::shielded::store::disposition_contract::{
        action_cmx, assert_holds_by_value, spend_with_actions,
    };
    use crate::wallet::shielded::store::PendingRedrive;

    /// An input whose spend was cancelled after a send that may have gone out.
    const CANCELLED_NULLIFIER: [u8; 32] = [0x51; 32];

    /// The only place these tests drive the lift a removal's holds wait for:
    /// a completed pass whose changeset `host` commits inline.
    async fn qualifying_pass(
        coordinator: &NetworkShieldedCoordinator,
        host: &Arc<Host>,
        id: SubwalletId,
    ) {
        assert!(host.inline && !host.refuse.load(Ordering::SeqCst));
        pass(coordinator).await;
        assert!(
            host.took_any_for(id),
            "the host commits the pass's changeset"
        );
    }

    async fn pass(coordinator: &NetworkShieldedCoordinator) {
        let outcome = coordinator.sync(true).await;
        assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    }

    async fn register_accounts(
        coordinator: &NetworkShieldedCoordinator,
        host: &Arc<Host>,
        accounts: &[u32],
    ) {
        let views = accounts
            .iter()
            .map(|account| {
                let keys =
                    OrchardKeySet::from_seed(&[42; 64], dashcore::Network::Testnet, *account)
                        .expect("test viewing key")
                        .viewing_keys();
                (*account, keys)
            })
            .collect();
        coordinator
            .register_wallet(WALLET, views, WalletPersister::new(WALLET, host.clone()))
            .await
            .expect("register test wallet");
        coordinator.mark_hydrated(WALLET, true).await;
    }

    /// A recording coordinator on the pool, with [`WALLET`]'s `accounts`
    /// bound to an inline host.
    async fn recording_coordinator(
        path: &std::path::Path,
        accounts: &[u32],
    ) -> Arc<NetworkShieldedCoordinator> {
        let coordinator = coordinator_on(pool_sdk().await, path);
        coordinator.set_records_spend_dispositions(true).await;
        register_accounts(&coordinator, &Host::inline(), accounts).await;
        coordinator
    }

    /// A scan resolves `id`'s spend of [`SPENT_NULLIFIER`] `Executed` on its
    /// own action's proof. Returns the record.
    async fn executed(coordinator: &NetworkShieldedCoordinator, id: SubwalletId) -> PendingRedrive {
        let redrive = spend_with_actions(0x72, &[SPENT_NULLIFIER]);
        let mut store = coordinator.store().write().await;
        arm_reserved(&mut *store, id, &redrive);
        store
            .resolve_redrives_spending(
                id,
                &SPENT_NULLIFIER,
                Some(&action_cmx(0x72, &SPENT_NULLIFIER)),
            )
            .unwrap();
        redrive
    }

    /// `id`'s spend of [`NEVER_SPENT_NULLIFIER`], left armed for a purge.
    async fn armed(coordinator: &NetworkShieldedCoordinator, id: SubwalletId) -> PendingRedrive {
        let redrive = spend(0x73, &[NEVER_SPENT_NULLIFIER]);
        arm_reserved(&mut *coordinator.store().write().await, id, &redrive);
        redrive
    }

    async fn assert_listed(
        coordinator: &NetworkShieldedCoordinator,
        expected: &[(&PendingRedrive, ShieldedSpendDisposition)],
    ) {
        let records = coordinator.spend_dispositions(WALLET).await.unwrap();
        assert_eq!(records.len(), expected.len());
        for (redrive, disposition) in expected {
            assert!(records
                .iter()
                .any(|record| record.st_hash == redrive.st_hash()
                    && record.disposition == *disposition));
        }
        let redrives: Vec<_> = expected.iter().map(|(redrive, _)| *redrive).collect();
        assert_holds_by_value(&records, &redrives);
    }

    async fn ack(
        coordinator: &NetworkShieldedCoordinator,
        id: SubwalletId,
        redrive: &PendingRedrive,
    ) {
        assert!(coordinator
            .ack_spend_disposition(WALLET, id.account_index, &redrive.st_hash())
            .await
            .unwrap());
    }

    fn inputs_unspent(id: SubwalletId, watermark: u64) -> ShieldedSyncStartState {
        snapshot_at(
            id,
            &[
                note(SPENT_NULLIFIER),
                note(NEVER_SPENT_NULLIFIER),
                note(CANCELLED_NULLIFIER),
                note(UNSPENT_NULLIFIER),
            ],
            watermark,
        )
    }

    /// Removed with an `Executed`, a `Cancelled` and an armed record, which the
    /// removal writes `Purged`, then added again under the same id from an
    /// older snapshot: before a pass every row is listed and holds its input,
    /// only the healthy note is selectable or counted, and a row can be
    /// acknowledged. A qualifying pass decides the executed input: it is
    /// spent and its row holds nothing. The purged spend may still land, so
    /// its input stays held across the pass until its row is acknowledged.
    #[tokio::test]
    async fn a_removed_wallets_rows_hold_until_a_qualifying_pass_decides() {
        let path = tree_path();
        let id = SubwalletId::new(WALLET, 0);
        let coordinator = recording_coordinator(&path, &[0]).await;
        let executed = executed(&coordinator, id).await;
        let purged = armed(&coordinator, id).await;
        let cancelled = spend(0x74, &[CANCELLED_NULLIFIER]);
        {
            let mut store = coordinator.store().write().await;
            arm_reserved(&mut *store, id, &cancelled);
            store
                .resolve_redrive(
                    id,
                    &cancelled.activity_id,
                    ShieldedSpendDisposition::Unresolved(UnresolvedReason::Cancelled),
                )
                .unwrap();
        }
        coordinator.unregister_wallet(WALLET).await;
        let rows = [
            (&executed, ShieldedSpendDisposition::Executed),
            (
                &purged,
                ShieldedSpendDisposition::Unresolved(UnresolvedReason::Purged),
            ),
            (
                &cancelled,
                ShieldedSpendDisposition::Unresolved(UnresolvedReason::Cancelled),
            ),
        ];
        assert_listed(&coordinator, &rows).await;

        let host = Host::inline();
        re_add(&coordinator, &host, &inputs_unspent(id, SNAPSHOT_WATERMARK)).await;
        assert_listed(&coordinator, &rows).await;
        assert_inputs_held(&coordinator, id, "held inputs before any pass").await;
        ack(&coordinator, id, &cancelled).await;
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([CANCELLED_NULLIFIER, UNSPENT_NULLIFIER]),
            "an ack frees a removed wallet's row before any pass"
        );

        qualifying_pass(&coordinator, &host, id).await;
        assert!(host.took_spent(id, SPENT_NULLIFIER));
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([CANCELLED_NULLIFIER, UNSPENT_NULLIFIER]),
            "the scan decides the executed input; the purged one stays held"
        );
        let records = coordinator.spend_dispositions(WALLET).await.unwrap();
        assert_eq!(records.len(), 2, "the rows stay listed");
        for record in &records {
            assert_eq!(
                record.held_nullifiers.is_empty(),
                record.st_hash == executed.st_hash(),
                "{:?}",
                record.disposition
            );
        }
        ack(&coordinator, id, &purged).await;
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([
                NEVER_SPENT_NULLIFIER,
                CANCELLED_NULLIFIER,
                UNSPENT_NULLIFIER
            ]),
            "only the ack frees the purged input"
        );
        drop(coordinator);
        remove_store_files(&path);
    }

    /// The same removal with a host that only buffers the pass's changeset:
    /// the rows keep holding their inputs across the pass, until acknowledged.
    #[tokio::test]
    async fn a_removed_wallets_rows_hold_until_ack_on_a_buffering_host() {
        let path = tree_path();
        let id = SubwalletId::new(WALLET, 0);
        let coordinator = recording_coordinator(&path, &[0]).await;
        let executed = executed(&coordinator, id).await;
        let purged = armed(&coordinator, id).await;
        coordinator.unregister_wallet(WALLET).await;

        let host = Host::buffering();
        re_add(&coordinator, &host, &inputs_unspent(id, SNAPSHOT_WATERMARK)).await;
        pass(&coordinator).await;
        assert!(host.took_spent(id, SPENT_NULLIFIER));
        let rows = [
            (&executed, ShieldedSpendDisposition::Executed),
            (
                &purged,
                ShieldedSpendDisposition::Unresolved(UnresolvedReason::Purged),
            ),
        ];
        assert_listed(&coordinator, &rows).await;
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([CANCELLED_NULLIFIER, UNSPENT_NULLIFIER]),
            "a buffered save lifts nothing"
        );
        ack(&coordinator, id, &executed).await;
        ack(&coordinator, id, &purged).await;
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([
                NEVER_SPENT_NULLIFIER,
                CANCELLED_NULLIFIER,
                UNSPENT_NULLIFIER
            ])
        );
        assert!(coordinator
            .spend_dispositions(WALLET)
            .await
            .unwrap()
            .is_empty());
        drop(coordinator);
        remove_store_files(&path);
    }

    enum Purge {
        DroppedAccount,
        Clear,
    }

    /// An account purged with an `Executed` and an armed record, which the
    /// purge writes `Purged`, by a re-bind that drops it or by a Clear, then
    /// bound again: the rows are listed and hold their inputs across a
    /// qualifying pass, and only an ack frees them.
    async fn a_purged_accounts_rows_hold_until_ack(purge: Purge) {
        let path = tree_path();
        let (id, watermark) = match purge {
            Purge::DroppedAccount => (SubwalletId::new(WALLET, 1), SNAPSHOT_WATERMARK),
            Purge::Clear => (SubwalletId::new(WALLET, 0), 0),
        };
        let coordinator = recording_coordinator(&path, &[0, 1]).await;
        let executed = executed(&coordinator, id).await;
        let purged = armed(&coordinator, id).await;
        match purge {
            Purge::DroppedAccount => register_accounts(&coordinator, &Host::inline(), &[0]).await,
            Purge::Clear => coordinator.clear().await.unwrap(),
        }
        let rows = [
            (&executed, ShieldedSpendDisposition::Executed),
            (
                &purged,
                ShieldedSpendDisposition::Unresolved(UnresolvedReason::Purged),
            ),
        ];
        assert_listed(&coordinator, &rows).await;

        let host = Host::inline();
        register_accounts(&coordinator, &host, &[0, 1]).await;
        coordinator
            .restore_for_wallet(WALLET, &inputs_unspent(id, watermark))
            .await
            .unwrap();
        assert_listed(&coordinator, &rows).await;
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([CANCELLED_NULLIFIER, UNSPENT_NULLIFIER])
        );
        qualifying_pass(&coordinator, &host, id).await;
        assert_listed(&coordinator, &rows).await;
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([CANCELLED_NULLIFIER, UNSPENT_NULLIFIER]),
            "a purge's holds stay across a pass"
        );
        ack(&coordinator, id, &executed).await;
        ack(&coordinator, id, &purged).await;
        assert_eq!(
            unspent(&coordinator, id).await,
            BTreeSet::from([
                NEVER_SPENT_NULLIFIER,
                CANCELLED_NULLIFIER,
                UNSPENT_NULLIFIER
            ]),
            "an ack frees them"
        );
        drop(coordinator);
        remove_store_files(&path);
    }

    #[tokio::test]
    async fn a_dropped_accounts_rows_hold_until_ack() {
        a_purged_accounts_rows_hold_until_ack(Purge::DroppedAccount).await;
    }

    #[tokio::test]
    async fn a_cleared_accounts_rows_hold_until_ack() {
        a_purged_accounts_rows_hold_until_ack(Purge::Clear).await;
    }
}

/// A pass over two wallets in which one wallet's disposition write keeps
/// failing: the other wallet's pass completes (its spend is applied, its
/// watermark advances and its host takes the changeset), while the failing
/// wallet is reported as failed, keeps its watermark and its armed record,
/// and its host takes nothing from the pass. Once the failure clears, its
/// next pass catches up.
#[tokio::test]
async fn a_persistent_disposition_failure_fails_only_its_wallets_pass() {
    const FAILING: [u8; 32] = [0x5B; 32];
    let path = tree_path();
    let coordinator = coordinator_on(pool_sdk().await, &path);
    coordinator.set_records_spend_dispositions(true).await;
    let healthy_id = SubwalletId::new(WALLET, 0);
    let failing_id = SubwalletId::new(FAILING, 0);
    let healthy_host = Host::inline();
    let failing_host = Host::inline();
    for (wallet_id, host) in [(WALLET, &healthy_host), (FAILING, &failing_host)] {
        let views = BTreeMap::from([(
            0,
            OrchardKeySet::from_seed(&[42; 64], dashcore::Network::Testnet, 0)
                .expect("test viewing key")
                .viewing_keys(),
        )]);
        coordinator
            .register_wallet(
                wallet_id,
                views,
                WalletPersister::new(wallet_id, host.clone()),
            )
            .await
            .expect("register test wallet");
        coordinator.mark_hydrated(wallet_id, true).await;
    }
    let healthy_spend = spend(0x91, &[SPENT_NULLIFIER]);
    let failing_spend = spend(0x92, &[SPENT_NULLIFIER]);
    {
        let mut store = coordinator.store().write().await;
        arm_reserved(&mut *store, healthy_id, &healthy_spend);
        arm_reserved(&mut *store, failing_id, &failing_spend);
        store.fail_disposition_write_for(&failing_spend.activity_id, true);
    }

    for _ in 0..2 {
        let outcome = coordinator.sync(true).await;
        assert!(
            matches!(
                outcome.wallet_results.get(&WALLET),
                Some(crate::manager::shielded_sync::WalletShieldedOutcome::Ok(_))
            ),
            "{outcome:?}"
        );
        assert!(
            matches!(
                outcome.wallet_results.get(&FAILING),
                Some(crate::manager::shielded_sync::WalletShieldedOutcome::Err(_))
            ),
            "{outcome:?}"
        );
        let store = coordinator.store().read().await;
        assert_eq!(store.last_synced_note_index(healthy_id).unwrap(), POOL_SIZE);
        assert!(store.pending_redrives(healthy_id).unwrap().is_empty());
        assert_eq!(store.last_synced_note_index(failing_id).unwrap(), 0);
        assert_eq!(
            store.pending_redrives(failing_id).unwrap(),
            vec![failing_spend.clone()]
        );
        drop(store);
        assert!(healthy_host.took_spent(healthy_id, SPENT_NULLIFIER));
        assert!(
            !failing_host.took_any_for(failing_id),
            "the failing wallet's host takes nothing of the pass"
        );
    }

    coordinator
        .store()
        .read()
        .await
        .fail_disposition_write_for(&failing_spend.activity_id, false);
    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 2, "{outcome:?}");
    assert!(failing_host.took_spent(failing_id, SPENT_NULLIFIER));
    assert_eq!(
        coordinator
            .store()
            .read()
            .await
            .last_synced_note_index(failing_id)
            .unwrap(),
        POOL_SIZE
    );
    drop(coordinator);
    remove_store_files(&path);
}
