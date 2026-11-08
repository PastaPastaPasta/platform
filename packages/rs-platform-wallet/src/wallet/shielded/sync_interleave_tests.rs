//! A sync pass against a wallet that is removed and re-added around it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use drive_proof_verifier::types::{
    ShieldedEncryptedNote, ShieldedEncryptedNotes, ShieldedEncryptedNotesQuery,
};

use super::balance_tests::{register, tree_path};
use super::sync::pass_pause;
use super::SubwalletId;
use super::{FileBackedShieldedStore, NetworkShieldedCoordinator, ShieldedNote, ShieldedStore};
use crate::changeset::{ShieldedSubwalletStartState, ShieldedSyncStartState};

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
const SPENT_NULLIFIER: [u8; 32] = [0x4E; 32];
const UNSPENT_NULLIFIER: [u8; 32] = [0x4F; 32];

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

fn owned_note(position: u64, nullifier: [u8; 32], value: u64, is_spent: bool) -> ShieldedNote {
    ShieldedNote {
        position,
        cmx: [position as u8; 32],
        nullifier,
        block_height: 1,
        is_spent,
        value,
        note_data: vec![position as u8; 115],
    }
}

fn unspent_nullifiers(
    coordinator: &NetworkShieldedCoordinator,
    id: SubwalletId,
) -> BTreeSet<[u8; 32]> {
    let store = coordinator.store().try_read().expect("store idle");
    store
        .get_unspent_notes(id)
        .unwrap()
        .into_iter()
        .map(|note| note.nullifier)
        .collect()
}

/// A wallet removed while a pass sits between its watermark read and its
/// scan, then re-added from a snapshot older than its live state: the next
/// pass still scans the restored note's spend, which landed between the
/// snapshot's watermark and the live one.
#[tokio::test]
async fn a_removal_during_a_pass_leaves_the_restored_spend_scannable() {
    let path = tree_path();
    let coordinator = Arc::new(NetworkShieldedCoordinator::new(
        Arc::new(pool_sdk().await),
        dashcore::Network::Testnet,
        path.clone(),
        FileBackedShieldedStore::open_path(&path, 100).unwrap(),
    ));
    let id = SubwalletId::new(WALLET, 0);
    register(&coordinator, WALLET, &[0]).await;
    coordinator.mark_hydrated(WALLET, true).await;
    {
        let mut store = coordinator.store().write().await;
        store
            .save_note(id, &owned_note(5, SPENT_NULLIFIER, 1000, true))
            .unwrap();
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
    let snapshot = ShieldedSyncStartState {
        per_subwallet: BTreeMap::from([(
            id,
            ShieldedSubwalletStartState {
                notes: vec![
                    owned_note(5, SPENT_NULLIFIER, 1000, false),
                    owned_note(6, UNSPENT_NULLIFIER, 300, false),
                ],
                has_sync_state: true,
                last_synced_index: SNAPSHOT_WATERMARK,
                ..Default::default()
            },
        )]),
        ..Default::default()
    };
    coordinator
        .restore_for_wallet(WALLET, &snapshot)
        .await
        .unwrap();
    coordinator.mark_hydrated(WALLET, true).await;

    let outcome = coordinator.sync(true).await;
    assert_eq!(outcome.success_count(), 1, "{outcome:?}");
    assert_eq!(
        unspent_nullifiers(&coordinator, id),
        BTreeSet::from([UNSPENT_NULLIFIER]),
        "the spend between the snapshot's watermark and the live one must be scanned"
    );
    drop(coordinator);
    for suffix in ["", "-wal", "-shm", ".lock"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let _ = std::fs::remove_file(file);
    }
}
