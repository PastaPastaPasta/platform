#![allow(clippy::field_reassign_with_default)]

//! The status-filtered asset-lock reader excludes terminal `Consumed`
//! rows so a spent one-shot lock never resurrects as actionable on
//! rehydration, while the historical row stays on disk.

mod common;

use common::{ensure_wallet_meta, fresh_persister, wid};
use dashcore::hashes::Hash;
use dashcore::{OutPoint, Transaction, Txid};
use key_wallet::wallet::managed_wallet_info::asset_lock_builder::AssetLockFundingType;
use platform_wallet::changeset::{AssetLockChangeSet, AssetLockEntry, PlatformWalletPersistence};
use platform_wallet::wallet::asset_lock::tracked::AssetLockStatus;
use platform_wallet_storage::sqlite::schema::asset_locks;

fn reopen(path: &std::path::Path) -> platform_wallet_storage::SqlitePersister {
    platform_wallet_storage::SqlitePersister::open(
        platform_wallet_storage::SqlitePersisterConfig::new(path),
    )
    .expect("reopen")
}

fn entry(op: OutPoint, status: AssetLockStatus) -> AssetLockEntry {
    AssetLockEntry {
        out_point: op,
        transaction: Transaction {
            version: 3,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        },
        account_index: 0,
        funding_type: AssetLockFundingType::IdentityTopUp,
        identity_index: 0,
        amount_duffs: 1000,
        status,
        proof: None,
    }
}

fn op(b: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([b; 32]),
        vout: 0,
    }
}

/// Store a mix including one terminal `Consumed`. After reopen: the
/// `Consumed` row is still on disk, is absent from the filtered
/// rehydration feed, and non-terminal rows survive.
#[test]
fn rt4_consumed_excluded_from_rehydration_feed() {
    let (persister, _tmp, path) = fresh_persister();
    let w = wid(0xA4);
    ensure_wallet_meta(&persister, &w);

    let op_built = op(0x10);
    let op_cl = op(0x11);
    let op_consumed = op(0x12);
    let mut cs = AssetLockChangeSet::default();
    cs.asset_locks
        .insert(op_built, entry(op_built, AssetLockStatus::Built));
    cs.asset_locks
        .insert(op_cl, entry(op_cl, AssetLockStatus::ChainLocked));
    cs.asset_locks
        .insert(op_consumed, entry(op_consumed, AssetLockStatus::Consumed));
    persister
        .store(
            w,
            platform_wallet::changeset::PlatformWalletChangeSet {
                asset_locks: Some(cs),
                ..Default::default()
            },
        )
        .unwrap();
    drop(persister);

    let p2 = reopen(&path);
    let conn = p2.lock_conn_for_test();

    // (a) the Consumed row is still physically on disk.
    let consumed_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM asset_locks WHERE wallet_id = ?1 AND status = 'consumed'",
            rusqlite::params![w.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(consumed_rows, 1, "Consumed row must persist on disk");

    // Unfiltered reader still returns the Consumed entry...
    let unfiltered =
        asset_locks::load_state(&conn, &w, &platform_wallet_storage::LoadCtx::strict()).unwrap();
    let all_ops: Vec<_> = unfiltered
        .values()
        .flat_map(|m| m.keys().copied())
        .collect();
    assert!(
        all_ops.contains(&op_consumed),
        "unfiltered load_state must still see Consumed (historical)"
    );

    // (b)+(c) the filtered rehydration feed excludes Consumed, keeps
    // the rest.
    let feed = asset_locks::load_unconsumed(&conn, &w, &platform_wallet_storage::LoadCtx::strict())
        .unwrap();
    drop(conn);
    let feed_ops: Vec<_> = feed.values().flat_map(|m| m.keys().copied()).collect();
    assert!(
        !feed_ops.contains(&op_consumed),
        "Consumed must NOT resurrect in the rehydration feed"
    );
    assert!(feed_ops.contains(&op_built), "Built must survive");
    assert!(feed_ops.contains(&op_cl), "ChainLocked must survive");
    assert_eq!(feed_ops.len(), 2);
}

/// An all-consumed wallet yields an empty rehydration feed, no error.
#[test]
fn a2_all_consumed_yields_empty_feed() {
    let (persister, _tmp, path) = fresh_persister();
    let w = wid(0xA5);
    ensure_wallet_meta(&persister, &w);
    let o = op(0x20);
    let mut cs = AssetLockChangeSet::default();
    cs.asset_locks
        .insert(o, entry(o, AssetLockStatus::Consumed));
    persister
        .store(
            w,
            platform_wallet::changeset::PlatformWalletChangeSet {
                asset_locks: Some(cs),
                ..Default::default()
            },
        )
        .unwrap();
    drop(persister);
    let p2 = reopen(&path);
    let conn = p2.lock_conn_for_test();
    let feed = asset_locks::load_unconsumed(&conn, &w, &platform_wallet_storage::LoadCtx::strict())
        .unwrap();
    drop(conn);
    assert!(feed.is_empty(), "all-consumed wallet → empty feed");
}

/// The point read sees a `Consumed` row the rehydration feed drops, keeps
/// it across a reopen, returns a live row's status, and `None` for an
/// outpoint the wallet never stored or another wallet's row.
#[test]
fn asset_lock_status_reads_consumed_rows_after_reopen() {
    let (persister, _tmp, path) = fresh_persister();
    let w = wid(0xA6);
    let other = wid(0xA7);
    ensure_wallet_meta(&persister, &w);
    ensure_wallet_meta(&persister, &other);
    let consumed = op(0x30);
    let live = op(0x31);
    let mut cs = AssetLockChangeSet::default();
    cs.asset_locks
        .insert(consumed, entry(consumed, AssetLockStatus::Consumed));
    cs.asset_locks
        .insert(live, entry(live, AssetLockStatus::InstantSendLocked));
    persister
        .store(
            w,
            platform_wallet::changeset::PlatformWalletChangeSet {
                asset_locks: Some(cs),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        persister.asset_lock_status(&w, &consumed).unwrap(),
        Some(AssetLockStatus::Consumed)
    );
    drop(persister);

    let p2 = reopen(&path);
    assert_eq!(
        p2.asset_lock_status(&w, &consumed).unwrap(),
        Some(AssetLockStatus::Consumed),
        "a consumed row reads back after a reopen"
    );
    assert_eq!(
        p2.asset_lock_status(&w, &live).unwrap(),
        Some(AssetLockStatus::InstantSendLocked)
    );
    assert_eq!(p2.asset_lock_status(&w, &op(0x32)).unwrap(), None);
    assert_eq!(
        p2.asset_lock_status(&other, &consumed).unwrap(),
        None,
        "another wallet's row is not this wallet's"
    );
}

/// Plant a row whose typed status says `consumed` while its lifecycle blob
/// says `Built`.
fn plant_consumed_column_over_built_blob(
    persister: &platform_wallet_storage::SqlitePersister,
    w: &platform_wallet::wallet::platform_wallet::WalletId,
    outpoint: OutPoint,
) {
    use platform_wallet_storage::sqlite::schema::blob;
    ensure_wallet_meta(persister, w);
    let conn = persister.lock_conn_for_test();
    conn.execute(
        "INSERT INTO asset_locks \
            (wallet_id, outpoint, status, account_index, identity_index, amount_duffs, lifecycle_blob) \
         VALUES (?1, ?2, 'consumed', 0, 0, 1000, ?3)",
        rusqlite::params![
            w.as_slice(),
            blob::encode_outpoint(&outpoint).unwrap(),
            asset_locks::encode_entry_for_test(&entry(outpoint, AssetLockStatus::Built)).unwrap()
        ],
    )
    .expect("plant asset-lock status drift");
}

/// Status drift through the point read: Strict refuses it with the named
/// error; Recovery returns the sticky `Consumed` and adds one drift per
/// read to the degradation snapshot.
#[test]
fn should_follow_the_load_policy_when_a_point_read_meets_status_drift() {
    use platform_wallet_storage::{LoadSite, WalletStorageError};
    let w = wid(0xA8);
    let drifted = op(0x40);

    let (strict, _tmp, _path) = fresh_persister();
    plant_consumed_column_over_built_blob(&strict, &w, drifted);
    assert!(matches!(
        strict.asset_lock_status(&w, &drifted),
        Err(WalletStorageError::AssetLockStatusMismatch { .. })
    ));
    assert!(!strict.last_load_degradation().degraded);

    let (recovery, _tmp, _path) = common::fresh_recovery_persister(|strict| {
        plant_consumed_column_over_built_blob(strict, &w, drifted);
    });
    for reads in 1..=2 {
        assert_eq!(
            recovery.asset_lock_status(&w, &drifted).unwrap(),
            Some(AssetLockStatus::Consumed),
            "consumption is sticky"
        );
        let degradation = recovery.last_load_degradation();
        assert!(degradation.degraded);
        assert_eq!(
            degradation
                .by_site
                .get(&LoadSite::AssetLockStatusDrift)
                .copied(),
            Some(reads),
            "{:?}",
            degradation.by_site
        );
        assert_eq!(degradation.total, reads);
    }
}

/// Under `FlushMode::Manual` a stored lock is in the write buffer, not the
/// committed table: the point read sees none until the flush.
#[test]
fn should_not_see_a_buffered_lock_until_its_flush() {
    let (persister, _tmp, _path) = common::fresh_persister_with_mode(common::FlushMode::Manual);
    let w = wid(0xAA);
    ensure_wallet_meta(&persister, &w);
    let buffered = op(0x42);
    let mut cs = AssetLockChangeSet::default();
    cs.asset_locks.insert(
        buffered,
        entry(buffered, AssetLockStatus::InstantSendLocked),
    );
    persister
        .store(
            w,
            platform_wallet::changeset::PlatformWalletChangeSet {
                asset_locks: Some(cs),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(persister.asset_lock_status(&w, &buffered).unwrap(), None);
    persister.flush(w).unwrap();
    assert_eq!(
        persister.asset_lock_status(&w, &buffered).unwrap(),
        Some(AssetLockStatus::InstantSendLocked)
    );
}
