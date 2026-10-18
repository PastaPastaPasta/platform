#![allow(clippy::field_reassign_with_default)]

//! Schema-history-presence and max-version gates must bind to the
//! STAGED copy, not the first source handle.
//!
//! These regression tests pin that a forward-version or
//! schema-history-missing source is rejected AND the live destination
//! is left untouched, closing the validate-then-reopen TOCTOU window.

mod common;

use std::fs;

use common::{ensure_wallet_meta, fresh_persister, ro_conn, wid};
use platform_wallet::changeset::{
    CoreChangeSet, PlatformWalletChangeSet, PlatformWalletPersistence,
};
use platform_wallet_storage::sqlite::migrations::{FORK_HISTORY_TABLE, OLD_FORK_V019_CHECKSUM};
use platform_wallet_storage::{SqlitePersister, SqlitePersisterConfig, WalletStorageError};

fn seed_one_row(persister: &SqlitePersister, w: &[u8; 32]) {
    ensure_wallet_meta(persister, w);
    let mut cs = PlatformWalletChangeSet::default();
    cs.core = Some(CoreChangeSet {
        synced_height: Some(5),
        last_processed_height: Some(5),
        ..Default::default()
    });
    persister.store(*w, cs).unwrap();
}

const SENTINEL: &[u8] = b"do-not-replace-me";

/// A source whose `refinery_schema_history` MAX(version) exceeds the
/// embedded max is rejected and the destination is left untouched.
#[test]
fn forward_version_rejected_destination_unchanged() {
    let (persister, tmp, _path) = fresh_persister();
    seed_one_row(&persister, &wid(0xF0));
    let backup_path = persister.backup_to(tmp.path()).unwrap();
    drop(persister);

    // Bump the staged source past the embedded max so the staged-copy
    // gate must reject it.
    let bumped = 1_000_000i64;
    {
        let conn = rusqlite::Connection::open(&backup_path).unwrap();
        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum) \
             VALUES (?1, 'future', '', '0')",
            rusqlite::params![bumped],
        )
        .unwrap();
    }

    let dest = tmp.path().join("dest.db");
    fs::write(&dest, SENTINEL).unwrap();
    let err = SqlitePersister::restore_from_skip_backup(&dest, &backup_path);
    assert!(
        matches!(
            err,
            Err(WalletStorageError::SchemaVersionUnsupported { .. })
        ),
        "expected SchemaVersionUnsupported, got {err:?}"
    );
    assert_eq!(
        fs::read(&dest).unwrap(),
        SENTINEL,
        "destination must be untouched when the staged copy is rejected"
    );
}

/// The same for the fork's history: a source with fork migrations this
/// build lacks is rejected and the destination is left untouched.
#[test]
fn forward_fork_version_rejected_destination_unchanged() {
    let (persister, tmp, _path) = fresh_persister();
    seed_one_row(&persister, &wid(0xF3));
    let backup_path = persister.backup_to(tmp.path()).unwrap();
    drop(persister);

    {
        let conn = rusqlite::Connection::open(&backup_path).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {FORK_HISTORY_TABLE} (version, name, applied_on, checksum) \
                 VALUES (2, 'future', '', '0')"
            ),
            [],
        )
        .unwrap();
    }

    let dest = tmp.path().join("dest.db");
    fs::write(&dest, SENTINEL).unwrap();
    let err = SqlitePersister::restore_from_skip_backup(&dest, &backup_path);
    assert!(
        matches!(
            err,
            Err(WalletStorageError::ForkSchemaVersionUnsupported {
                found: 2,
                max_supported: 1
            })
        ),
        "expected ForkSchemaVersionUnsupported, got {err:?}"
    );
    assert_eq!(fs::read(&dest).unwrap(), SENTINEL);
}

/// A source whose fork history refinery would refuse to read, or whose fork
/// schema is gone or reshaped, is rejected before it replaces a healthy
/// wallet, which stays byte for byte as it was.
#[test]
fn malformed_fork_history_rejected_healthy_destination_unchanged() {
    // An old fork build's file (fork V1 recorded as upstream V019, no fork
    // history table) whose fork column is gone.
    let old_fork_file_reshaped = format!(
        "DROP TABLE {FORK_HISTORY_TABLE};
         INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
             VALUES (19, 'dashpay_external_rotation', '2026-10-01T00:00:00Z', '{OLD_FORK_V019_CHECKSUM}');
         ALTER TABLE contacts DROP COLUMN external_account_reference;"
    );
    for sql in [
        "UPDATE dw_fork_schema_history SET checksum = 'not_a_u64'",
        "UPDATE dw_fork_schema_history SET applied_on = 'not-a-timestamp'",
        "UPDATE dw_fork_schema_history SET name = 'wrong_name'",
        "UPDATE dw_fork_schema_history SET checksum = '1'",
        "DROP TABLE core_address_pool_retired;
         CREATE TABLE core_address_pool_retired (wallet_id BLOB);",
        &old_fork_file_reshaped,
    ] {
        let (persister, tmp, dest) = fresh_persister();
        seed_one_row(&persister, &wid(0xF4));
        let backup_path = persister.backup_to(tmp.path()).unwrap();
        drop(persister);
        rusqlite::Connection::open(&backup_path)
            .unwrap()
            .execute_batch(sql)
            .unwrap();

        let before = fs::read(&dest).unwrap();
        let err = SqlitePersister::restore_from_skip_backup(&dest, &backup_path);
        assert!(
            matches!(err, Err(WalletStorageError::SchemaHistoryMalformed { .. })),
            "{sql}: expected SchemaHistoryMalformed, got {err:?}"
        );
        assert_eq!(fs::read(&dest).unwrap(), before, "{sql}");
        SqlitePersister::open(platform_wallet_storage::SqlitePersisterConfig::new(&dest))
            .expect("the destination still opens");
    }
}

/// A live WAL source whose committed state is still in its `-wal` (not
/// checkpointed into the main file) restores with that state: staging reads
/// it through SQLite, not as a copy of the main file.
#[test]
fn a_wal_sources_uncheckpointed_commits_are_restored() {
    let w = wid(0xF5);
    let birth_height = |path: &std::path::Path| -> Option<i64> {
        ro_conn(path)
            .query_row(
                "SELECT birth_height FROM wallets WHERE wallet_id = ?1",
                [w.as_slice()],
                |r| r.get(0),
            )
            .ok()
    };
    let (source, tmp, source_path) = fresh_persister();
    seed_one_row(&source, &w);
    drop(source);
    let (dest, _dest_tmp, dest_path) = fresh_persister();
    seed_one_row(&dest, &w);
    drop(dest);
    rusqlite::Connection::open(&dest_path)
        .unwrap()
        .execute("UPDATE wallets SET birth_height = 222", [])
        .unwrap();

    // A writer that keeps its commit in the WAL while the restore runs.
    let writer = rusqlite::Connection::open(&source_path).unwrap();
    let mode: String = writer
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    writer
        .execute_batch("PRAGMA wal_autocheckpoint = 0")
        .unwrap();
    writer
        .execute("UPDATE wallets SET birth_height = 111", [])
        .unwrap();
    let main_file_only = tmp.path().join("main-file-only.db");
    fs::copy(&source_path, &main_file_only).unwrap();
    assert_ne!(
        birth_height(&main_file_only),
        Some(111),
        "the commit is only in the WAL"
    );

    SqlitePersister::restore_from_skip_backup(&dest_path, &source_path).unwrap();
    drop(writer);
    assert_eq!(birth_height(&dest_path), Some(111));
    assert_no_restore_leftovers(dest_path.parent().unwrap());
    SqlitePersister::open(SqlitePersisterConfig::new(&dest_path)).expect("the restored file opens");
}

/// Neither the staged temp, its sidecars nor the proof's copy stay behind.
fn assert_no_restore_leftovers(dir: &std::path::Path) {
    let leftovers: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".restore-proof-") || name.starts_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// Restore accepts what open accepts (DEC-258): a backup whose history
/// passes the restore's checks but whose migrations the open refuses (fork
/// V1's row gone while its schema stays; upstream V1 recorded with another
/// checksum) is refused with the open's own error, and a healthy destination
/// stays byte for byte and still opens.
#[test]
fn a_backup_the_open_would_refuse_is_refused() {
    for sql in [
        format!("DELETE FROM {FORK_HISTORY_TABLE} WHERE version = 1"),
        "UPDATE refinery_schema_history SET checksum = '0' WHERE version = 1".to_string(),
    ] {
        let (persister, tmp, dest) = fresh_persister();
        seed_one_row(&persister, &wid(0xF6));
        let backup_path = persister.backup_to(tmp.path()).unwrap();
        drop(persister);
        rusqlite::Connection::open(&backup_path)
            .unwrap()
            .execute_batch(&sql)
            .unwrap();

        let before = fs::read(&dest).unwrap();
        let err = SqlitePersister::restore_from_skip_backup(&dest, &backup_path);
        assert!(
            matches!(err, Err(WalletStorageError::Migration(_))),
            "{sql}: {err:?}"
        );
        assert_eq!(fs::read(&dest).unwrap(), before, "{sql}");
        assert_no_restore_leftovers(tmp.path());
        SqlitePersister::open(SqlitePersisterConfig::new(&dest)).expect("the destination opens");
    }
}

/// A WAL database restored over itself: the source is closed before the
/// destination's lock, so the restore takes it rather than waiting on its
/// own read.
#[test]
fn a_database_restores_over_itself() {
    let (persister, _tmp, path) = fresh_persister();
    seed_one_row(&persister, &wid(0xF7));
    drop(persister);
    SqlitePersister::restore_from_skip_backup(&path, &path).unwrap();
    let rows: i64 = ro_conn(&path)
        .query_row("SELECT COUNT(*) FROM wallets", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);
}

/// A source lacking `refinery_schema_history` but otherwise
/// integrity-valid is rejected and the destination is left untouched.
#[test]
fn missing_schema_history_rejected_destination_unchanged() {
    let tmp = common::secure_tempdir().unwrap();
    let fake_src = tmp.path().join("empty.db");
    rusqlite::Connection::open(&fake_src).unwrap();

    let dest = tmp.path().join("dest.db");
    fs::write(&dest, SENTINEL).unwrap();
    let err = SqlitePersister::restore_from_skip_backup(&dest, &fake_src);
    assert!(
        matches!(err, Err(WalletStorageError::SchemaHistoryMissing)),
        "expected SchemaHistoryMissing, got {err:?}"
    );
    assert_eq!(
        fs::read(&dest).unwrap(),
        SENTINEL,
        "destination must be untouched when the staged copy is rejected"
    );
}

/// If the staged copy fails its forward-version gate, the
/// destination's `<dest>-wal` / `<dest>-shm` siblings must NOT be
/// unlinked. Deleting them before validation succeeds = un-checkpointed
/// committed pages lost on rollback.
#[test]
fn rejected_restore_leaves_wal_shm_siblings_intact() {
    let (persister, tmp, _path) = fresh_persister();
    seed_one_row(&persister, &wid(0xF1));
    let backup_path = persister.backup_to(tmp.path()).unwrap();
    drop(persister);

    // Bump the source past the embedded max.
    let bumped = 1_000_000i64;
    {
        let conn = rusqlite::Connection::open(&backup_path).unwrap();
        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum) \
             VALUES (?1, 'future', '', '0')",
            rusqlite::params![bumped],
        )
        .unwrap();
    }

    let dest = tmp.path().join("dest.db");
    fs::write(&dest, SENTINEL).unwrap();
    let wal = tmp.path().join("dest.db-wal");
    let shm = tmp.path().join("dest.db-shm");
    fs::write(&wal, b"wal-sentinel").unwrap();
    fs::write(&shm, b"shm-sentinel").unwrap();

    let err = SqlitePersister::restore_from_skip_backup(&dest, &backup_path);
    assert!(
        matches!(
            err,
            Err(WalletStorageError::SchemaVersionUnsupported { .. })
        ),
        "expected SchemaVersionUnsupported, got {err:?}"
    );
    assert_eq!(fs::read(&dest).unwrap(), SENTINEL, "main DB preserved");
    assert!(
        wal.exists(),
        "WAL sibling must NOT be unlinked on rejection"
    );
    assert!(
        shm.exists(),
        "SHM sibling must NOT be unlinked on rejection"
    );
    assert_eq!(fs::read(&wal).unwrap(), b"wal-sentinel");
    assert_eq!(fs::read(&shm).unwrap(), b"shm-sentinel");
}

/// A forward-version source must fail BEFORE the full file is streamed
/// into the destination's parent dir. We assert no
/// NamedTempFile from the staging copy survives in the parent dir
/// after the rejection — the cheap source-side sniff fails fast.
#[test]
fn forward_version_rejected_before_staging() {
    let (persister, tmp, _path) = fresh_persister();
    seed_one_row(&persister, &wid(0xF3));
    let backup_path = persister.backup_to(tmp.path()).unwrap();
    drop(persister);

    // Bump the source past the embedded max.
    {
        let conn = rusqlite::Connection::open(&backup_path).unwrap();
        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum) \
             VALUES (?1, 'future', '', '0')",
            rusqlite::params![1_000_000i64],
        )
        .unwrap();
    }

    let dest_dir = common::secure_tempdir().unwrap();
    let dest = dest_dir.path().join("dest.db");
    fs::write(&dest, SENTINEL).unwrap();

    let before: usize = fs::read_dir(dest_dir.path()).unwrap().count();
    let err = SqlitePersister::restore_from_skip_backup(&dest, &backup_path);
    let after: usize = fs::read_dir(dest_dir.path()).unwrap().count();

    assert!(
        matches!(
            err,
            Err(WalletStorageError::SchemaVersionUnsupported { .. })
        ),
        "expected SchemaVersionUnsupported, got {err:?}"
    );
    assert_eq!(
        after, before,
        "no staging temp file should be left behind on pre-staging rejection"
    );
}

/// Happy path: a valid in-range backup still restores and the
/// destination reflects the restored bytes.
#[test]
fn valid_backup_roundtrips() {
    let (persister, tmp, path) = fresh_persister();
    let w = wid(0xF2);
    seed_one_row(&persister, &w);
    let backup_path = persister.backup_to(tmp.path()).unwrap();
    let mut cs = PlatformWalletChangeSet::default();
    cs.core = Some(CoreChangeSet {
        synced_height: Some(999),
        last_processed_height: Some(999),
        ..Default::default()
    });
    persister.store(w, cs).unwrap();
    drop(persister);

    SqlitePersister::restore_from_skip_backup(&path, &backup_path).expect("restore_from");

    let cfg = platform_wallet_storage::SqlitePersisterConfig::new(&path);
    let p2 = SqlitePersister::open(cfg).unwrap();
    let conn = p2.lock_conn_for_test();
    let h: i64 = conn
        .query_row(
            "SELECT synced_height FROM core_sync_state WHERE wallet_id = ?1",
            rusqlite::params![w.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        h, 5,
        "restored bytes must reflect the backup, not the mutation"
    );
}
