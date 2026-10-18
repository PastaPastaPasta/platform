#![allow(clippy::field_reassign_with_default)]

//! CLI smoke tests for the maintenance binary.

mod common;

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;

fn cli() -> Command {
    Command::cargo_bin("platform-wallet-storage").expect("bin built")
}

fn restore_without_backup(db: &std::path::Path, from: &std::path::Path) -> std::process::Output {
    cli()
        .args([
            "--db",
            db.to_str().unwrap(),
            "restore",
            "--from",
            from.to_str().unwrap(),
            "--yes",
            "--no-auto-backup",
        ])
        .output()
        .unwrap()
}

fn migrate(db: &std::path::Path) -> std::process::Output {
    cli()
        .args(["--db", db.to_str().unwrap(), "migrate"])
        .output()
        .unwrap()
}

#[test]
fn missing_db_is_usage_error_for_database_commands() {
    for args in [
        vec!["migrate"],
        vec!["backup", "--out", "unused.db"],
        vec!["restore", "--from", "unused.db", "--yes"],
    ] {
        let out = cli().args(&args).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?} without --db must exit 2; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn restore_source_validation_errors_exit_three() {
    let tmp = common::secure_tempdir().unwrap();
    let valid = tmp.path().join("valid.db");
    let migrated = cli()
        .args(["--db", valid.to_str().unwrap(), "migrate"])
        .output()
        .unwrap();
    assert!(
        migrated.status.success(),
        "source migrate failed: {migrated:?}"
    );

    let foreign = tmp.path().join("foreign.db");
    let conn = rusqlite::Connection::open(&foreign).unwrap();
    conn.execute_batch(
        "CREATE TABLE refinery_schema_history (
             version INTEGER PRIMARY KEY,
             name TEXT,
             applied_on TEXT,
             checksum TEXT
         );
         INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
             VALUES (1, 'initial', '2026-01-01T00:00:00+00:00', '12345');",
    )
    .unwrap();
    drop(conn);

    let future = tmp.path().join("future.db");
    std::fs::copy(&valid, &future).unwrap();
    let conn = rusqlite::Connection::open(&future).unwrap();
    conn.execute(
        "INSERT INTO refinery_schema_history (version, name, applied_on, checksum) \
         VALUES (1000000, 'future', '2026-01-01T00:00:00+00:00', '0')",
        [],
    )
    .unwrap();
    drop(conn);

    let malformed = tmp.path().join("malformed.db");
    std::fs::copy(&valid, &malformed).unwrap();
    let conn = rusqlite::Connection::open(&malformed).unwrap();
    conn.execute(
        "UPDATE refinery_schema_history SET applied_on = 'not-a-timestamp' WHERE version = 1",
        [],
    )
    .unwrap();
    drop(conn);

    let corrupt = tmp.path().join("corrupt.db");
    std::fs::write(&corrupt, b"not a sqlite database").unwrap();

    let missing = tmp.path().join("missing.db");
    let dest = tmp.path().join("dest.db");
    for source in [&missing, &foreign, &future, &malformed, &corrupt] {
        let out = cli()
            .args([
                "--db",
                dest.to_str().unwrap(),
                "restore",
                "--from",
                source.to_str().unwrap(),
                "--yes",
                "--no-auto-backup",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(3),
            "source {} must be a validation error; stderr={}",
            source.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn restore_missing_schema_history_message_is_not_integrity_failure() {
    let tmp = common::secure_tempdir().unwrap();
    let source = tmp.path().join("empty.db");
    rusqlite::Connection::open(&source).unwrap();
    let dest = tmp.path().join("dest.db");
    let out = cli()
        .args([
            "--db",
            dest.to_str().unwrap(),
            "restore",
            "--from",
            source.to_str().unwrap(),
            "--yes",
            "--no-auto-backup",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("schema history missing"), "stderr={stderr}");
    assert!(!stderr.contains("integrity check"), "stderr={stderr}");
}

/// migrate on a fresh DB prints `applied: <N>` then `applied: 0`.
#[test]
fn tc056_migrate_idempotent() {
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("w.db");
    let out = cli()
        .args(["--db", db.to_str().unwrap(), "migrate"])
        .output()
        .unwrap();
    assert!(out.status.success(), "first migrate failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("applied: ") && stdout.trim() != "applied: 0",
        "unexpected first-run stdout: {stdout}"
    );
    let out2 = cli()
        .args(["--db", db.to_str().unwrap(), "migrate"])
        .output()
        .unwrap();
    assert!(out2.status.success(), "second migrate failed");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert_eq!(stdout2.trim(), "applied: 0");
}

/// migrate on a file an earlier fork build migrated (fork migration 1
/// recorded as upstream version 19) reconciles it and prints `applied: 0`:
/// moving the row between the histories applies nothing.
#[test]
fn migrate_reconciling_an_old_fork_file_applies_nothing() {
    use platform_wallet_storage::sqlite::migrations::{FORK_HISTORY_TABLE, OLD_FORK_V019_CHECKSUM};
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("w.db");
    assert!(migrate(&db).status.success());
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(&format!("DROP TABLE {FORK_HISTORY_TABLE}"))
            .unwrap();
        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
             VALUES (19, 'dashpay_external_rotation', '2026-10-01T00:00:00Z', ?1)",
            [OLD_FORK_V019_CHECKSUM.to_string()],
        )
        .unwrap();
    }
    let out = migrate(&db);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "applied: 0");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let fork: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {FORK_HISTORY_TABLE}"),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fork, 1);
}

/// Sol's DP3-04b r2 schedules, run through the binary. A backup whose fork
/// history refinery cannot read is refused (exit 3) without touching the live
/// file, even with `--no-auto-backup`.
#[test]
fn restore_of_a_malformed_fork_history_leaves_the_live_file() {
    use platform_wallet_storage::sqlite::migrations::FORK_HISTORY_TABLE;
    let tmp = common::secure_tempdir().unwrap();
    let live = tmp.path().join("live.db");
    let bad = tmp.path().join("bad-backup.db");
    assert!(migrate(&live).status.success());
    std::fs::copy(&live, &bad).unwrap();
    rusqlite::Connection::open(&bad)
        .unwrap()
        .execute(
            &format!("UPDATE {FORK_HISTORY_TABLE} SET checksum = 'not_a_u64' WHERE version = 1"),
            [],
        )
        .unwrap();
    let before = std::fs::read(&live).unwrap();
    let restore = restore_without_backup(&live, &bad);
    assert_eq!(restore.status.code(), Some(3), "{restore:?}");
    assert_eq!(std::fs::read(&live).unwrap(), before);
    let reopened = migrate(&live);
    assert!(reopened.status.success(), "{reopened:?}");
}

/// Sol's DP3-04b r3 schedules: a backup whose history passes the restore's
/// checks but that the open refuses (fork V1's row gone while its schema
/// stays; upstream V1 recorded with another checksum) is refused (exit 3)
/// because a copy of it must open first. The live file stays byte for byte
/// and still opens.
#[test]
fn restore_refuses_a_backup_the_open_would_refuse() {
    use platform_wallet_storage::sqlite::migrations::FORK_HISTORY_TABLE;
    for sql in [
        format!("DELETE FROM {FORK_HISTORY_TABLE} WHERE version = 1"),
        "UPDATE refinery_schema_history SET checksum = '0' WHERE version = 1".to_string(),
    ] {
        let tmp = common::secure_tempdir().unwrap();
        let live = tmp.path().join("live.db");
        let backup = tmp.path().join("backup.db");
        assert!(migrate(&live).status.success());
        std::fs::copy(&live, &backup).unwrap();
        rusqlite::Connection::open(&backup)
            .unwrap()
            .execute_batch(&sql)
            .unwrap();
        let before = std::fs::read(&live).unwrap();
        let restore = restore_without_backup(&live, &backup);
        assert_eq!(restore.status.code(), Some(3), "{sql}: {restore:?}");
        assert_eq!(std::fs::read(&live).unwrap(), before, "{sql}");
        let reopened = migrate(&live);
        assert!(reopened.status.success(), "{sql}: {reopened:?}");
        // Nothing of the restore's own stays (the read-only source
        // connection may leave the WAL source's own sidecars).
        let mut files: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with("backup.db-"))
            .collect();
        files.sort();
        assert_eq!(files, ["backup.db", "live.db"], "{sql}");
    }
}

/// A file whose two histories both record fork migration 1, the fork's row
/// under another name, is refused (exit 1; the open's history check stops it
/// before the reconcile, which refuses it too) and keeps the old upstream row.
#[test]
fn migrate_refuses_a_conflicting_fork_row_unchanged() {
    use platform_wallet_storage::sqlite::migrations::{FORK_HISTORY_TABLE, OLD_FORK_V019_CHECKSUM};
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("duplicate.db");
    assert!(migrate(&db).status.success());
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            &format!("UPDATE {FORK_HISTORY_TABLE} SET name = 'wrong_name' WHERE version = 1"),
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
             VALUES (19, 'dashpay_external_rotation', '2026-10-01T00:00:00Z', ?1)",
            [OLD_FORK_V019_CHECKSUM.to_string()],
        )
        .unwrap();
    }
    let out = migrate(&db);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("schema history is malformed"), "{stderr}");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let old_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM refinery_schema_history WHERE version = 19",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old_rows, 1);
}

/// A fork table replaced under its name with an unusable shape is refused.
#[test]
fn migrate_refuses_a_reshaped_fork_table() {
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("shape.db");
    assert!(migrate(&db).status.success());
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "DROP TABLE core_address_pool_retired;
             CREATE TABLE core_address_pool_retired (wallet_id BLOB);",
        )
        .unwrap();
    let out = migrate(&db);
    assert!(!out.status.success(), "{out:?}");
}

/// restore without --yes refuses (exit 2).
#[test]
fn tc062_restore_without_yes_refuses() {
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("w.db");
    cli()
        .args(["--db", db.to_str().unwrap(), "migrate"])
        .output()
        .expect("migrate ran");
    let fake_src = tmp.path().join("not-a-backup.db");
    std::fs::write(&fake_src, b"x").unwrap();
    let out = cli()
        .args([
            "--db",
            db.to_str().unwrap(),
            "restore",
            "--from",
            fake_src.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2; got {:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// prune without --keep-last or --max-age is a usage error.
#[test]
fn tc065_prune_requires_a_rule() {
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("w.db");
    let dir = tmp.path().join("bk");
    std::fs::create_dir(&dir).unwrap();
    let out = cli()
        .args([
            "--db",
            db.to_str().unwrap(),
            "prune",
            "--in",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// The `inspect` subcommand is removed from the CLI; invoking it is an
/// unknown-subcommand usage error.
#[test]
fn inspect_subcommand_removed() {
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("w.db");
    cli()
        .args(["--db", db.to_str().unwrap(), "migrate"])
        .output()
        .expect("migrate ran");
    let out = cli()
        .args(["--db", db.to_str().unwrap(), "inspect"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected clap usage exit code 2 for removed subcommand; got {:?}",
        out.status.code()
    );
}

/// The `delete-wallet` subcommand is not part of the CLI; invoking it is
/// an unknown-subcommand usage error.
#[test]
fn tc072_delete_wallet_subcommand_removed() {
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("w.db");
    cli()
        .args(["--db", db.to_str().unwrap(), "migrate"])
        .output()
        .expect("migrate ran");
    let out = cli()
        .args([
            "--db",
            db.to_str().unwrap(),
            "delete-wallet",
            "--wallet-id",
            &"aa".repeat(32),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected clap usage exit code 2 for removed subcommand; got {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unrecognized") || stderr.contains("unexpected"),
        "expected clap unknown-subcommand error, got stderr: `{stderr}`"
    );
}

/// backup --out <dir> writes a timestamped file.
#[test]
fn tc059_backup_dir() {
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("w.db");
    cli()
        .args(["--db", db.to_str().unwrap(), "migrate"])
        .output()
        .expect("migrate ran");
    let out_dir = tmp.path().join("bk");
    std::fs::create_dir(&out_dir).unwrap();
    let out = cli()
        .args([
            "--db",
            db.to_str().unwrap(),
            "backup",
            "--out",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "backup failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let path = stdout.trim();
    assert!(path.ends_with(".db"));
    assert!(std::path::Path::new(path).exists());
}

/// 1a: the supported `--no-auto-backup` flag disables the
/// pre-migration auto-backup. `migrate --no-auto-backup` succeeds on a
/// fresh DB without writing the `backups/auto/` sentinel snapshot.
#[test]
fn tc_code_030_1a_no_auto_backup_disables() {
    let tmp = common::secure_tempdir().unwrap();
    let db = tmp.path().join("w.db");
    let out = cli()
        .args(["--db", db.to_str().unwrap(), "migrate", "--no-auto-backup"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "migrate --no-auto-backup failed: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("auto-backup skipped (--no-auto-backup)"),
        "expected `--no-auto-backup` notice on stderr, got: {stderr}"
    );
    // No `backups/auto/pre-migration-*.db` written when the flag is set.
    let auto_dir = tmp.path().join("backups").join("auto");
    if auto_dir.exists() {
        let pre_mig: Vec<_> = std::fs::read_dir(&auto_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("pre-migration"))
            .collect();
        assert!(
            pre_mig.is_empty(),
            "pre-migration backup written despite --no-auto-backup: {pre_mig:?}"
        );
    }
}
