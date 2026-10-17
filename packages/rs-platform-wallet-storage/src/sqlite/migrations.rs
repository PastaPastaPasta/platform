//! Schema migration plumbing.
//!
//! Embeds every Rust migration under `migrations/` (upstream's) and
//! `migrations_fork/` (this fork's, with their own history table) at compile
//! time (see `refinery::embed_migrations!`). The `run` function applies any
//! pending migrations to the supplied connection.

use rusqlite::OptionalExtension;

use crate::sqlite::error::WalletStorageError;
use refinery_core::error::WrapMigrationError;

mod legacy_v008;

// Generates a `migrations` module with `runner()`; path is relative to
// the crate root.
refinery::embed_migrations!("./migrations");

/// This fork's own migrations. Their history is kept in
/// [`FORK_HISTORY_TABLE`], apart from upstream's `refinery_schema_history`,
/// so upstream can number its migrations in any order: the two numberings
/// never conflict, and a fork version never sits above one upstream adds
/// later. An upstream build ignores both the table and what the fork
/// migrations add.
mod fork {
    refinery::embed_migrations!("./migrations_fork");
}

/// The fork migrations' refinery history table.
pub const FORK_HISTORY_TABLE: &str = "dw_fork_schema_history";

/// The fork migration builds before [`FORK_HISTORY_TABLE`] recorded in
/// upstream's history as version 19 (now fork version 1).
const OLD_FORK_V019_NAME: &str = "dashpay_external_rotation";

/// Its refinery checksum as those builds recorded it. Only this exact row is
/// reconciled; the same version and name with any other checksum is refused.
pub const OLD_FORK_V019_CHECKSUM: u64 = 15375114024144232753;

const OLD_FORK_V019_FOREIGN: &str = "version 19 names the fork migration with an unknown checksum";

/// What each fork migration leaves, checked after every migration run: an
/// upstream migration that rebuilds or alters a table could drop a fork
/// column while the fork history still says it is applied. `(fork version,
/// table, column)`; no column means the table itself.
const FORK_SCHEMA: &[(i32, &str, Option<&str>)] = &[
    (1, "core_address_pool_retired", None),
    (1, "contacts", Some("external_account_reference")),
];

/// Apply every pending migration to `conn`: upstream's, then the fork's.
pub fn run(conn: &mut rusqlite::Connection) -> Result<refinery::Report, refinery::Error> {
    run_with_runners(conn, migrations::runner(), Some(fork::migrations::runner()))
}

/// Move a database that recorded the fork migration as upstream version 19
/// into the fork's own history, in one transaction: the row leaves
/// `refinery_schema_history` and fork version 1 is recorded as applied when it
/// was. Its schema objects are already there, so nothing re-runs. Runs after
/// the schema guards (which skip exactly this row) and before refinery, which
/// would otherwise read version 19 as upstream's. A crash before the commit
/// leaves the old history for the next open. One-way: a build before the fork
/// history table cannot open the file afterwards (its V019 fails, rolled back).
pub(crate) fn reconcile_old_fork_history(
    conn: &mut rusqlite::Connection,
) -> Result<(), WalletStorageError> {
    if !has_schema_history(conn)? {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let row: Option<(String, String, String)> = tx
        .query_row(
            "SELECT name, applied_on, checksum FROM refinery_schema_history WHERE version = 19",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((name, applied_on, checksum)) = row else {
        return Ok(());
    };
    if name != OLD_FORK_V019_NAME {
        return Ok(());
    }
    if checksum != OLD_FORK_V019_CHECKSUM.to_string() {
        return Err(WalletStorageError::SchemaHistoryMalformed {
            reason: OLD_FORK_V019_FOREIGN,
        });
    }
    let v1 = fork_migration(1);
    // Mirrors refinery's own history DDL.
    tx.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {FORK_HISTORY_TABLE}(
             version int4 PRIMARY KEY,
             name VARCHAR(255),
             applied_on VARCHAR(255),
             checksum VARCHAR(255));"
    ))?;
    let recorded: Option<String> = tx
        .query_row(
            &format!("SELECT checksum FROM {FORK_HISTORY_TABLE} WHERE version = ?1"),
            [v1.version()],
            |row| row.get(0),
        )
        .optional()?;
    match recorded {
        // Both histories record it (a hand-merged file): keep the fork's row.
        Some(recorded) if recorded == v1.checksum().to_string() => {}
        Some(_) => {
            return Err(WalletStorageError::SchemaHistoryMalformed {
                reason: "fork version 1 is recorded with an unknown checksum",
            });
        }
        None => {
            tx.execute(
                &format!(
                    "INSERT INTO {FORK_HISTORY_TABLE} (version, name, applied_on, checksum)
                     VALUES (?1, ?2, ?3, ?4)"
                ),
                rusqlite::params![
                    v1.version(),
                    v1.name(),
                    applied_on,
                    v1.checksum().to_string()
                ],
            )?;
        }
    }
    tx.execute("DELETE FROM refinery_schema_history WHERE version = 19", [])?;
    tx.commit()?;
    Ok(())
}

fn fork_migration(version: i32) -> refinery::Migration {
    (fork::migrations::runner().get_migrations().iter())
        .find(|m| m.version() == version)
        .cloned()
        .expect("embedded fork migration must exist")
}

/// Keep refinery's history validation, target selection and SQL/history writes
/// inside the same writer exclusion as the typed legacy conversion. Its native
/// rusqlite driver starts its own transactions, so this adapter implements the
/// supported driver traits over our outer transaction instead. The fork's
/// runner (if any) runs after upstream's in the same transaction, against
/// [`FORK_HISTORY_TABLE`]: an open applies both or neither. With the fork
/// runner, the run fails, rolled back, when an applied fork migration's
/// schema is gone ([`FORK_SCHEMA`]): an upstream migration took it, and the
/// pin bump that brought it needs a reconcile (BL-193).
fn run_with_runners(
    conn: &mut rusqlite::Connection,
    runner: refinery::Runner,
    fork: Option<refinery::Runner>,
) -> Result<refinery::Report, refinery::Error> {
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .migration_err("begin wallet schema migration", None)?;
    let embedded = migrations::runner();
    let hook_sql = |version| {
        embedded
            .get_migrations()
            .iter()
            .find(|m| m.version() == version)
            .and_then(|m| m.sql())
            .expect("embedded typed migration must exist")
            .to_owned()
    };
    let mut driver = MigrationTransaction {
        tx,
        registration_sql: hook_sql(8),
        pool_sql: hook_sql(11),
    };
    // Grouped reports never claim that rolled-back migrations were applied.
    let mut report = runner.set_grouped(true).run(&mut driver)?;
    if let Some(fork) = fork {
        let mut fork = fork.set_grouped(true);
        let applied = fork
            .set_migration_table_name(FORK_HISTORY_TABLE)
            .run(&mut driver)?;
        let mut all = report.applied_migrations().clone();
        all.extend(applied.applied_migrations().iter().cloned());
        report = refinery::Report::new(all);
        if let Some(missing) = missing_fork_schema(&driver.tx)
            .migration_err("check the fork migrations' schema", None)?
        {
            return Err(std::io::Error::other(missing))
                .migration_err("an upstream migration removed fork schema", None);
        }
    }
    driver
        .tx
        .commit()
        .migration_err("commit wallet schema migration", None)?;
    Ok(report)
}

struct MigrationTransaction<'conn> {
    tx: rusqlite::Transaction<'conn>,
    registration_sql: String,
    pool_sql: String,
}

impl refinery_core::traits::sync::Transaction for MigrationTransaction<'_> {
    type Error = WalletStorageError;

    fn execute<'a, T: Iterator<Item = &'a str>>(
        &mut self,
        queries: T,
    ) -> Result<usize, Self::Error> {
        let mut count = 0;
        for query in queries {
            self.tx.execute_batch(query)?;
            if query == self.registration_sql {
                legacy_v008::backfill_registrations(&self.tx)?;
            } else if query == self.pool_sql {
                legacy_v008::convert_pools(&self.tx)?;
            }
            count += 1;
        }
        Ok(count)
    }
}

impl refinery_core::traits::sync::Query<Vec<refinery::Migration>> for MigrationTransaction<'_> {
    fn query(&mut self, query: &str) -> Result<Vec<refinery::Migration>, Self::Error> {
        let mut stmt = self.tx.prepare(query)?;
        let mut rows = stmt.query([])?;
        let mut applied = Vec::new();
        while let Some(row) = rows.next()? {
            let timestamp: String = row.get(2)?;
            let applied_on = time::OffsetDateTime::parse(
                &timestamp,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| WalletStorageError::SchemaHistoryMalformed {
                reason: "applied_on is not a valid RFC3339 timestamp",
            })?;
            let checksum: String = row.get(3)?;
            let checksum =
                checksum
                    .parse()
                    .map_err(|_| WalletStorageError::SchemaHistoryMalformed {
                        reason: "checksum is not a valid u64",
                    })?;
            applied.push(refinery::Migration::applied(
                row.get(0)?,
                row.get(1)?,
                applied_on,
                checksum,
            ));
        }
        Ok(applied)
    }
}

impl refinery_core::traits::sync::Migrate for MigrationTransaction<'_> {}

/// Apply migrations on behalf of [`crate::sqlite::persister::SqlitePersister::open`].
///
/// A typed-error chokepoint: a single entry point for any future
/// migration that needs to re-classify a refinery error.
pub(crate) fn run_for_open(
    conn: &mut rusqlite::Connection,
) -> Result<refinery::Report, WalletStorageError> {
    run(conn).map_err(WalletStorageError::Migration)
}

/// Return a fresh atomic migration runner seeded with the embedded list.
/// Tests can apply a subset via [`MigrationRunner::set_target`].
#[cfg(any(test, feature = "__test-helpers"))]
pub fn runner() -> MigrationRunner {
    MigrationRunner {
        upstream: migrations::runner(),
        fork: Some(fork::migrations::runner()),
    }
}

/// Test runner using the same atomic conversion path as production open.
#[cfg(any(test, feature = "__test-helpers"))]
pub struct MigrationRunner {
    upstream: refinery::Runner,
    fork: Option<refinery::Runner>,
}

#[cfg(any(test, feature = "__test-helpers"))]
impl MigrationRunner {
    /// Stop after the selected upstream migration, retaining staged legacy
    /// rows. The fork's migrations need the latest upstream schema, so they
    /// are left for a later full run.
    pub fn set_target(self, target: refinery::Target) -> Self {
        Self {
            upstream: self.upstream.set_target(target),
            fork: None,
        }
    }

    /// An upstream revision simulated: the embedded upstream migrations plus
    /// `later` (`(file name, SQL)`, numbered after them), with the fork's.
    pub fn with_upstream(later: &[(&str, &str)]) -> Self {
        let mut all = migrations::runner().get_migrations().clone();
        for (name, sql) in later {
            all.push(refinery::Migration::unapplied(name, sql).expect("migration name"));
        }
        Self {
            upstream: refinery::Runner::new(&all),
            fork: Some(fork::migrations::runner()),
        }
    }

    /// Without the fork's migrations: what an upstream build runs.
    pub fn upstream_only(self) -> Self {
        Self { fork: None, ..self }
    }

    /// Apply the selected migration set and typed conversions atomically.
    pub fn run(self, conn: &mut rusqlite::Connection) -> Result<refinery::Report, refinery::Error> {
        run_with_runners(conn, self.upstream, self.fork)
    }
}

/// Highest migration version this binary knows how to apply. Used by
/// both `SqlitePersister::open` and `backup::restore_from` to refuse
/// forward-version databases.
pub fn max_supported_version() -> i64 {
    embedded_migrations()
        .iter()
        .map(|(v, _)| *v as i64)
        .max()
        .unwrap_or(0)
}

/// Returns true if the `refinery_schema_history` table exists on this
/// connection. Used by `open`, `restore_from`, and `count_pending` to
/// distinguish "fresh DB" (no migrations applied yet) from
/// "pre-existing DB" (carries refinery history).
pub(crate) fn has_schema_history(conn: &rusqlite::Connection) -> Result<bool, WalletStorageError> {
    has_table(conn, "refinery_schema_history")
}

/// Returns true if the database already carries any schema object (table,
/// index, view, or trigger). `open` uses it to tell a brand-new empty DB
/// apart from a pre-existing NON-wallet SQLite file that lacks
/// `refinery_schema_history`: the former is migrated, the latter rejected
/// rather than silently grafting wallet tables onto a foreign schema.
pub(crate) fn db_has_objects(conn: &rusqlite::Connection) -> Result<bool, WalletStorageError> {
    let exists = conn
        .query_row("SELECT 1 FROM sqlite_master LIMIT 1", [], |_| Ok(()))
        .optional()?
        .is_some();
    Ok(exists)
}

/// The first [`FORK_SCHEMA`] object an applied fork migration should have
/// left and `conn` lacks, named `table` or `table.column`.
fn missing_fork_schema(conn: &rusqlite::Connection) -> Result<Option<String>, rusqlite::Error> {
    let applied: i64 = conn.query_row(
        &format!("SELECT COALESCE(MAX(version), 0) FROM {FORK_HISTORY_TABLE}"),
        [],
        |row| row.get(0),
    )?;
    for &(version, table, column) in FORK_SCHEMA {
        if i64::from(version) > applied {
            continue;
        }
        let present = match column {
            None => conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |_| Ok(()),
                )
                .optional()?,
            Some(column) => conn
                .query_row(
                    "SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2",
                    [table, column],
                    |_| Ok(()),
                )
                .optional()?,
        };
        if present.is_none() {
            return Ok(Some(match column {
                None => format!("fork version {version} table {table} is missing"),
                Some(column) => {
                    format!("fork version {version} column {table}.{column} is missing")
                }
            }));
        }
    }
    Ok(None)
}

/// Refuse to operate on a DB whose schema histories are newer than this
/// build: upstream's ([`WalletStorageError::SchemaVersionUnsupported`]) or the
/// fork's ([`WalletStorageError::ForkSchemaVersionUnsupported`]).
pub fn assert_schema_version_supported(
    conn: &rusqlite::Connection,
) -> Result<(), WalletStorageError> {
    assert_upstream_schema_version_supported(conn)?;
    assert_fork_schema_version_supported(conn)
}

/// Refuse to operate on a DB whose `refinery_schema_history` MAX(version)
/// exceeds [`max_supported_version`], returning
/// [`WalletStorageError::SchemaVersionUnsupported`]. This is a forward-only
/// gate — it refuses a newer DB but never migrates it down (SQLite
/// migrations are one-directional).
///
/// Quietly succeeds when the table is absent; the caller decides what a
/// missing schema-history means (`restore_from` rejects it, `open` treats
/// it as a brand-new DB).
fn assert_upstream_schema_version_supported(
    conn: &rusqlite::Connection,
) -> Result<(), WalletStorageError> {
    if !has_schema_history(conn)? {
        return Ok(());
    }
    // The old fork row is not upstream's: the open reconciles it
    // (`reconcile_old_fork_history`). Under the fork's name with another
    // checksum it is neither, and not a newer build's either.
    let checksum = OLD_FORK_V019_CHECKSUM.to_string();
    let foreign = conn
        .query_row(
            "SELECT 1 FROM refinery_schema_history
             WHERE version = 19 AND name = ?1 AND checksum <> ?2",
            rusqlite::params![OLD_FORK_V019_NAME, checksum],
            |_| Ok(()),
        )
        .optional()?;
    if foreign.is_some() {
        return Err(WalletStorageError::SchemaHistoryMalformed {
            reason: OLD_FORK_V019_FOREIGN,
        });
    }
    let found: Option<i64> = conn.query_row(
        "SELECT MAX(version) FROM refinery_schema_history
         WHERE NOT (version = 19 AND name = ?1 AND checksum = ?2)",
        rusqlite::params![OLD_FORK_V019_NAME, checksum],
        |row| row.get(0),
    )?;
    let max_supported = max_supported_version();
    match found {
        Some(found) if found > max_supported => Err(WalletStorageError::SchemaVersionUnsupported {
            found,
            max_supported,
        }),
        _ => Ok(()),
    }
}

/// The upstream guard for the fork's history: refuse a database whose
/// [`FORK_HISTORY_TABLE`] holds a version above [`max_fork_version`], with
/// [`WalletStorageError::ForkSchemaVersionUnsupported`]. Quietly succeeds when
/// the table is absent (no fork migration applied yet).
fn assert_fork_schema_version_supported(
    conn: &rusqlite::Connection,
) -> Result<(), WalletStorageError> {
    if !has_table(conn, FORK_HISTORY_TABLE)? {
        return Ok(());
    }
    let found: Option<i64> = conn.query_row(
        &format!("SELECT MAX(version) FROM {FORK_HISTORY_TABLE}"),
        [],
        |row| row.get(0),
    )?;
    let max_supported = max_fork_version();
    match found {
        Some(found) if found > max_supported => {
            Err(WalletStorageError::ForkSchemaVersionUnsupported {
                found,
                max_supported,
            })
        }
        _ => Ok(()),
    }
}

/// The highest fork migration this binary embeds.
pub fn max_fork_version() -> i64 {
    (fork::migrations::runner().get_migrations().iter())
        .map(|m| i64::from(m.version()))
        .max()
        .unwrap_or(0)
}

/// How many embedded fork migrations `conn` has not applied yet.
pub(crate) fn fork_pending(conn: &rusqlite::Connection) -> Result<usize, WalletStorageError> {
    let embedded = fork::migrations::runner().get_migrations().len();
    if !has_table(conn, FORK_HISTORY_TABLE)? {
        return Ok(embedded);
    }
    let applied: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM {FORK_HISTORY_TABLE}"),
        [],
        |row| row.get(0),
    )?;
    Ok(embedded.saturating_sub(applied as usize))
}

fn has_table(conn: &rusqlite::Connection, name: &str) -> Result<bool, WalletStorageError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn refinery_timestamp_is_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    let shape_is_valid = bytes.len() >= 20
        && bytes.len() <= 30
        && digits(0..4)
        && bytes[4] == b'-'
        && digits(5..7)
        && bytes[7] == b'-'
        && digits(8..10)
        && bytes[10] == b'T'
        && digits(11..13)
        && bytes[13] == b':'
        && digits(14..16)
        && bytes[16] == b':'
        && digits(17..19)
        && bytes[17] <= b'5'
        && bytes[bytes.len() - 1] == b'Z'
        && (bytes.len() == 20 || (bytes[19] == b'.' && digits(20..bytes.len().saturating_sub(1))));

    shape_is_valid && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

/// Probe `refinery_schema_history` rows BEFORE handing the connection to
/// refinery, which parses `applied_on` (RFC3339) and `checksum` (`u64`)
/// with `unwrap()` — a malformed value would abort the process. Surfaces
/// a typed [`WalletStorageError::SchemaHistoryMalformed`] instead.
/// Quietly succeeds when the table is absent.
pub(crate) fn assert_schema_history_well_formed(
    conn: &rusqlite::Connection,
) -> Result<(), WalletStorageError> {
    if !has_schema_history(conn)? {
        return Ok(());
    }
    let mut stmt = conn.prepare("SELECT applied_on, checksum FROM refinery_schema_history")?;
    let rows = stmt.query_map([], |row| {
        let applied_on: String = row.get(0)?;
        let checksum: String = row.get(1)?;
        Ok((applied_on, checksum))
    })?;
    for row in rows {
        let (applied_on, checksum) = row?;
        // Deliberately NARROWER than refinery's own reader, which accepts any
        // RFC3339 value (`drivers/rusqlite.rs` parses with `time::Rfc3339`).
        // We can be narrower because refinery only ever WRITES the canonical
        // UTC shape: `runner.rs` stamps `OffsetDateTime::now_utc()` and
        // `traits/mod.rs` formats it with `time::Rfc3339`, which emits a
        // trailing `Z` for a UTC offset rather than `+00:00`. So every value
        // refinery produced passes this gate, while a hand-written `+00:00`
        // is refused — a typed error, which is the point: the panic this
        // guard replaces is unrecoverable.
        if !refinery_timestamp_is_valid(&applied_on) {
            return Err(WalletStorageError::SchemaHistoryMalformed {
                reason: "applied_on is not a valid RFC3339 timestamp",
            });
        }
        if checksum.parse::<u64>().is_err() {
            return Err(WalletStorageError::SchemaHistoryMalformed {
                reason: "checksum is not a valid u64",
            });
        }
    }
    Ok(())
}

/// True when `refinery_schema_history` is non-empty and every applied
/// `(version, name)` pair names a migration this binary embeds at that same
/// version.
///
/// This is the positive identification behind
/// [`crate::sqlite::conn::assert_wallet_application_id_or_legacy`]: a foreign
/// SQLite database does not carry our migration names, so an unstamped file
/// that passes here is a wallet database created before the header stamp
/// existed. Deliberately name-only — a checksum comparison is refinery's job
/// moments later, and doing it here would report a divergent body as
/// "not a wallet database", which is the wrong diagnosis.
pub(crate) fn applied_history_matches_embedded(
    conn: &rusqlite::Connection,
) -> Result<bool, WalletStorageError> {
    let embedded: std::collections::HashMap<i32, String> =
        embedded_migrations().into_iter().collect();
    let mut stmt = conn.prepare("SELECT version, name FROM refinery_schema_history")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut saw_row = false;
    for row in rows {
        let (version, name) = row?;
        saw_row = true;
        let Ok(version) = i32::try_from(version) else {
            return Ok(false);
        };
        if embedded.get(&version) != Some(&name) {
            return Ok(false);
        }
    }
    Ok(saw_row)
}

/// List `(version, name)` of every embedded migration. Used by tests and
/// the migration-drift hash check.
pub fn embedded_migrations() -> Vec<(i32, String)> {
    migrations::runner()
        .get_migrations()
        .iter()
        .map(|m| (m.version(), m.name().to_string()))
        .collect()
}

/// SHA-256 over `(version, name)` of every embedded migration in version
/// order. Deliberately content-blind: it hashes the migration set's
/// identity, not the SQL bodies, so it catches an added/removed/renamed
/// migration but ignores in-place DDL edits (a content-pinning guard
/// belongs with the schema freeze at release).
#[cfg(any(test, feature = "__test-helpers"))]
pub fn embedded_migrations_fingerprint() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut entries = embedded_migrations();
    entries.sort_by_key(|(v, _)| *v);
    let mut hasher = Sha256::new();
    for (v, name) in entries {
        hasher.update(v.to_be_bytes());
        hasher.update([0u8]);
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
    }
    hasher.finalize().into()
}

/// SHA-256 over `(version, name, rendered SQL)` of every embedded migration
/// in version order. Unlike [`embedded_migrations_fingerprint`] this is
/// content-level: it pins each migration's SQL body, so an in-place DDL edit
/// (e.g. renaming a table inside a same-named file) breaks the golden test.
/// This is the guard the D0 schema freeze relies on; the identity-only
/// fingerprint cannot catch a same-name body edit.
///
/// The SQL *text* is deterministic even where a value is generated at run
/// time (`randomblob(16)`): the literal string is hashed, not the runtime
/// bytes.
#[cfg(any(test, feature = "__test-helpers"))]
pub fn embedded_migrations_sql_fingerprint() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut migrations = migrations::runner().get_migrations().clone();
    migrations.sort_by_key(|m| m.version());
    let mut hasher = Sha256::new();
    for m in &migrations {
        hasher.update((m.version() as u32).to_be_bytes());
        hasher.update([0u8]);
        hasher.update(m.name().as_bytes());
        hasher.update([0u8]);
        let sql = m
            .sql()
            .expect("embedded migrations always carry rendered SQL");
        hasher.update(sql.as_bytes());
        hasher.update([0u8]);
    }
    hasher.finalize().into()
}

/// Rendered SQL of every embedded migration paired with its version, in
/// version order. The retired-name guard needs the version to skip the
/// pre-rename history, where a retired table name is correct.
#[cfg(any(test, feature = "__test-helpers"))]
pub fn embedded_migrations_sql_by_version() -> Vec<(i32, String)> {
    let mut migrations = migrations::runner().get_migrations().clone();
    migrations.sort_by_key(|m| m.version());
    migrations
        .iter()
        .map(|m| {
            (
                m.version(),
                m.sql()
                    .expect("embedded migrations always carry rendered SQL")
                    .to_string(),
            )
        })
        .collect()
}

/// Rendered SQL of every embedded migration, in version order. Used by the
/// schema-freeze grep guard to scan for retired table names.
#[cfg(any(test, feature = "__test-helpers"))]
pub fn embedded_migrations_sql() -> Vec<String> {
    let mut migrations = migrations::runner().get_migrations().clone();
    migrations.sort_by_key(|m| m.version());
    migrations
        .iter()
        .map(|m| {
            m.sql()
                .expect("embedded migrations always carry rendered SQL")
                .to_string()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    #[test]
    fn schema_history_guard_rejects_timestamps_refinery_rejects() {
        for applied_on in ["2024-01-01T00:00:00−00:00", "2024-01-01T00:00:60Z"] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(
                "CREATE TABLE refinery_schema_history (
                    applied_on TEXT NOT NULL,
                    checksum TEXT NOT NULL
                )",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO refinery_schema_history (applied_on, checksum) VALUES (?1, '0')",
                params![applied_on],
            )
            .unwrap();

            assert!(matches!(
                assert_schema_history_well_formed(&conn),
                Err(WalletStorageError::SchemaHistoryMalformed { .. })
            ));
        }
    }

    /// The helper returns false on a brand-new in-memory DB (no
    /// `refinery_schema_history`), and true after the table is created.
    #[test]
    fn has_schema_history_distinguishes_fresh_vs_migrated() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(
            !has_schema_history(&conn).unwrap(),
            "fresh in-memory DB has no schema-history table"
        );
        conn.execute(
            "CREATE TABLE refinery_schema_history (version INTEGER PRIMARY KEY)",
            [],
        )
        .unwrap();
        assert!(
            has_schema_history(&conn).unwrap(),
            "schema-history table is present after creation"
        );
    }

    fn table_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |_| Ok(()),
        )
        .is_ok()
    }

    fn column_exists(conn: &Connection, table: &str, column: &str) -> bool {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        cols.iter().any(|c| c == column)
    }

    /// The initial schema (V001) creates the DashPay sync-correctness
    /// objects directly — the `contacts.payment_channel_broken` column and
    /// the `ignored_senders` table. V001-V007 are published and immutable;
    /// this test pins that these objects survive the full migration set.
    #[test]
    fn v001_creates_dashpay_sync_schema() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();

        assert!(
            table_exists(&conn, "ignored_senders"),
            "V001 must create the ignored-senders table"
        );
        assert!(
            column_exists(&conn, "contacts", "payment_channel_broken"),
            "V001 must create the contacts.payment_channel_broken column"
        );
    }

    /// An upstream revision after this pin, simulated: the numbers upstream's
    /// open branches claim (V019, V020, V021), with SQL of their own.
    const LATER_UPSTREAM: &[(&str, &str)] = &[
        (
            "V019__asset_lock_operation_id",
            "CREATE TABLE sim_asset_lock_operation_id (id INTEGER PRIMARY KEY);",
        ),
        (
            "V020__shielded_funding_attempts",
            "CREATE TABLE sim_shielded_funding_attempts (id INTEGER PRIMARY KEY);",
        ),
        (
            "V021__core_transaction_accounting",
            "CREATE TABLE sim_core_transaction_accounting (id INTEGER PRIMARY KEY);",
        ),
    ];

    fn upstream_history(conn: &Connection) -> Vec<(i64, String)> {
        let mut stmt = conn
            .prepare("SELECT version, name FROM refinery_schema_history ORDER BY version")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// `(version, name, applied_on, checksum)` of the fork's history; empty
    /// when the table does not exist.
    fn fork_history(conn: &Connection) -> Vec<(i64, String, String, String)> {
        if !table_exists(conn, FORK_HISTORY_TABLE) {
            return Vec::new();
        }
        let mut stmt = conn
            .prepare(&format!(
                "SELECT version, name, applied_on, checksum FROM {FORK_HISTORY_TABLE} ORDER BY version"
            ))
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn upstream_versions(conn: &Connection) -> Vec<i64> {
        upstream_history(conn).into_iter().map(|(v, _)| v).collect()
    }

    fn has_fork_schema(conn: &Connection) -> bool {
        table_exists(conn, "core_address_pool_retired")
            && column_exists(conn, "contacts", "external_account_reference")
    }

    /// Rewinds a migrated database to the history builds before the fork
    /// table wrote: fork migration 1 recorded as upstream version 19, with
    /// `checksum`.
    fn as_old_fork_build_left_it(conn: &Connection, checksum: &str) -> String {
        let (_, _, applied_on, _) = fork_history(conn).remove(0);
        conn.execute_batch(&format!("DROP TABLE {FORK_HISTORY_TABLE}"))
            .unwrap();
        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
             VALUES (19, 'dashpay_external_rotation', ?1, ?2)",
            rusqlite::params![applied_on, checksum],
        )
        .unwrap();
        applied_on
    }

    fn embedded_upstream() -> Vec<i64> {
        (1..=max_supported_version()).collect()
    }

    /// The pinned checksum is the one refinery computes for fork migration 1's
    /// SQL under its old name and number, so it is exactly what those builds
    /// recorded, and it pins that SQL: an edit to fork V1 fails here.
    #[test]
    fn the_old_fork_checksum_is_fork_v1_under_version_19() {
        let v1 = fork_migration(1);
        let as_v019 =
            refinery::Migration::unapplied("V019__dashpay_external_rotation", v1.sql().unwrap())
                .unwrap();
        assert_eq!(as_v019.checksum(), OLD_FORK_V019_CHECKSUM);
        assert_eq!(v1.name(), OLD_FORK_V019_NAME);
    }

    /// Test 1: a fresh database takes upstream's migrations into upstream's
    /// history and the fork's into its own.
    #[test]
    fn a_fresh_database_keeps_the_two_histories_apart() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        assert_eq!(upstream_versions(&conn), embedded_upstream());
        let fork = fork_history(&conn);
        assert_eq!(fork.len(), 1);
        assert_eq!(
            (fork[0].0, fork[0].1.as_str()),
            (1, "dashpay_external_rotation")
        );
        assert!(has_fork_schema(&conn));
        assert_eq!(fork_pending(&conn).unwrap(), 0);
    }

    /// Test 2: a database an old fork build migrated (fork V1 as upstream
    /// V019) is reconciled: the row moves to the fork's history with its
    /// applied time, nothing re-runs, and the later upstream revision then
    /// applies its own V019, V020 and V021.
    #[test]
    fn an_old_fork_v019_database_is_reconciled_then_takes_upstreams_v019() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        let applied_on = as_old_fork_build_left_it(&conn, &OLD_FORK_V019_CHECKSUM.to_string());
        assert!(upstream_versions(&conn).contains(&19));
        // The guards read the old row as the fork's, not a newer build's.
        assert_schema_version_supported(&conn).unwrap();
        assert_fork_schema_version_supported(&conn).unwrap();

        reconcile_old_fork_history(&mut conn).unwrap();
        assert_eq!(upstream_versions(&conn), embedded_upstream());
        let fork = fork_history(&conn);
        assert_eq!(fork.len(), 1);
        assert_eq!(fork[0].0, 1);
        assert_eq!(fork[0].2, applied_on, "applied when it was");
        assert_eq!(fork[0].3, fork_migration(1).checksum().to_string());
        assert!(has_fork_schema(&conn));
        reconcile_old_fork_history(&mut conn).unwrap();
        assert_eq!(
            fork_history(&conn),
            fork,
            "a second reconcile changes nothing"
        );

        let report = MigrationRunner::with_upstream(LATER_UPSTREAM)
            .run(&mut conn)
            .unwrap();
        let applied: Vec<i32> = report
            .applied_migrations()
            .iter()
            .map(|m| m.version())
            .collect();
        assert_eq!(applied, vec![19, 20, 21], "fork V1 does not re-run");
        assert_eq!(
            upstream_history(&conn).last().unwrap().1,
            "core_transaction_accounting"
        );
        assert!(table_exists(&conn, "sim_asset_lock_operation_id"));
        assert_eq!(fork_history(&conn), fork);
    }

    /// Test 3: a database a later upstream build migrated (its own V019 to
    /// V021, no fork table) opens with the fork on that revision: fork V1
    /// applies and upstream's history is left as upstream wrote it.
    #[test]
    fn an_upstream_v021_database_takes_fork_v1() {
        let mut conn = Connection::open_in_memory().unwrap();
        MigrationRunner::with_upstream(LATER_UPSTREAM)
            .upstream_only()
            .run(&mut conn)
            .unwrap();
        assert!(fork_history(&conn).is_empty());
        let upstream = upstream_history(&conn);

        MigrationRunner::with_upstream(LATER_UPSTREAM)
            .run(&mut conn)
            .unwrap();
        assert_eq!(upstream_history(&conn), upstream);
        assert_eq!(fork_history(&conn).len(), 1);
        assert!(has_fork_schema(&conn));
    }

    /// Test 4: a fork database at upstream V018 opens with the later upstream
    /// revision: upstream's V019 to V021 are above upstream's applied maximum,
    /// so refinery applies them; fork V1 stays applied.
    #[test]
    fn a_fork_database_takes_a_later_upstream_revision() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        let fork = fork_history(&conn);

        MigrationRunner::with_upstream(LATER_UPSTREAM)
            .run(&mut conn)
            .unwrap();
        assert_eq!(*upstream_versions(&conn).last().unwrap(), 21);
        assert_eq!(fork_history(&conn), fork);
    }

    /// Test 5: an upstream build (no fork migrations) opens a fork database:
    /// its guard and refinery see only upstream's history.
    #[test]
    fn an_upstream_build_opens_a_fork_database() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        assert_schema_version_supported(&conn).unwrap();
        runner().upstream_only().run(&mut conn).unwrap();
        MigrationRunner::with_upstream(LATER_UPSTREAM)
            .upstream_only()
            .run(&mut conn)
            .unwrap();
        assert_eq!(*upstream_versions(&conn).last().unwrap(), 21);
    }

    /// Test 6: a fork history newer than this build is refused, typed.
    #[test]
    fn a_newer_fork_history_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {FORK_HISTORY_TABLE} (version, name, applied_on, checksum)
                 VALUES (2, 'from_a_newer_build', '2026-10-17T00:00:00Z', '1')"
            ),
            [],
        )
        .unwrap();
        assert!(matches!(
            assert_fork_schema_version_supported(&conn),
            Err(WalletStorageError::ForkSchemaVersionUnsupported {
                found: 2,
                max_supported: 1
            })
        ));
    }

    /// Test 7: version 19 under the fork's name with any other checksum is
    /// not reconciled: refused, typed, and the database left as it was.
    #[test]
    fn the_old_row_with_another_checksum_is_refused_untouched() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        let other = OLD_FORK_V019_CHECKSUM.wrapping_add(1).to_string();
        as_old_fork_build_left_it(&conn, &other);
        let before = upstream_history(&conn);
        assert!(matches!(
            reconcile_old_fork_history(&mut conn),
            Err(WalletStorageError::SchemaHistoryMalformed { .. })
        ));
        assert_eq!(upstream_history(&conn), before);
        assert!(!table_exists(&conn, FORK_HISTORY_TABLE));
        // The guard, which runs first at open and restore, refuses it the
        // same way: not as the fork's, nor as a newer build's.
        assert!(matches!(
            assert_schema_version_supported(&conn),
            Err(WalletStorageError::SchemaHistoryMalformed { .. })
        ));
    }

    /// A file whose two histories both record fork migration 1 (merged by
    /// hand) keeps the fork's row when its checksum is fork V1's; any other
    /// checksum there is refused, untouched.
    #[test]
    fn the_old_row_beside_a_recorded_fork_v1() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        let fork = fork_history(&conn);
        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
             VALUES (19, 'dashpay_external_rotation', '2026-10-01T00:00:00Z', ?1)",
            [OLD_FORK_V019_CHECKSUM.to_string()],
        )
        .unwrap();
        reconcile_old_fork_history(&mut conn).unwrap();
        assert_eq!(upstream_versions(&conn), embedded_upstream());
        assert_eq!(fork_history(&conn), fork);

        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
             VALUES (19, 'dashpay_external_rotation', '2026-10-01T00:00:00Z', ?1)",
            [OLD_FORK_V019_CHECKSUM.to_string()],
        )
        .unwrap();
        conn.execute(
            &format!("UPDATE {FORK_HISTORY_TABLE} SET checksum = '1' WHERE version = 1"),
            [],
        )
        .unwrap();
        assert!(matches!(
            reconcile_old_fork_history(&mut conn),
            Err(WalletStorageError::SchemaHistoryMalformed { .. })
        ));
        assert!(upstream_versions(&conn).contains(&19));
    }

    /// Test 8: all or nothing. A reconcile that fails at its last statement
    /// leaves the old history; a migration run whose fork stage fails leaves
    /// upstream's migrations of that run unapplied too.
    #[test]
    fn a_failure_midway_changes_nothing() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        as_old_fork_build_left_it(&conn, &OLD_FORK_V019_CHECKSUM.to_string());
        conn.execute_batch(
            "CREATE TEMP TRIGGER boom BEFORE DELETE ON refinery_schema_history
             BEGIN SELECT RAISE(ABORT, 'crash'); END;",
        )
        .unwrap();
        assert!(reconcile_old_fork_history(&mut conn).is_err());
        assert!(upstream_versions(&conn).contains(&19));
        assert!(!table_exists(&conn, FORK_HISTORY_TABLE));
        conn.execute_batch("DROP TRIGGER boom").unwrap();
        reconcile_old_fork_history(&mut conn).unwrap();
        assert_eq!(fork_history(&conn).len(), 1);

        // Upstream at V018 without fork V1, and an object in fork V1's way.
        let mut conn = Connection::open_in_memory().unwrap();
        runner().upstream_only().run(&mut conn).unwrap();
        conn.execute_batch("CREATE TABLE core_address_pool_retired (x INTEGER)")
            .unwrap();
        assert!(MigrationRunner::with_upstream(LATER_UPSTREAM)
            .run(&mut conn)
            .is_err());
        assert_eq!(upstream_versions(&conn), embedded_upstream());
        assert!(!table_exists(&conn, "sim_asset_lock_operation_id"));
        assert!(fork_history(&conn).is_empty());
    }

    /// Test 9: an upstream revision that adds fork V1's column itself fails
    /// loudly on a fork database, inside the transaction, and leaves it
    /// unchanged. This is the standing rule for a pin bump (BL-193): when
    /// upstream adopts a fork migration's schema, that bump adds a reconcile
    /// from the fork version to upstream's.
    #[test]
    fn an_upstream_adoption_without_a_reconcile_fails_loudly() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn).unwrap();
        let adopting: &[(&str, &str)] = &[(
            "V019__contact_external_account_reference",
            "ALTER TABLE contacts ADD COLUMN external_account_reference INTEGER NULL;",
        )];
        let err = MigrationRunner::with_upstream(adopting)
            .run(&mut conn)
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("duplicate column"),
            "a clear error: {err:?}"
        );
        assert_eq!(upstream_versions(&conn), embedded_upstream());
        assert_eq!(fork_history(&conn).len(), 1);
    }

    /// Test 10: an upstream migration that drops or rebuilds away a fork
    /// migration's schema, while the fork history still records it, fails
    /// the run, rolled back, rather than leaving a file the fork code cannot
    /// use. The same BL-193 rule applies.
    #[test]
    fn an_upstream_migration_removing_fork_schema_fails_loudly() {
        for sql in [
            "ALTER TABLE contacts DROP COLUMN external_account_reference;",
            "DROP TABLE core_address_pool_retired;",
        ] {
            let mut conn = Connection::open_in_memory().unwrap();
            run(&mut conn).unwrap();
            let err = MigrationRunner::with_upstream(&[("V019__rebuild", sql)])
                .run(&mut conn)
                .unwrap_err();
            assert!(
                format!("{err:?}").contains("is missing"),
                "{sql}: a clear error: {err:?}"
            );
            assert_eq!(upstream_versions(&conn), embedded_upstream(), "{sql}");
            assert!(has_fork_schema(&conn), "{sql}");
        }
    }
}
