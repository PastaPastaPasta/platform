//! A DashPay contact's payment-xpub rotation (fork migration 1).
//!
//! The rotated contact's `DashpayExternalAccount` keeps its account key but
//! derives a new pool. The registration flush retires the old xpub's pool rows
//! to `core_address_pool_retired` in the same transaction that replaces the
//! xpub, so the new pool lands, the old addresses stay known for history, and
//! nothing payable is ever built from them. The contact's
//! `external_account_reference` stamp persists alongside.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{
    ensure_identity, ensure_wallet_meta, fresh_persister, fresh_persister_with_mode, wid, FlushMode,
};
use dpp::prelude::Identifier;
use key_wallet::account::AccountType;
use key_wallet::bip32::ExtendedPubKey;
use key_wallet::managed_account::address_pool::{AddressState, KeySource};
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::managed_account::ManagedCoreFundsAccount;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::Wallet;
use key_wallet::{Account, AddressInfo, Network};
use platform_wallet::changeset::{
    AccountAddressPoolEntry, AccountRegistrationEntry, ContactChangeSet, PersistenceError,
    PlatformWalletChangeSet, PlatformWalletPersistence, SentContactRequestKey,
};
use platform_wallet::wallet::identity::{ContactRequest, EstablishedContact};
use platform_wallet::wallet::platform_wallet::WalletId;
use platform_wallet_storage::sqlite::migrations::{
    max_supported_version, FORK_HISTORY_TABLE, OLD_FORK_V019_CHECKSUM,
};
use platform_wallet_storage::sqlite::schema::{contacts, core_pool};
use platform_wallet_storage::{
    LoadCtx, SqlitePersister, SqlitePersisterConfig, WalletStorageError,
};

const OWNER: [u8; 32] = [0x71; 32];
const FRIEND: [u8; 32] = [0x72; 32];

fn reopen(path: &std::path::Path) -> SqlitePersister {
    SqlitePersister::open(SqlitePersisterConfig::new(path)).expect("reopen persister")
}

fn external_account() -> AccountType {
    AccountType::DashpayExternalAccount {
        index: 0,
        user_identity_id: OWNER,
        friend_identity_id: FRIEND,
    }
}

/// A stand-in for the xpub a contact encrypts into their request.
fn contact_xpub(seed_byte: u8) -> ExtendedPubKey {
    Wallet::from_seed_bytes(
        [seed_byte; 64],
        Network::Testnet,
        WalletAccountCreationOptions::Default,
    )
    .expect("wallet")
    .get_bip44_account(0)
    .expect("BIP44 account 0")
    .account_xpub
}

/// The pool entries `register_external_contact_account` persists for `xpub`,
/// with the addresses at `used` marked used.
fn pool_entries(xpub: ExtendedPubKey, used: &[u32]) -> Vec<AccountAddressPoolEntry> {
    pool_entries_extended(xpub, used, 0)
}

/// [`pool_entries`] with `extra` more addresses, as a pool its gap limit
/// extended after payments snapshots it.
fn pool_entries_extended(
    xpub: ExtendedPubKey,
    used: &[u32],
    extra: u32,
) -> Vec<AccountAddressPoolEntry> {
    let account = Account {
        parent_wallet_id: None,
        account_type: external_account(),
        network: Network::Testnet,
        account_xpub: xpub,
        is_watch_only: true,
    };
    let mut managed = ManagedCoreFundsAccount::from_account(&account);
    if extra > 0 {
        for pool in managed.managed_account_type_mut().address_pools_mut() {
            pool.generate_addresses(extra, &KeySource::Public(xpub), true)
                .expect("extend the pool");
        }
    }
    let entries: Vec<AccountAddressPoolEntry> = managed
        .managed_account_type()
        .address_pools()
        .into_iter()
        .filter(|pool| !pool.addresses.is_empty())
        .map(|pool| AccountAddressPoolEntry {
            account_type: external_account(),
            pool_type: pool.pool_type,
            addresses: pool
                .addresses
                .values()
                .cloned()
                .map(|mut info| {
                    if used.contains(&info.index) {
                        info.state = AddressState::Used;
                    }
                    info
                })
                .collect(),
        })
        .collect();
    assert!(!entries.is_empty(), "the external account derives a pool");
    entries
}

/// The changeset `register_external_contact_account` stores.
fn registration(xpub: ExtendedPubKey, used: &[u32]) -> PlatformWalletChangeSet {
    PlatformWalletChangeSet {
        account_registrations: vec![AccountRegistrationEntry {
            account_type: external_account(),
            account_xpub: xpub,
        }],
        account_address_pools: pool_entries(xpub, used),
        ..Default::default()
    }
}

fn infos(entries: &[AccountAddressPoolEntry]) -> Vec<&AddressInfo> {
    entries.iter().flat_map(|e| e.addresses.iter()).collect()
}

fn scripts_of(xpub: ExtendedPubKey) -> BTreeSet<Vec<u8>> {
    infos(&pool_entries(xpub, &[]))
        .into_iter()
        .map(|info| info.script_pubkey.to_bytes())
        .collect()
}

fn address_at(xpub: ExtendedPubKey, index: u32) -> AddressInfo {
    infos(&pool_entries(xpub, &[]))
        .into_iter()
        .find(|info| info.index == index)
        .cloned()
        .expect("derived address at index")
}

fn live_scripts(persister: &SqlitePersister, w: &WalletId) -> BTreeSet<Vec<u8>> {
    let conn = persister.lock_conn_for_test();
    let mut stmt = conn
        .prepare("SELECT script FROM core_address_pool WHERE wallet_id = ?1")
        .unwrap();
    stmt.query_map(rusqlite::params![w.as_slice()], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Retired rows by script: (the xpub they came from, used).
fn retired(persister: &SqlitePersister, w: &WalletId) -> BTreeMap<Vec<u8>, (Vec<u8>, bool)> {
    persister
        .retired_pool_addresses(w, Network::Testnet)
        .expect("read retired pool")
        .into_iter()
        .map(|row| {
            let owner = &row.owner;
            assert_eq!(owner.account_type, "dashpay_external");
            assert_eq!(
                (owner.user_identity_id, owner.friend_identity_id),
                (OWNER, FRIEND)
            );
            (
                row.address.script_pubkey().to_bytes(),
                (row.account_xpub, row.used),
            )
        })
        .collect()
}

/// The xpub and pool scripts `load()` rebuilds the external account from.
fn loaded_account(
    persister: &SqlitePersister,
    w: &WalletId,
) -> (ExtendedPubKey, BTreeSet<Vec<u8>>) {
    let state = persister.load().expect("load");
    let start = state.wallets.get(w).expect("wallet rehydrated");
    let xpub = start
        .wallet
        .accounts
        .account_of_type(external_account())
        .expect("external account restored")
        .account_xpub;
    let managed = start
        .wallet_info
        .all_managed_accounts()
        .into_iter()
        .find(|m| m.managed_account_type().to_account_type() == external_account())
        .expect("managed external account restored");
    let scripts = managed
        .managed_account_type()
        .address_pools()
        .into_iter()
        .flat_map(|pool| pool.addresses.values().map(|i| i.script_pubkey.to_bytes()))
        .collect();
    (xpub, scripts)
}

fn used_scripts(persister: &SqlitePersister, w: &WalletId) -> BTreeSet<Vec<u8>> {
    let conn = persister.lock_conn_for_test();
    core_pool::load_used_addresses(&conn, w, Network::Testnet)
        .expect("used addresses")
        .into_iter()
        .map(|(address, _)| address.script_pubkey().to_bytes())
        .collect()
}

fn request(sender: [u8; 32], recipient: [u8; 32], account_reference: u32) -> ContactRequest {
    ContactRequest {
        sender_id: Identifier::from(sender),
        recipient_id: Identifier::from(recipient),
        sender_key_index: 1,
        recipient_key_index: 2,
        account_reference,
        encrypted_account_label: None,
        encrypted_public_key: vec![9; 96],
        auto_accept_proof: None,
        core_height_created_at: 42,
        created_at: 7,
    }
}

fn contact_key() -> SentContactRequestKey {
    SentContactRequestKey {
        owner_id: Identifier::from(OWNER),
        recipient_id: Identifier::from(FRIEND),
    }
}

/// The established row `note_external_account_registered` writes once the
/// account built from the contact's request `reference` is stored.
/// Store [`stamped_contact`] under an owner identity of `w` (`load()` refuses
/// a contact whose owner it doesn't hold).
fn store_stamp(persister: &SqlitePersister, w: &WalletId, reference: u32, stamp: Option<u32>) {
    ensure_identity(persister, &OWNER, Some(w));
    persister
        .store(
            *w,
            PlatformWalletChangeSet {
                contacts: Some(stamped_contact(reference, stamp)),
                ..Default::default()
            },
        )
        .unwrap();
}

fn stamped_contact(reference: u32, stamp: Option<u32>) -> ContactChangeSet {
    let mut established = BTreeMap::new();
    established.insert(
        contact_key(),
        EstablishedContact {
            contact_identity_id: Identifier::from(FRIEND),
            outgoing_request: request(OWNER, FRIEND, 0),
            incoming_request: request(FRIEND, OWNER, reference),
            alias: None,
            note: None,
            is_hidden: false,
            accepted_accounts: vec![0],
            payment_channel_broken: false,
            contact_account_label: None,
            external_account_reference: stamp,
        },
    );
    ContactChangeSet {
        established,
        ..Default::default()
    }
}

fn loaded_stamp(persister: &SqlitePersister, w: &WalletId) -> Option<u32> {
    let conn = persister.lock_conn_for_test();
    contacts::load_state_for_test(&conn, w, &LoadCtx::strict())
        .expect("contacts load")
        .established
        .get(&contact_key())
        .expect("established contact")
        .external_account_reference
}

fn storage_error(err: PersistenceError) -> Box<WalletStorageError> {
    match err {
        PersistenceError::Backend { source, .. } => source
            .downcast::<WalletStorageError>()
            .unwrap_or_else(|source| panic!("expected WalletStorageError, got {source}")),
        other => panic!("expected Backend {{ .. }}, got {other:?}"),
    }
}

/// The contact rotates: the new xpub's pool replaces the old one, whose rows
/// (with their used flags) move to history keyed by the old xpub.
#[test]
fn new_xpub_rotation_retires_the_old_pool() {
    let (persister, _tmp, _path) = fresh_persister();
    let w = wid(0xE1);
    ensure_wallet_meta(&persister, &w);
    let (a, b) = (contact_xpub(0x0A), contact_xpub(0x0B));

    persister.store(w, registration(a, &[0, 2])).unwrap();
    persister.store(w, registration(b, &[])).unwrap();

    assert_eq!(live_scripts(&persister, &w), scripts_of(b));
    let history = retired(&persister, &w);
    assert_eq!(
        history.keys().cloned().collect::<BTreeSet<_>>(),
        scripts_of(a)
    );
    for info in infos(&pool_entries(a, &[])) {
        let (xpub, used) = &history[&info.script_pubkey.to_bytes()];
        assert_eq!(xpub, &a.encode().to_vec());
        assert_eq!(*used, matches!(info.index, 0 | 2), "index {}", info.index);
    }
    let (xpub, scripts) = loaded_account(&persister, &w);
    assert_eq!(xpub, b);
    assert_eq!(scripts, scripts_of(b));

    // A second rotation keys its history by its own xpub: no collision.
    let c = contact_xpub(0x0C);
    persister.store(w, registration(c, &[])).unwrap();
    assert_eq!(live_scripts(&persister, &w), scripts_of(c));
    let history = retired(&persister, &w);
    assert_eq!(
        history.keys().cloned().collect::<BTreeSet<_>>(),
        &scripts_of(a) | &scripts_of(b)
    );
}

/// The sweep rebuilding an account from the xpub it already has replaces
/// nothing and retires nothing.
#[test]
fn same_xpub_rebuild_retires_nothing() {
    let (persister, _tmp, _path) = fresh_persister();
    let w = wid(0xE2);
    ensure_wallet_meta(&persister, &w);
    let a = contact_xpub(0x0A);

    persister.store(w, registration(a, &[1])).unwrap();
    persister.store(w, registration(a, &[])).unwrap();

    assert_eq!(live_scripts(&persister, &w), scripts_of(a));
    assert!(retired(&persister, &w).is_empty());
    assert!(used_scripts(&persister, &w).contains(&address_at(a, 1).script_pubkey.to_bytes()));
    assert_eq!(loaded_account(&persister, &w).0, a);
}

/// After a relaunch the account comes back on the new xpub with only the new
/// pool, the stamp comes back with it, and an old address is neither in a pool
/// nor used — it is only in the history.
#[test]
fn rotation_and_stamp_survive_a_relaunch() {
    let (persister, _tmp, path) = fresh_persister();
    let w = wid(0xE3);
    ensure_wallet_meta(&persister, &w);
    let (a, b) = (contact_xpub(0x0A), contact_xpub(0x0B));

    persister.store(w, registration(a, &[1])).unwrap();
    persister.store(w, registration(b, &[])).unwrap();
    store_stamp(&persister, &w, 5, Some(5));
    drop(persister);

    let persister = reopen(&path);
    let (xpub, scripts) = loaded_account(&persister, &w);
    assert_eq!(xpub, b);
    assert_eq!(scripts, scripts_of(b));
    let old = address_at(a, 1).script_pubkey.to_bytes();
    assert!(!scripts.contains(&old));
    assert!(!used_scripts(&persister, &w).contains(&old));
    assert_eq!(retired(&persister, &w)[&old], (a.encode().to_vec(), true));
    assert_eq!(loaded_stamp(&persister, &w), Some(5));

    // The re-key that precedes a rebuild clears the stamp; that persists too.
    store_stamp(&persister, &w, 6, None);
    drop(persister);
    assert_eq!(loaded_stamp(&reopen(&path), &w), None);
}

/// A failure after the retire step rolls the whole flush back: the old
/// account, its pool and an empty history are what a relaunch sees, and the
/// retried registration then rotates cleanly.
#[test]
fn a_failure_mid_flush_rolls_the_rotation_back() {
    let (persister, _tmp, path) = fresh_persister();
    let w = wid(0xE4);
    ensure_wallet_meta(&persister, &w);
    let (a, b) = (contact_xpub(0x0A), contact_xpub(0x0B));
    persister.store(w, registration(a, &[0])).unwrap();

    // Fails the first new-pool insert: the retire copy, the live-row delete
    // and the account upsert have all run inside the flush by then.
    persister
        .lock_conn_for_test()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_new_pool AFTER INSERT ON core_address_pool \
             BEGIN SELECT RAISE(ABORT, 'injected mid-flush failure'); END;",
        )
        .unwrap();
    persister
        .store(w, registration(b, &[]))
        .expect_err("the injected failure fails the flush");
    persister
        .lock_conn_for_test()
        .execute_batch("DROP TRIGGER fail_new_pool;")
        .unwrap();

    assert_eq!(live_scripts(&persister, &w), scripts_of(a));
    assert!(retired(&persister, &w).is_empty());
    drop(persister);

    let persister = reopen(&path);
    let (xpub, scripts) = loaded_account(&persister, &w);
    assert_eq!(xpub, a);
    assert_eq!(scripts, scripts_of(a));
    assert!(used_scripts(&persister, &w).contains(&address_at(a, 0).script_pubkey.to_bytes()));

    persister.store(w, registration(b, &[])).unwrap();
    assert_eq!(live_scripts(&persister, &w), scripts_of(b));
    assert_eq!(
        retired(&persister, &w)
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        scripts_of(a)
    );
}

fn pools_only(entries: Vec<AccountAddressPoolEntry>) -> PlatformWalletChangeSet {
    PlatformWalletChangeSet {
        account_address_pools: entries,
        ..Default::default()
    }
}

/// A pool snapshot of the retired xpub that arrives after the rotation (taken
/// before it, flushed after) updates the history instead of failing the
/// flush. It is longer than the new pool (the old one's gap limit grew with
/// its payments), and none of its rows enters the live pool, so the new pool
/// still grows past them.
#[test]
fn a_late_snapshot_of_the_retired_xpub_lands_in_history() {
    let (persister, _tmp, _path) = fresh_persister();
    let w = wid(0xE5);
    ensure_wallet_meta(&persister, &w);
    let (a, b) = (contact_xpub(0x0A), contact_xpub(0x0B));
    persister.store(w, registration(a, &[])).unwrap();
    persister.store(w, registration(b, &[])).unwrap();

    let late = pool_entries_extended(a, &[3, 12], 5);
    persister.store(w, pools_only(late.clone())).unwrap();

    assert_eq!(live_scripts(&persister, &w), scripts_of(b));
    let history = retired(&persister, &w);
    assert_eq!(history.len(), infos(&late).len());
    for info in infos(&late) {
        let (xpub, used) = &history[&info.script_pubkey.to_bytes()];
        assert_eq!(xpub, &a.encode().to_vec());
        assert_eq!(*used, matches!(info.index, 3 | 12), "index {}", info.index);
    }

    // The new pool grows over the indices the late rows had.
    let grown = pool_entries_extended(b, &[11], 5);
    persister.store(w, pools_only(grown.clone())).unwrap();
    let grown_scripts: BTreeSet<_> = infos(&grown)
        .iter()
        .map(|i| i.script_pubkey.to_bytes())
        .collect();
    assert_eq!(live_scripts(&persister, &w), grown_scripts);
}

/// Manual mode merges buffered changesets, so one flush can carry a stale
/// pool snapshot ahead of the rotation that retires it, and two rotations of
/// one account. Every row lands by the xpub it derives from: the last
/// registration's live, each earlier one's in its history.
#[test]
fn rotations_merged_into_one_flush_land_by_derivation() {
    let (persister, _tmp, _path) = fresh_persister_with_mode(FlushMode::Manual);
    let w = wid(0xE8);
    ensure_wallet_meta(&persister, &w);
    let (a, b, c) = (contact_xpub(0x0A), contact_xpub(0x0B), contact_xpub(0x0C));
    persister.store(w, registration(a, &[])).unwrap();
    persister.flush(w).unwrap();

    persister
        .store(w, pools_only(pool_entries_extended(a, &[4], 3)))
        .unwrap();
    persister.store(w, registration(b, &[2])).unwrap();
    persister.store(w, registration(c, &[])).unwrap();
    persister.flush(w).unwrap();

    assert_eq!(live_scripts(&persister, &w), scripts_of(c));
    let history = retired(&persister, &w);
    let a_rows = infos(&pool_entries_extended(a, &[], 3))
        .iter()
        .map(|i| {
            (
                i.script_pubkey.to_bytes(),
                (a.encode().to_vec(), i.index == 4),
            )
        })
        .collect::<Vec<_>>();
    let b_rows = infos(&pool_entries(b, &[]))
        .iter()
        .map(|i| {
            (
                i.script_pubkey.to_bytes(),
                (b.encode().to_vec(), i.index == 2),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(history, a_rows.into_iter().chain(b_rows).collect());
    assert_eq!(loaded_account(&persister, &w).0, c);
}

/// A contact rotating back to an xpub they had gets that generation's rows
/// back, used flags included, and the history keeps only the xpub replaced.
#[test]
fn rotating_back_restores_the_earlier_generation() {
    let (persister, _tmp, _path) = fresh_persister();
    let w = wid(0xE9);
    ensure_wallet_meta(&persister, &w);
    let (a, b) = (contact_xpub(0x0A), contact_xpub(0x0B));
    persister.store(w, registration(a, &[1])).unwrap();
    persister.store(w, registration(b, &[0])).unwrap();
    persister.store(w, registration(a, &[])).unwrap();

    assert_eq!(live_scripts(&persister, &w), scripts_of(a));
    let used = used_scripts(&persister, &w);
    assert!(used.contains(&address_at(a, 1).script_pubkey.to_bytes()));
    assert!(!used.contains(&address_at(b, 0).script_pubkey.to_bytes()));
    let history = retired(&persister, &w);
    assert_eq!(
        history.keys().cloned().collect::<BTreeSet<_>>(),
        scripts_of(b)
    );
    assert_eq!(
        history[&address_at(b, 0).script_pubkey.to_bytes()],
        (b.encode().to_vec(), true)
    );
    assert_eq!(loaded_account(&persister, &w).0, a);
}

/// A snapshot from an xpub the account never had is still a typed-key
/// conflict: only rows of a generation the account had are history.
#[test]
fn a_snapshot_of_an_unknown_xpub_still_conflicts() {
    let (persister, _tmp, _path) = fresh_persister();
    let w = wid(0xE6);
    ensure_wallet_meta(&persister, &w);
    let (a, c) = (contact_xpub(0x0A), contact_xpub(0x0C));
    persister.store(w, registration(a, &[])).unwrap();

    let err = persister
        .store(
            w,
            PlatformWalletChangeSet {
                account_address_pools: pool_entries(c, &[]),
                ..Default::default()
            },
        )
        .expect_err("a foreign typed key conflicts");
    assert!(
        matches!(
            *storage_error(err),
            WalletStorageError::TypedPoolKeyConflict { .. }
        ),
        "expected TypedPoolKeyConflict"
    );
    assert_eq!(live_scripts(&persister, &w), scripts_of(a));
    assert!(retired(&persister, &w).is_empty());
}

/// A database written before fork migration 1 migrates in place: its
/// established contact loads with no stamp (the sweep's "rebuild once"
/// signal), its pool is untouched, and the history starts empty.
#[test]
fn a_pre_fork_v1_database_migrates_with_no_stamp() {
    let (persister, _tmp, path) = fresh_persister();
    let w = wid(0xE7);
    ensure_wallet_meta(&persister, &w);
    let a = contact_xpub(0x0A);
    persister.store(w, registration(a, &[2])).unwrap();
    store_stamp(&persister, &w, 5, Some(5));
    drop(persister);

    // Rewind the file to the V018 schema: what V001..V018 left on disk.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(&format!(
            "DROP TABLE core_address_pool_retired;
             ALTER TABLE contacts DROP COLUMN external_account_reference;
             DROP TABLE {FORK_HISTORY_TABLE};"
        ))
        .unwrap();
    }

    let persister = reopen(&path);
    assert_eq!(loaded_stamp(&persister, &w), None);
    assert_eq!(live_scripts(&persister, &w), scripts_of(a));
    assert!(retired(&persister, &w).is_empty());
    assert!(used_scripts(&persister, &w).contains(&address_at(a, 2).script_pubkey.to_bytes()));
    assert_eq!(loaded_account(&persister, &w).0, a);

    // The healed database rotates like a fresh one.
    let b = contact_xpub(0x0B);
    persister.store(w, registration(b, &[])).unwrap();
    assert_eq!(live_scripts(&persister, &w), scripts_of(b));
    assert_eq!(
        retired(&persister, &w)
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        scripts_of(a)
    );
}

/// Rewinds the file at `path` to what builds before the fork history table
/// recorded: fork migration 1 as upstream version 19. Returns its applied
/// time.
fn as_an_old_fork_build_recorded_it(path: &std::path::Path) -> String {
    let conn = rusqlite::Connection::open(path).unwrap();
    let applied_on: String = conn
        .query_row(
            &format!("SELECT applied_on FROM {FORK_HISTORY_TABLE} WHERE version = 1"),
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute_batch(&format!("DROP TABLE {FORK_HISTORY_TABLE}"))
        .unwrap();
    conn.execute(
        "INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
         VALUES (19, 'dashpay_external_rotation', ?1, ?2)",
        rusqlite::params![applied_on, OLD_FORK_V019_CHECKSUM.to_string()],
    )
    .unwrap();
    applied_on
}

/// A backup an earlier fork build made restores (the guards skip exactly
/// the old row) and the restored file opens reconciled, data intact.
#[test]
fn a_backup_from_a_build_that_recorded_v019_restores_and_opens() {
    let (persister, tmp, _path) = fresh_persister();
    let w = wid(0xE9);
    ensure_wallet_meta(&persister, &w);
    let a = contact_xpub(0x0A);
    persister.store(w, registration(a, &[1])).unwrap();
    store_stamp(&persister, &w, 7, Some(7));
    let backup = persister.backup_to(tmp.path()).unwrap();
    drop(persister);
    as_an_old_fork_build_recorded_it(&backup);

    let dest = tmp.path().join("restored.db");
    SqlitePersister::restore_from_skip_backup(&dest, &backup).unwrap();
    let persister = reopen(&dest);
    assert_eq!(loaded_stamp(&persister, &w), Some(7));
    assert_eq!(live_scripts(&persister, &w), scripts_of(a));
    let conn = persister.lock_conn_for_test();
    let old_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM refinery_schema_history WHERE version = 19",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old_rows, 0);
    let fork: i64 = conn
        .query_row(
            &format!("SELECT MAX(version) FROM {FORK_HISTORY_TABLE}"),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fork, 1);
}

/// A database an earlier fork build wrote recorded fork migration 1 in
/// upstream's history as version 19. It opens: the row moves to the fork's
/// history with its applied time, nothing re-runs, and the contact, its stamp,
/// its pool and the retired generation load as stored.
#[test]
fn a_database_from_a_build_that_recorded_v019_opens_intact() {
    let (persister, _tmp, path) = fresh_persister();
    let w = wid(0xE8);
    ensure_wallet_meta(&persister, &w);
    let (a, b) = (contact_xpub(0x0A), contact_xpub(0x0B));
    persister.store(w, registration(a, &[1])).unwrap();
    persister.store(w, registration(b, &[])).unwrap();
    store_stamp(&persister, &w, 6, Some(6));
    drop(persister);

    let applied_on = as_an_old_fork_build_recorded_it(&path);

    let persister = reopen(&path);
    assert_eq!(loaded_stamp(&persister, &w), Some(6));
    assert_eq!(loaded_account(&persister, &w).0, b);
    assert_eq!(live_scripts(&persister, &w), scripts_of(b));
    assert_eq!(
        retired(&persister, &w)
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        scripts_of(a)
    );
    let conn = persister.lock_conn_for_test();
    let upstream_max: i64 = conn
        .query_row(
            "SELECT MAX(version) FROM refinery_schema_history",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(upstream_max, max_supported_version());
    let fork: (i64, String, String) = conn
        .query_row(
            &format!("SELECT version, name, applied_on FROM {FORK_HISTORY_TABLE}"),
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(fork, (1, "dashpay_external_rotation".into(), applied_on));
}

/// The reconcile runs in the open's migration transaction: an old fork
/// build's file that the open then refuses (here, fork migration 1's column
/// is gone) keeps its old history, with no fork history table.
#[test]
fn a_refused_open_keeps_an_old_fork_files_history() {
    let (persister, _tmp, path) = fresh_persister();
    drop(persister);
    as_an_old_fork_build_recorded_it(&path);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("ALTER TABLE contacts DROP COLUMN external_account_reference")
        .unwrap();

    let err = SqlitePersister::open(SqlitePersisterConfig::new(&path))
        .err()
        .expect("a missing fork column is refused");
    assert!(format!("{err:?}").contains("is missing"), "{err:?}");
    let conn = rusqlite::Connection::open(&path).unwrap();
    let old_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM refinery_schema_history WHERE version = 19",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(old_rows, 1);
    let fork_tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
            [FORK_HISTORY_TABLE],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fork_tables, 0);
}

/// A file a newer build wrote, with fork migrations this build does not
/// have, is refused at open, typed, and left as it was.
#[test]
fn a_newer_fork_history_refuses_to_open() {
    let (persister, _tmp, path) = fresh_persister();
    drop(persister);
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {FORK_HISTORY_TABLE} (version, name, applied_on, checksum)
                 VALUES (2, 'from_a_newer_build', '2026-10-17T00:00:00Z', '1')"
            ),
            [],
        )
        .unwrap();
    }
    let err = SqlitePersister::open(SqlitePersisterConfig::new(&path))
        .err()
        .expect("a newer fork history is refused");
    assert!(
        matches!(
            err,
            WalletStorageError::ForkSchemaVersionUnsupported {
                found: 2,
                max_supported: 1
            }
        ),
        "{err:?}"
    );
    let conn = rusqlite::Connection::open(&path).unwrap();
    let rows: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {FORK_HISTORY_TABLE}"),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 2);
}

/// The history never blocks a live write: a retired generation whose xpub no
/// longer decodes is skipped, and the contact's own pool still stores.
#[test]
fn a_corrupt_retired_xpub_does_not_block_live_writes() {
    let (persister, _tmp, _path) = fresh_persister();
    let w = wid(0xEA);
    ensure_wallet_meta(&persister, &w);
    let (a, b) = (contact_xpub(0x0A), contact_xpub(0x0B));
    persister.store(w, registration(a, &[])).unwrap();
    persister.store(w, registration(b, &[])).unwrap();
    persister
        .lock_conn_for_test()
        .execute(
            "UPDATE core_address_pool_retired SET account_xpub = X'00' WHERE wallet_id = ?1",
            rusqlite::params![w.as_slice()],
        )
        .unwrap();

    persister
        .store(w, pools_only(pool_entries_extended(b, &[1], 2)))
        .unwrap();
    assert!(used_scripts(&persister, &w).contains(&address_at(b, 1).script_pubkey.to_bytes()));
}
