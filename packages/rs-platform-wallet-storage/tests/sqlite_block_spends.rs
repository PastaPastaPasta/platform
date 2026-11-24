//! Block spends of the wallet's coins reach the SQLite store through the
//! event adapter, and the store drops them only for a truncation, a
//! rewind, a reset, a header-chain mismatch or the wallet's deletion.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::fresh_persister;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::Wallet;
use platform_wallet::changeset::{
    spawn_wallet_event_adapter, AccountRegistrationEntry, ClientStartState,
    PersistenceCapabilities, PersistenceError, PlatformWalletChangeSet, PlatformWalletPersistence,
    WalletMetadataEntry,
};
use platform_wallet::key_wallet_manager::{WalletEvent, WalletInterface, WalletManager};
use platform_wallet::test_support::wallet_manager_with_persistence;
use platform_wallet::wallet::platform_wallet::{PlatformWalletInfo, WalletId};
use platform_wallet_storage::SqlitePersister;
use tokio::sync::{mpsc, RwLock};

/// The SQLite persister, recording each stored round's truncation height.
struct Recording {
    inner: SqlitePersister,
    truncations: Mutex<Vec<Option<u32>>>,
}

impl PlatformWalletPersistence for Recording {
    fn persistence_capabilities(&self) -> PersistenceCapabilities {
        self.inner.persistence_capabilities()
    }

    fn store(
        &self,
        wallet_id: WalletId,
        changeset: PlatformWalletChangeSet,
    ) -> Result<(), PersistenceError> {
        if let Some(core) = changeset.core.as_ref() {
            self.truncations
                .lock()
                .unwrap()
                .push(core.block_spends_truncated_above);
        }
        self.inner.store(wallet_id, changeset)
    }

    fn flush(&self, wallet_id: WalletId) -> Result<(), PersistenceError> {
        self.inner.flush(wallet_id)
    }

    fn load(&self) -> Result<ClientStartState, PersistenceError> {
        self.inner.load()
    }
}

fn register(persister: &SqlitePersister, wallet_id: WalletId, wallet: &Wallet) {
    let manifest = wallet
        .accounts
        .all_accounts()
        .into_iter()
        .map(|a| AccountRegistrationEntry {
            account_type: a.account_type,
            account_xpub: a.account_xpub,
        })
        .collect();
    persister
        .store(
            wallet_id,
            PlatformWalletChangeSet {
                wallet_metadata: Some(WalletMetadataEntry {
                    network: key_wallet::Network::Testnet,
                    wallet_group_id: [0u8; 32],
                    birth_height: 0,
                }),
                account_registrations: manifest,
                ..Default::default()
            },
        )
        .expect("register the wallet");
}

async fn persist_queued(
    manager: &Arc<RwLock<WalletManager<PlatformWalletInfo>>>,
    queued: &mut mpsc::UnboundedReceiver<WalletEvent>,
    persister: &Arc<Recording>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    while let Ok(event) = queued.try_recv() {
        tx.send(event).expect("adapter channel");
    }
    drop(tx);
    let adapter = spawn_wallet_event_adapter(
        Arc::clone(manager),
        Arc::downgrade(persister),
        rx,
        Arc::new(AtomicBool::new(false)),
        tokio_util::sync::CancellationToken::new(),
    );
    tokio::time::timeout(Duration::from_secs(60), adapter)
        .await
        .expect("the adapter drains")
        .expect("the adapter task");
}

fn coin(byte: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([byte; 32]),
        vout: 0,
    }
}

fn spending(coin: OutPoint) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: coin,
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: 1_000,
            script_pubkey: dashcore::Address::dummy(key_wallet::Network::Testnet, 9)
                .script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

/// A store and a manager whose wallet restored claims on three coins, each
/// spent by a foreign transaction in the block at its height (100, 101,
/// 102), with every round persisted. Returns the block hash at each height.
async fn wallet_with_block_spends() -> (
    Arc<Recording>,
    tempfile::TempDir,
    Arc<RwLock<WalletManager<PlatformWalletInfo>>>,
    WalletId,
    mpsc::UnboundedReceiver<WalletEvent>,
    BTreeMap<u32, BlockHash>,
) {
    let (persister, tmp, _path) = fresh_persister();
    let wallet = Wallet::new_random(
        key_wallet::Network::Testnet,
        WalletAccountCreationOptions::Default,
    )
    .expect("wallet");
    let manifest_wallet = wallet.clone();
    let (manager, wallet_id, mut queued) = wallet_manager_with_persistence(wallet);
    register(&persister, wallet_id, &manifest_wallet);
    let persister = Arc::new(Recording {
        inner: persister,
        truncations: Mutex::new(Vec::new()),
    });
    let mut hashes = BTreeMap::new();
    {
        let mut wm = manager.write().await;
        wm.get_wallet_info_mut(&wallet_id)
            .unwrap()
            .restore_spent_outpoints(&[(coin(100), None), (coin(101), None), (coin(102), None)]);
        for height in [100u32, 101, 102] {
            let block = dashcore::Block::dummy(height, vec![spending(coin(height as u8))]);
            hashes.insert(height, block.block_hash());
            wm.process_block_for_wallets(
                &block,
                block.block_hash(),
                height,
                &BTreeSet::from([wallet_id]),
            )
            .await;
        }
        wm.update_wallet_last_processed_height(&wallet_id, 102);
        wm.update_wallet_synced_height(&wallet_id, 102);
    }
    persist_queued(&manager, &mut queued, &persister).await;
    persister.flush(wallet_id).expect("flush");
    (persister, tmp, manager, wallet_id, queued, hashes)
}

fn stored(persister: &Recording, wallet_id: &WalletId) -> BTreeSet<OutPoint> {
    persister
        .inner
        .block_spent_outpoints(wallet_id)
        .expect("read")
        .into_keys()
        .collect()
}

#[tokio::test]
async fn spike_c2_truncate_above_through_the_bridge_deletes_block_spends_above_the_fork() {
    let (persister, _tmp, manager, wallet_id, mut queued, hashes) =
        wallet_with_block_spends().await;
    let rows = persister.inner.block_spent_outpoints(&wallet_id).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[&coin(101)].height, 101);
    assert_eq!(rows[&coin(101)].block_hash, hashes[&101]);
    assert_eq!(rows[&coin(101)].spender_txid, spending(coin(101)).txid());
    persister.truncations.lock().unwrap().clear();

    manager
        .write()
        .await
        .truncate_above(101)
        .expect("truncates");
    persist_queued(&manager, &mut queued, &persister).await;
    persister.flush(wallet_id).expect("flush");

    assert!(persister.truncations.lock().unwrap().contains(&Some(101)));
    assert_eq!(
        stored(&persister, &wallet_id),
        BTreeSet::from([coin(100), coin(101)])
    );
}

#[tokio::test]
async fn spike_c2_load_time_hash_check_deletes_rows_off_the_header_chain() {
    let (persister, _tmp, _manager, wallet_id, _queued, hashes) = wallet_with_block_spends().await;
    let replaced = BlockHash::from_byte_array([0xEE; 32]);

    let unknown_and_matching = BTreeMap::from([(101, None), (102, Some(hashes[&102]))]);
    assert_eq!(
        persister
            .inner
            .delete_block_spends_off_chain(&wallet_id, 99, &unknown_and_matching)
            .unwrap(),
        0,
        "an unknown header and a matching one keep their rows"
    );
    assert_eq!(stored(&persister, &wallet_id).len(), 3);

    let chain = BTreeMap::from([
        (100, Some(replaced)),
        (101, Some(replaced)),
        (102, Some(hashes[&102])),
    ]);
    let deleted = persister
        .inner
        .delete_block_spends_off_chain(&wallet_id, 100, &chain)
        .expect("check");

    assert_eq!(deleted, 1, "only the mismatch above the ChainLock goes");
    assert_eq!(
        stored(&persister, &wallet_id),
        BTreeSet::from([coin(100), coin(102)]),
        "a row at or below the ChainLock stays, and so does one on the chain"
    );
}

#[tokio::test]
async fn a_found_block_spend_is_stored_with_its_coin_marked_spent() {
    let (persister, _tmp, _manager, wallet_id, _queued, _) = wallet_with_block_spends().await;
    let found = platform_wallet::changeset::BlockSpend {
        outpoint: coin(103),
        height: 103,
        block_hash: BlockHash::from_byte_array([0x33; 32]),
        spender_txid: spending(coin(103)).txid(),
    };
    persister
        .inner
        .record_found_block_spend(&wallet_id, found)
        .expect("record");
    let rows = persister.inner.block_spent_outpoints(&wallet_id).unwrap();
    assert_eq!(rows[&coin(103)], found);
}

#[tokio::test]
async fn a_rewind_deletes_block_spends_above_its_checkpoint() {
    let (persister, _tmp, _manager, wallet_id, _queued, _) = wallet_with_block_spends().await;
    assert_eq!(
        persister
            .inner
            .delete_block_spends_above(&wallet_id, 100)
            .unwrap(),
        2
    );
    assert_eq!(stored(&persister, &wallet_id), BTreeSet::from([coin(100)]));
}

#[tokio::test]
async fn a_reset_clears_every_block_spend_of_the_wallet() {
    let (persister, _tmp, _manager, wallet_id, _queued, _) = wallet_with_block_spends().await;
    assert_eq!(persister.inner.clear_block_spends(&wallet_id).unwrap(), 3);
    assert!(stored(&persister, &wallet_id).is_empty());
}

#[tokio::test]
async fn deleting_the_wallet_deletes_its_block_spends() {
    let (persister, _tmp, _manager, wallet_id, _queued, _) = wallet_with_block_spends().await;
    persister
        .inner
        .delete_wallet_skip_backup(wallet_id)
        .expect("delete");
    assert!(stored(&persister, &wallet_id).is_empty());
}

#[tokio::test]
async fn the_block_spends_migration_is_owed_until_marked_and_survives_a_reset() {
    let (persister, _tmp, _manager, wallet_id, _queued, _) = wallet_with_block_spends().await;
    assert!(persister
        .inner
        .persistence_capabilities()
        .contains(PersistenceCapabilities::CORE_BLOCK_SPENDS));
    assert!(
        !persister
            .inner
            .block_spends_migration_done(&wallet_id)
            .unwrap(),
        "a store that just attests the bit owes the migration"
    );

    persister
        .inner
        .mark_block_spends_migration_done(&wallet_id)
        .unwrap();
    persister
        .inner
        .mark_block_spends_migration_done(&wallet_id)
        .unwrap();
    assert!(persister
        .inner
        .block_spends_migration_done(&wallet_id)
        .unwrap());

    persister.inner.clear_block_spends(&wallet_id).unwrap();
    assert!(
        persister
            .inner
            .block_spends_migration_done(&wallet_id)
            .unwrap(),
        "a reset keeps the mark"
    );

    persister
        .inner
        .delete_wallet_skip_backup(wallet_id)
        .expect("delete");
    assert!(
        !persister
            .inner
            .block_spends_migration_done(&wallet_id)
            .unwrap(),
        "a wallet delete removes the mark"
    );
}
