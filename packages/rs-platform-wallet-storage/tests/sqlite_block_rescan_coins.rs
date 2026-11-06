//! Coins a block credits only when dash-spv re-scans it for the addresses
//! its own outputs derive reach the SQLite store through the event adapter,
//! and a reload restores every one of them.

mod common;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use common::fresh_persister;
use dashcore::OutPoint;
use key_wallet::account::{AccountType, StandardAccountType};
use key_wallet::managed_account::address_pool::AddressPoolType;
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::ManagedWalletInfo;
use key_wallet::Wallet;
use platform_wallet::changeset::{
    spawn_wallet_event_adapter, AccountRegistrationEntry, PlatformWalletChangeSet,
    PlatformWalletPersistence, WalletMetadataEntry,
};
use platform_wallet::key_wallet_manager::WalletEvent;
use platform_wallet::test_support::{
    block_paying, external_addresses, process_block_with_rescans, transaction_paying,
    wallet_manager_with_persistence,
};
use platform_wallet::wallet::platform_wallet::{PlatformWalletInfo, WalletId};
use platform_wallet_storage::{SqlitePersister, SqlitePersisterConfig};
use tokio::sync::{mpsc, RwLock};

const VALUE: u64 = 10_000_000;
const PAST_GAP: u32 = 25;
const HEIGHT: u32 = 100;

fn external_gap(wallet: &Wallet, account: AccountType) -> u32 {
    ManagedWalletInfo::from_wallet(wallet, 0)
        .accounts
        .funds_account(&account)
        .expect("account")
        .managed_account_type()
        .address_pools()
        .into_iter()
        .find(|p| p.pool_type == AddressPoolType::External)
        .expect("external pool")
        .gap_limit
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

/// Runs the event adapter over every event the manager queued, into
/// `persister`, until it has stored them all.
async fn persist_queued(
    manager: &Arc<RwLock<platform_wallet::key_wallet_manager::WalletManager<PlatformWalletInfo>>>,
    queued: &mut mpsc::UnboundedReceiver<WalletEvent>,
    persister: &Arc<SqlitePersister>,
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

/// The coins `account` holds after a reload of the store at `path`.
fn reloaded_coins(
    path: &std::path::Path,
    wallet_id: WalletId,
    account: AccountType,
) -> Vec<OutPoint> {
    let reopened = SqlitePersister::open(SqlitePersisterConfig::new(path)).expect("reopen");
    let state = reopened.load().expect("load");
    let slice = state.wallets.get(&wallet_id).expect("the wallet loads");
    slice
        .wallet_info
        .accounts
        .funds_account(&account)
        .expect("account")
        .utxos
        .keys()
        .copied()
        .collect()
}

async fn every_coin_of_one_transaction_past_the_gap_reloads(account: AccountType) {
    let (persister, _tmp, path) = fresh_persister();
    let persister = Arc::new(persister);
    let wallet = Wallet::new_random(
        key_wallet::Network::Testnet,
        WalletAccountCreationOptions::Default,
    )
    .expect("wallet");
    let count = external_gap(&wallet, account) + PAST_GAP;
    let addresses = external_addresses(&wallet, account, count);
    let manifest_wallet = wallet.clone();
    let (manager, wallet_id, mut queued) = wallet_manager_with_persistence(wallet);
    register(&persister, wallet_id, &manifest_wallet);

    let block = block_paying(&addresses, VALUE, HEIGHT);
    process_block_with_rescans(&manager, wallet_id, &block, HEIGHT).await;
    persist_queued(&manager, &mut queued, &persister).await;
    persister.flush(wallet_id).expect("flush");
    drop(persister);

    let txid = block.txdata[0].txid();
    let mut reloaded: Vec<u32> = reloaded_coins(&path, wallet_id, account)
        .into_iter()
        .filter(|o| o.txid == txid)
        .map(|o| o.vout)
        .collect();
    reloaded.sort_unstable();
    assert_eq!(
        reloaded,
        (0..count).collect::<Vec<_>>(),
        "a reload restores every coin the block credited"
    );
}

#[tokio::test]
async fn coinjoin_coins_past_the_gap_in_one_transaction_survive_a_reload() {
    every_coin_of_one_transaction_past_the_gap_reloads(AccountType::CoinJoin { index: 0 }).await;
}

#[tokio::test]
async fn bip44_coins_past_the_gap_in_one_transaction_survive_a_reload() {
    every_coin_of_one_transaction_past_the_gap_reloads(AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    })
    .await;
}

fn bip44_account_0() -> AccountType {
    AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    }
}

/// One block pays two funds accounts, CoinJoin past its gap and BIP44
/// within it. The re-scan passes re-send the BIP44 coins, and a reload puts
/// every coin of each transaction in its own account.
#[tokio::test]
async fn coins_of_two_accounts_at_one_height_reload_into_their_own_accounts() {
    const BIP44_PAID: u32 = 5;
    let (persister, _tmp, path) = fresh_persister();
    let persister = Arc::new(persister);
    let wallet = Wallet::new_random(
        key_wallet::Network::Testnet,
        WalletAccountCreationOptions::Default,
    )
    .expect("wallet");
    let coinjoin = AccountType::CoinJoin { index: 0 };
    let count = external_gap(&wallet, coinjoin) + PAST_GAP;
    let past_gap = transaction_paying(&external_addresses(&wallet, coinjoin, count), VALUE, 1);
    let within_gap = transaction_paying(
        &external_addresses(&wallet, bip44_account_0(), BIP44_PAID),
        VALUE,
        2,
    );
    let manifest_wallet = wallet.clone();
    let (manager, wallet_id, mut queued) = wallet_manager_with_persistence(wallet);
    register(&persister, wallet_id, &manifest_wallet);

    let block = dashcore::Block::dummy(HEIGHT, vec![past_gap.clone(), within_gap.clone()]);
    process_block_with_rescans(&manager, wallet_id, &block, HEIGHT).await;
    persist_queued(&manager, &mut queued, &persister).await;
    persister.flush(wallet_id).expect("flush");
    drop(persister);

    let vouts_of = |account: AccountType, txid: dashcore::Txid| -> Vec<u32> {
        let mut vouts: Vec<u32> = reloaded_coins(&path, wallet_id, account)
            .into_iter()
            .filter(|o| o.txid == txid)
            .map(|o| o.vout)
            .collect();
        vouts.sort_unstable();
        vouts
    };
    assert_eq!(
        vouts_of(coinjoin, past_gap.txid()),
        (0..count).collect::<Vec<_>>()
    );
    assert_eq!(
        vouts_of(bip44_account_0(), within_gap.txid()),
        (0..BIP44_PAID).collect::<Vec<_>>()
    );
    assert!(vouts_of(coinjoin, within_gap.txid()).is_empty());
    assert!(vouts_of(bip44_account_0(), past_gap.txid()).is_empty());
}
