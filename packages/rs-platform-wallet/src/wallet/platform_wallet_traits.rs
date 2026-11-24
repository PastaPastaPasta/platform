//! Trait implementations for `PlatformWalletInfo`.
//!
//! Implements [`WalletInfoInterface`], [`WalletTransactionChecker`], and
//! [`ManagedAccountOperations`] by delegating to the inner `ManagedWalletInfo`.

use std::collections::BTreeSet;

use async_trait::async_trait;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{Address as DashAddress, OutPoint, ScriptBuf, Transaction, Txid};

use key_wallet::account::AccountType;
use key_wallet::bip32::ExtendedPubKey;
use key_wallet::managed_account::managed_account_collection::ManagedAccountCollection;
use key_wallet::transaction_checking::account_checker::TransactionCheckResult;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::transaction_checking::WalletTransactionChecker;
use key_wallet::wallet::managed_wallet_info::helpers::WalletConflictSweep;
use key_wallet::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::{
    ApplyChainLockOutcome, Truncation, WalletInfoInterface,
};
use key_wallet::wallet::managed_wallet_info::TransactionRecord;
use key_wallet::{Network, Utxo, Wallet, WalletCoreBalance};

use super::platform_wallet::PlatformWalletInfo;
use crate::changeset::BlockSpend;

// ---------------------------------------------------------------------------
// WalletInfoInterface — delegate to `self.core`
// ---------------------------------------------------------------------------

impl WalletInfoInterface for PlatformWalletInfo {
    fn from_wallet(wallet: &Wallet, birth_height: CoreBlockHeight) -> Self {
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

        let inner = ManagedWalletInfo::from_wallet(wallet, birth_height);
        Self {
            core_wallet: inner,
            generation: std::sync::Arc::new(super::core::WalletGeneration::new()),
            identity_manager: super::identity::IdentityManager::new(),
            tracked_asset_locks: std::collections::BTreeMap::new(),
            observed_input_conflicts: Default::default(),
            spent_claim_mirror: Default::default(),
            pending_block_spends: Default::default(),
            block_capture_inputs: None,
            dpns_name_states: std::collections::BTreeMap::new(),
        }
    }

    fn from_wallet_with_name(wallet: &Wallet, name: String, birth_height: CoreBlockHeight) -> Self {
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

        let inner = ManagedWalletInfo::from_wallet_with_name(wallet, name, birth_height);
        Self {
            core_wallet: inner,
            generation: std::sync::Arc::new(super::core::WalletGeneration::new()),
            identity_manager: super::identity::IdentityManager::new(),
            tracked_asset_locks: std::collections::BTreeMap::new(),
            observed_input_conflicts: Default::default(),
            spent_claim_mirror: Default::default(),
            pending_block_spends: Default::default(),
            block_capture_inputs: None,
            dpns_name_states: std::collections::BTreeMap::new(),
        }
    }

    fn network(&self) -> Network {
        self.core_wallet.network()
    }

    fn wallet_id(&self) -> [u8; 32] {
        self.core_wallet.wallet_id()
    }

    fn name(&self) -> Option<&str> {
        self.core_wallet.name()
    }

    fn set_name(&mut self, name: String) {
        self.core_wallet.set_name(name);
    }

    fn description(&self) -> Option<&str> {
        self.core_wallet.description()
    }

    fn set_description(&mut self, description: Option<String>) {
        self.core_wallet.set_description(description);
    }

    fn birth_height(&self) -> CoreBlockHeight {
        self.core_wallet.birth_height()
    }

    // `first_loaded_at` lives on `WalletMetadata` and is read/written
    // directly there; `WalletInfoInterface` has no accessors for it and
    // `ManagedWalletInfo` has no backing methods, so nothing is
    // delegated here.

    fn update_last_synced(&mut self, timestamp: u64) {
        self.core_wallet.update_last_synced(timestamp);
    }

    fn monitored_addresses(&self) -> Vec<DashAddress> {
        self.core_wallet.monitored_addresses()
    }

    fn monitored_script_pubkeys(&self) -> Vec<ScriptBuf> {
        self.core_wallet.monitored_script_pubkeys()
    }

    fn monitored_filter_elements(&self) -> Vec<Vec<u8>> {
        self.core_wallet.monitored_filter_elements()
    }

    fn utxos(&self) -> BTreeSet<&Utxo> {
        self.core_wallet.utxos()
    }

    fn get_spendable_utxos(&self) -> BTreeSet<&Utxo> {
        self.core_wallet.get_spendable_utxos()
    }

    fn balance(&self) -> WalletCoreBalance {
        self.core_wallet.balance()
    }

    fn update_balance(&mut self) {
        self.core_wallet.update_balance();
    }

    fn transaction_history(&self) -> Vec<&TransactionRecord> {
        self.core_wallet.transaction_history()
    }

    fn accounts_mut(&mut self) -> &mut ManagedAccountCollection {
        self.core_wallet.accounts_mut()
    }

    fn accounts(&self) -> &ManagedAccountCollection {
        self.core_wallet.accounts()
    }

    fn unrecorded_spend_heights(&self, tx: &Transaction) -> BTreeSet<u32> {
        self.core_wallet.unrecorded_spend_heights(tx)
    }

    fn immature_transactions(&self) -> Vec<Transaction> {
        self.core_wallet.immature_transactions()
    }

    fn last_processed_height(&self) -> CoreBlockHeight {
        self.core_wallet.last_processed_height()
    }

    fn synced_height(&self) -> CoreBlockHeight {
        self.core_wallet.synced_height()
    }

    fn update_last_processed_height(&mut self, current_height: u32) {
        self.block_capture_inputs = None;
        self.core_wallet
            .update_last_processed_height(current_height);
    }

    fn update_synced_height(&mut self, current_height: u32) {
        self.core_wallet.update_synced_height(current_height);
    }

    fn truncate_above(&mut self, height: CoreBlockHeight) -> Result<Truncation, key_wallet::Error> {
        self.block_capture_inputs = None;
        let truncation = self.core_wallet.truncate_above(height)?;
        self.pending_block_spends
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|spend| spend.height <= height);
        Ok(truncation)
    }

    fn matured_coinbase_records(
        &self,
        old_height: CoreBlockHeight,
        new_height: CoreBlockHeight,
    ) -> Vec<TransactionRecord> {
        self.core_wallet
            .matured_coinbase_records(old_height, new_height)
    }

    fn mark_instant_send_utxos(&mut self, txid: &Txid, lock: &InstantLock) -> bool {
        self.core_wallet.mark_instant_send_utxos(txid, lock)
    }

    fn monitor_revision(&self) -> u64 {
        self.core_wallet.monitor_revision()
    }

    fn account_generation(&self) -> u64 {
        self.core_wallet.account_generation()
    }

    fn is_dismissed(&self, txid: &Txid) -> bool {
        self.core_wallet.is_dismissed(txid)
    }

    fn refetch_on_lock(&self, txid: &Txid) -> bool {
        self.core_wallet.refetch_on_lock(txid)
    }

    fn dismiss_spend(&mut self, tx: &Transaction) -> bool {
        self.core_wallet.dismiss_spend(tx)
    }

    fn undismiss(&mut self, txid: &Txid) {
        self.core_wallet.undismiss(txid)
    }

    fn unconfirmed_spent_outpoints(&self) -> std::collections::BTreeMap<OutPoint, BTreeSet<Txid>> {
        self.core_wallet.unconfirmed_spent_outpoints()
    }

    fn sweep_conflicts_only(
        &mut self,
        tx: &Transaction,
        context: &TransactionContext,
    ) -> WalletConflictSweep {
        self.core_wallet.sweep_conflicts_only(tx, context)
    }

    // Delegate the chain-lock methods to the inner `ManagedWalletInfo`.
    //
    // Without these delegations, `WalletInfoInterface`'s default impls
    // kick in (no-op `apply_chain_lock` returning an empty BTreeMap;
    // `last_applied_chain_lock` returning `None`). That's the bug behind
    // "stuck asset lock #10": upstream's
    // `spawn_chainlock_wallet_dispatch` task receives every validated
    // `ChainLockReceived` event and calls
    // `wallet.write().await.apply_chain_lock(...)`, but our
    // `PlatformWalletInfo` was hitting the trait default — promotion
    // never fired and `metadata.last_applied_chain_lock` stayed `None`.
    fn last_applied_chain_lock(&self) -> Option<&ChainLock> {
        self.core_wallet.last_applied_chain_lock()
    }

    fn apply_chain_lock(&mut self, chain_lock: ChainLock) -> ApplyChainLockOutcome {
        let cl_height = chain_lock.block_height;
        let outcome = self.core_wallet.apply_chain_lock(chain_lock);
        let total_promoted: usize = outcome.locked_transactions.values().map(|v| v.len()).sum();
        tracing::debug!(
            cl_height,
            total_promoted,
            accounts_with_promotions = outcome.locked_transactions.len(),
            metadata_advanced = outcome.metadata_advanced,
            "apply_chain_lock delegated"
        );
        outcome
    }

    // The trait default is a no-op, which would keep every observed spend
    // until the first chain lock is applied.
    fn note_chain_lock_height(&mut self, height: CoreBlockHeight) {
        self.core_wallet.note_chain_lock_height(height);
    }
}

impl PlatformWalletInfo {
    fn unconfirmed_inputs_of_block(
        &mut self,
        block_hash: dashcore::BlockHash,
    ) -> std::sync::Arc<BTreeSet<OutPoint>> {
        if let Some((hash, inputs)) = &self.block_capture_inputs {
            if *hash == block_hash {
                return std::sync::Arc::clone(inputs);
            }
        }
        let inputs = std::sync::Arc::new(
            self.core_wallet
                .unconfirmed_spent_outpoints()
                .into_keys()
                .collect::<BTreeSet<_>>(),
        );
        self.block_capture_inputs = Some((block_hash, std::sync::Arc::clone(&inputs)));
        inputs
    }

    fn holds_or_claims(&self, outpoint: &OutPoint) -> bool {
        self.has_restored_claim(outpoint)
            || self
                .core_wallet
                .accounts
                .all_accounts()
                .into_iter()
                .filter_map(|account| account.as_funds())
                .any(|funds| funds.utxos.contains_key(outpoint))
    }
}

// ---------------------------------------------------------------------------
// WalletTransactionChecker — delegate to `self.core`
// ---------------------------------------------------------------------------

#[async_trait]
impl WalletTransactionChecker for PlatformWalletInfo {
    async fn check_core_transaction(
        &mut self,
        tx: &Transaction,
        context: TransactionContext,
        wallet: &mut Wallet,
        update_state: bool,
        update_balance: bool,
    ) -> TransactionCheckResult {
        let block = context
            .block_info()
            .filter(|_| update_state && !tx.is_coin_base())
            .copied();
        let mut spent: BTreeSet<OutPoint> = match block {
            Some(block) => {
                let pending = self.unconfirmed_inputs_of_block(block.block_hash());
                tx.input
                    .iter()
                    .map(|input| input.previous_output)
                    .filter(|outpoint| pending.contains(outpoint) || self.holds_or_claims(outpoint))
                    .collect()
            }
            None => {
                if update_state {
                    self.block_capture_inputs = None;
                }
                BTreeSet::new()
            }
        };
        let result = self
            .core_wallet
            .check_core_transaction(tx, context, wallet, update_state, update_balance)
            .await;
        if let Some(block) = block {
            let txid = tx.txid();
            if !result.swept_transactions.is_empty() {
                spent.extend(tx.input.iter().map(|input| input.previous_output));
            }
            for record in result.new_records.iter().chain(&result.updated_records) {
                if record.txid != txid {
                    continue;
                }
                for detail in &record.input_details {
                    if let Some(input) = tx.input.get(detail.index as usize) {
                        spent.insert(input.previous_output);
                    }
                }
            }
            if !spent.is_empty() {
                let pending = self
                    .pending_block_spends
                    .get_mut()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                pending.extend(spent.into_iter().map(|outpoint| BlockSpend {
                    outpoint,
                    height: block.height(),
                    block_hash: block.block_hash(),
                    spender_txid: txid,
                }));
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// ManagedAccountOperations — delegate to `self.core`
// ---------------------------------------------------------------------------

impl ManagedAccountOperations for PlatformWalletInfo {
    fn add_managed_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
    ) -> key_wallet::Result<()> {
        self.core_wallet.add_managed_account(wallet, account_type)
    }

    fn add_managed_account_from_xpub(
        &mut self,
        account_type: AccountType,
        account_xpub: ExtendedPubKey,
    ) -> key_wallet::Result<()> {
        self.core_wallet
            .add_managed_account_from_xpub(account_type, account_xpub)
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
    ) -> key_wallet::Result<()> {
        self.core_wallet
            .add_managed_bls_account(wallet, account_type)
    }

    #[cfg(feature = "bls")]
    fn add_managed_bls_account_from_public_key(
        &mut self,
        account_type: AccountType,
        bls_public_key: [u8; 48],
    ) -> key_wallet::Result<()> {
        self.core_wallet
            .add_managed_bls_account_from_public_key(account_type, bls_public_key)
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account(
        &mut self,
        wallet: &Wallet,
        account_type: AccountType,
    ) -> key_wallet::Result<()> {
        self.core_wallet
            .add_managed_eddsa_account(wallet, account_type)
    }

    #[cfg(feature = "eddsa")]
    fn add_managed_eddsa_account_from_public_key(
        &mut self,
        account_type: AccountType,
        ed25519_public_key: [u8; 32],
    ) -> key_wallet::Result<()> {
        self.core_wallet
            .add_managed_eddsa_account_from_public_key(account_type, ed25519_public_key)
    }
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

impl std::fmt::Debug for PlatformWalletInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformWalletInfo")
            .field("wallet_id", &hex::encode(self.core_wallet.wallet_id()))
            .field("identity_count", &self.identity_manager.identity_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use dashcore::{BlockHash, OutPoint, TxIn};
    use key_wallet::transaction_checking::BlockInfo;
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;

    use super::*;

    fn spending(outpoint: OutPoint) -> Transaction {
        Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: outpoint,
                ..Default::default()
            }],
            output: Vec::new(),
            special_transaction_payload: None,
        }
    }

    /// dash-spv commits a matched filter batch only while the account
    /// generation it read stands, so the wrapper reports the wallet's own: a
    /// widened address pool is a new generation.
    #[test]
    fn widening_a_pool_is_a_new_account_generation_of_the_platform_wallet() {
        use key_wallet::account::{AccountType, StandardAccountType};
        use key_wallet::managed_account::address_pool::KeySource;
        use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;

        let wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
            .expect("test wallet");
        let mut info = PlatformWalletInfo::from_wallet(&wallet, 0);
        let bip44 = AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        };
        let xpub = wallet
            .accounts
            .account_of_type(bip44)
            .expect("BIP44 account")
            .account_xpub;
        let before = info.account_generation();

        let account = info
            .core_wallet
            .accounts
            .funds_account_mut(&bip44)
            .expect("account");
        assert!(!account
            .set_gap_limit(200, &KeySource::Public(xpub))
            .unwrap()
            .is_empty());

        assert_eq!(info.account_generation(), before + 1);
        assert_eq!(
            info.account_generation(),
            info.core_wallet.account_generation()
        );
    }

    /// A transaction the core wallet dropped as dead is dead for the wrapper
    /// too, so a delivery of it without a lock reaches no other wallet.
    #[test]
    fn an_abandoned_transaction_is_dismissed_for_the_platform_wallet() {
        use dashcore::hashes::Hash;

        let wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
            .expect("test wallet");
        let mut info = PlatformWalletInfo::from_wallet(&wallet, 0);
        let txid = Txid::from_byte_array([0x07; 32]);
        assert!(!info.is_dismissed(&txid));
        info.core_wallet.abandon_transaction(txid);
        assert!(info.is_dismissed(&txid));
        let child = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![dashcore::TxIn {
                previous_output: dashcore::OutPoint::new(txid, 0),
                ..Default::default()
            }],
            output: vec![],
            special_transaction_payload: None,
        };
        assert!(info.dismiss_spend(&child));
        assert!(info.core_wallet.is_dismissed(&child.txid()));
        info.undismiss(&txid);
        assert!(!info.core_wallet.is_dismissed(&child.txid()));
        assert!(info.refetch_on_lock(&child.txid()));
        assert!(info.core_wallet.refetch_on_lock(&child.txid()));
    }

    /// dash-spv notes a chain-lock height during the initial sync, before a
    /// chain lock is applied. Spends observed at or below the synced height
    /// are final from then on and are forgotten.
    #[tokio::test]
    async fn should_prune_final_observed_spends_when_a_chain_lock_height_is_noted() {
        let mut wallet = Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::None)
            .expect("test wallet");
        let mut info = PlatformWalletInfo::from_wallet(&wallet, 0);
        let final_spend = OutPoint::new(Txid::from([0x01; 32]), 0);
        let open_spend = OutPoint::new(Txid::from([0x03; 32]), 0);
        for (outpoint, height) in [(final_spend, 50), (open_spend, 150)] {
            let block = BlockInfo::new(height, BlockHash::from([0x07; 32]), 1_735_689_600);
            info.check_core_transaction(
                &spending(outpoint),
                TransactionContext::InBlock(block),
                &mut wallet,
                true,
                false,
            )
            .await;
        }
        info.update_synced_height(100);
        assert_eq!(info.core_wallet.observed_spent_outpoints().len(), 2);

        info.note_chain_lock_height(200);

        let observed = info.core_wallet.observed_spent_outpoints();
        assert!(
            !observed.contains_key(&final_spend),
            "a spend at height 50 is final below synced height 100"
        );
        assert!(
            observed.contains_key(&open_spend),
            "a spend at height 150 is above synced height 100"
        );
    }
}
