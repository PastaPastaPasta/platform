//! A recovery record of the unsigned spends the open drops.
//!
//! Fork migration 3. Opening a writable store drops an unconfirmed
//! transaction that spends one of the wallet's coins without its owner's
//! signature (`core_state::drop_unauthorized_pending_spends`), and gives back
//! the coins it marked spent. Each drop is copied here first, in the same
//! transaction, so it can be put back by hand. Nothing in the wallet reads
//! this table.
//!
//! A row keeps the transaction's `core_transactions` record, its
//! `core_instant_locks` row if it had one, the `core_utxos` rows of its outputs
//! that were deleted, and the `core_utxos` rows of the coins it claimed as they
//! were before they were set unspent. Both row lists are JSON arrays of
//! objects with each column, blobs in hex.

pub fn migration() -> String {
    "\
CREATE TABLE core_dropped_unsigned_spends (
    id INTEGER PRIMARY KEY,
    wallet_id BLOB NOT NULL,
    txid BLOB NOT NULL,
    record_blob BLOB NOT NULL,
    islock_blob BLOB NULL,
    islock_verified INTEGER NULL,
    deleted_outputs TEXT NOT NULL,
    released_coins TEXT NOT NULL,
    dropped_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id) ON DELETE CASCADE
);

CREATE INDEX idx_core_dropped_unsigned_spends_txid
    ON core_dropped_unsigned_spends(wallet_id, txid);"
        .to_string()
}
