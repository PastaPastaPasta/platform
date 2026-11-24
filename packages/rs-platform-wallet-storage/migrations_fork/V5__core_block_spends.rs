//! A durable record of the wallet's coins that a block spent.
//!
//! Fork migration 5 (4 is reserved for `core_dismissed_txids`). The wallet
//! notes a block's spend of a coin only in memory, and drops the note once
//! the block is final. A row here outlives that: no release, sweep or
//! open-time repair sets a coin with a row unspent, and the load never
//! hands one back as unspent. A row goes only when a chain truncation
//! replaces its block, when the engine rewinds or resets the wallet's chain
//! data, or with its wallet.

pub fn migration() -> String {
    "\
CREATE TABLE core_block_spends (
    wallet_id BLOB NOT NULL,
    outpoint BLOB NOT NULL,
    height INTEGER NOT NULL,
    block_hash BLOB NOT NULL,
    spender_txid BLOB NOT NULL,
    PRIMARY KEY (wallet_id, outpoint),
    FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id) ON DELETE CASCADE
);

CREATE INDEX idx_core_block_spends_height
    ON core_block_spends(wallet_id, height);"
        .to_string()
}
