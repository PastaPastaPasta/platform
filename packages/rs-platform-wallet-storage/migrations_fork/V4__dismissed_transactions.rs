//! The transactions the wallet dropped as dead.
//!
//! Fork migration 4. The wallet ignores an unconfirmed, unlocked delivery of a
//! transaction it dropped as dead (a loser of a conflict a final transaction
//! won, one the user abandoned, an unsigned claim it removed) and of a spend
//! of one. The wallet keeps that set in memory; this table keeps it across a
//! restart. Each txid a sweep removes is written here, and storing a record of
//! the txid again, as happens once it is locked or mined, deletes it. A load
//! gives the wallet the newest rows.

pub fn migration() -> String {
    "\
CREATE TABLE core_dismissed_transactions (
    id INTEGER PRIMARY KEY,
    wallet_id BLOB NOT NULL,
    txid BLOB NOT NULL,
    UNIQUE (wallet_id, txid),
    FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id) ON DELETE CASCADE
);"
    .to_string()
}
