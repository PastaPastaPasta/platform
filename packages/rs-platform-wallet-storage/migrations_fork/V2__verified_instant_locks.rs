//! Mark the InstantSend locks known to be verified.
//!
//! Fork migration 2. A `core_instant_locks` row makes the coins of its
//! transaction final and spendable on load. Builds before the verified-lock
//! rule (rust-dashcore fork `ab6cb737`) stored any lock a peer announced,
//! verified or not, so a row of unknown provenance must not count.
//!
//! `verified` is 1 only for a row a build that stores verified locks alone
//! wrote; every row already on disk, and any row a build without this column
//! writes later, reads 0 and is not restored. Such a transaction shows as an
//! ordinary unconfirmed payment until a peer announces its lock again or it is
//! mined; the row is removed with the transaction's other rows when it
//! confirms.

pub fn migration() -> String {
    "ALTER TABLE core_instant_locks
         ADD COLUMN verified INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1));"
        .to_string()
}
