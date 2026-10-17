//! DashPay external-account rotation: retire the old pool, persist the stamp.
//!
//! A contact who rotates their payment xpub gets a new `DashpayExternalAccount`
//! under the same account key. The registration upsert already replaces the
//! account's xpub, but every pool row of the old xpub keeps its
//! `(account, pool_type, address_index)` primary key with the old typed public
//! key, so the new pool's index 0 was refused as a typed-key conflict and the
//! whole registration rolled back on every retry: the contact stayed
//! unpayable, and each relaunch reloaded the old account.
//!
//! `core_address_pool_retired` keeps the rows an account derived from an xpub
//! it no longer has, keyed by that xpub (so a second rotation never collides
//! with the first). They stay known for history and attribution; nothing that
//! builds a payable pool reads them. Rows only move here inside the flush that
//! replaces the account's xpub (see `accounts::apply_registrations`).
//!
//! `contacts.external_account_reference` persists
//! `EstablishedContact::external_account_reference`: the `accountReference` of
//! the request the contact's external account was last built from. Before this
//! column every established contact reloaded with `None`, which the library's
//! sweep reads as "rebuild once". Existing rows keep `NULL` and heal the same
//! way on their next sweep.

pub fn migration() -> String {
    "\
CREATE TABLE core_address_pool_retired (
    wallet_id BLOB NOT NULL,
    account_type TEXT NOT NULL,
    account_index INTEGER NOT NULL,
    key_class INTEGER NOT NULL DEFAULT 0,
    user_identity_id BLOB NOT NULL DEFAULT (zeroblob(32)),
    friend_identity_id BLOB NOT NULL DEFAULT (zeroblob(32)),
    -- The BIP32 serialization of the xpub these rows were derived from.
    account_xpub BLOB NOT NULL,
    pool_type INTEGER NOT NULL CHECK (pool_type IN (0, 1, 2, 3)),
    address_index INTEGER NOT NULL,
    script BLOB NOT NULL,
    used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1)),
    public_key BLOB NULL,
    key_type INTEGER NULL CHECK (key_type IS NULL OR key_type IN (0, 1, 2)),
    retired_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (wallet_id, account_type, account_index, key_class, user_identity_id,
                 friend_identity_id, account_xpub, pool_type, address_index),
    FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id) ON DELETE CASCADE
);

CREATE INDEX idx_core_address_pool_retired_script
    ON core_address_pool_retired(wallet_id, script);

ALTER TABLE contacts ADD COLUMN external_account_reference INTEGER NULL
    CHECK (external_account_reference IS NULL
           OR external_account_reference BETWEEN 0 AND 4294967295);"
        .to_string()
}
