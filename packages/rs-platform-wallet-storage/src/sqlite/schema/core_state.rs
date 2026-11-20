//! Writers + readers for the `core_*` tables.

use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use key_wallet::managed_account::transaction_record::TransactionRecord;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::Utxo;
use platform_wallet::changeset::CoreChangeSet;
use platform_wallet::wallet::platform_wallet::WalletId;

use crate::sqlite::error::WalletStorageError;
use crate::sqlite::load_ctx::{LoadCtx, LoadSite};
use crate::sqlite::schema::blob;
use crate::sqlite::schema::blob::impl_persistable_blob;
use crate::sqlite::schema::core_pool::{owning_account_for_script, OwningAccount};

// PUBLIC material only: core-chain state reaching `record_blob` /
// `islock_blob` (transaction records + InstantLocks are public chain data).
impl_persistable_blob!(TransactionRecord, dashcore::InstantLock);

/// Encode a `ChainLock` to bytes for storage in `core_sync_state`.
fn encode_chain_lock(cl: &ChainLock) -> Result<Vec<u8>, WalletStorageError> {
    Ok(bincode::encode_to_vec(cl, blob::bounded_config())?)
}

/// Decode a `ChainLock` from `core_sync_state.last_applied_chain_lock`.
///
/// Error mapping mirrors [`blob::decode`]: an over-cap payload is
/// [`WalletStorageError::BlobTooLarge`], trailing bytes after the typed
/// length are a `BlobDecode`, and anything else keeps the upstream bincode
/// error as its source.
///
/// # Errors
///
/// Under [`LoadPolicy::Strict`](crate::LoadPolicy) any of the above aborts
/// the load. Under `Recovery` they are counted and the field is left
/// `None`, which the next ChainLock sync repopulates. `BlobTooLarge` is
/// fatal in both — recovery tolerates inconsistent rows, not oversize
/// allocations.
fn decode_chain_lock(bytes: &[u8], ctx: &LoadCtx) -> Result<Option<ChainLock>, WalletStorageError> {
    let failure = match bincode::decode_from_slice::<ChainLock, _>(bytes, blob::bounded_config()) {
        Ok((cl, consumed)) if consumed == bytes.len() => return Ok(Some(cl)),
        Ok(_) => WalletStorageError::blob_decode(
            "unexpected trailing bytes in core_sync_state.last_applied_chain_lock",
        ),
        Err(bincode::error::DecodeError::LimitExceeded) => {
            return Err(WalletStorageError::BlobTooLarge {
                len_bytes: bytes.len(),
                limit_bytes: blob::BLOB_SIZE_LIMIT_BYTES,
            })
        }
        Err(other) => WalletStorageError::from(other),
    };
    ctx.tolerate(LoadSite::ChainLockBlob, failure)?;
    Ok(None)
}

/// Block height of an encoded `last_applied_chain_lock` blob, or `None` if it
/// can't be decoded. Used to monotonic-max-merge the chain lock so an
/// out-of-order lower-height update never regresses the finalized checkpoint.
fn chain_lock_height(bytes: &[u8]) -> Option<u32> {
    match bincode::decode_from_slice::<ChainLock, _>(bytes, blob::bounded_config()) {
        // Require full consumption (like `decode_chain_lock`) so a corrupt
        // stored blob can't out-rank a later valid update and stay stuck.
        Ok((cl, consumed)) if consumed == bytes.len() => Some(cl.block_height),
        _ => None,
    }
}

/// Apply a `CoreChangeSet` inside a transaction.
///
/// Recordless UTXOs write monotonic height-only rows; transaction records win.
pub fn apply(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
    cs: &CoreChangeSet,
) -> Result<(), WalletStorageError> {
    if !cs.records.is_empty() {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO core_transactions \
                (wallet_id, txid, height, block_hash, block_time, finalized, record_blob) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(wallet_id, txid) DO UPDATE SET \
                height = excluded.height, \
                block_hash = excluded.block_hash, \
                block_time = excluded.block_time, \
                finalized = excluded.finalized, \
                record_blob = excluded.record_blob",
        )?;
        for record in &cs.records {
            let block_info = record.block_info();
            let height = block_info.map(|b| i64::from(b.height()));
            let block_hash = block_info.map(|b| AsRef::<[u8]>::as_ref(&b.block_hash()).to_vec());
            let block_time = block_info.map(|b| i64::from(b.timestamp()));
            let finalized = block_info.is_some();
            let payload = blob::encode(record)?;
            stmt.execute(params![
                wallet_id.as_slice(),
                AsRef::<[u8]>::as_ref(&record.txid),
                height,
                block_hash,
                block_time,
                finalized,
                payload,
            ])?;
        }
    }
    // `addresses_derived` is intentionally NOT persisted here — the pool
    // snapshot (`account_address_pools`) is the derived-address source used
    // to resolve UTXO ownership during rehydration.
    if !cs.new_utxos.is_empty() {
        // Blob-bearing records always win; height-only writes never overwrite them.
        // Placeholder confirmation is `height IS NOT NULL`; `finalized` stays 0.
        let mut height_only_stmt = tx.prepare_cached(
            "INSERT INTO core_transactions \
                (wallet_id, txid, height, block_hash, block_time, finalized, record_blob) \
             VALUES (?1, ?2, ?3, NULL, NULL, 0, NULL) \
             ON CONFLICT(wallet_id, txid) DO UPDATE SET height = \
                CASE \
                    WHEN excluded.height IS NOT NULL \
                         AND (core_transactions.height IS NULL \
                              OR excluded.height > core_transactions.height) \
                    THEN excluded.height \
                    ELSE core_transactions.height \
                END \
             WHERE core_transactions.record_blob IS NULL",
        )?;
        let mut utxo_stmt = tx.prepare_cached(UPSERT_UTXO_SQL)?;
        for utxo in &cs.new_utxos {
            let affected = height_only_stmt.execute(params![
                wallet_id.as_slice(),
                AsRef::<[u8]>::as_ref(&utxo.outpoint.txid),
                utxo.is_confirmed.then_some(i64::from(utxo.height)),
            ])?;
            if affected == 0 {
                tracing::debug!(
                    txid = %utxo.outpoint.txid,
                    "existing transaction record blocked a stale height-only write; \
                     refresh the record itself to update its confirmation height"
                );
            }
            execute_upsert_utxo(&mut utxo_stmt, wallet_id, utxo, false)?;
        }
    }
    if !cs.spent_utxos.is_empty() {
        // Only a materialized row takes the in-place fast path. A
        // never-materialised placeholder (`is_sweep_placeholder = 1`, `apply_sweep`'s
        // tombstone) must go through the full upsert instead: the wallet
        // delivering the coin as spent is a delivery, and the collector's
        // soundness argument assumes every delivery materialises the row.
        // Marking the placeholder in place would leave the placeholder flag set and
        // the stamp intact, so `collect_finalized_tombstones` would delete
        // the only durable record of the spend once the boundary passed —
        // and a later rescan re-delivery would land the coin unspent.
        let mut materialised_stmt = tx.prepare_cached(
            "SELECT 1 FROM core_utxos \
             WHERE wallet_id = ?1 AND outpoint = ?2 AND is_sweep_placeholder = 0",
        )?;
        let mut mark_spent_stmt = tx.prepare_cached(
            "UPDATE core_utxos SET spent = 1 WHERE wallet_id = ?1 AND outpoint = ?2",
        )?;
        let mut upsert_stmt = tx.prepare_cached(UPSERT_UTXO_SQL)?;
        for utxo in &cs.spent_utxos {
            let op = blob::encode_outpoint(&utxo.outpoint)?;
            let materialised: bool = materialised_stmt
                .query_row(params![wallet_id.as_slice(), &op[..]], |_| Ok(true))
                .optional()?
                .unwrap_or(false);
            if materialised {
                mark_spent_stmt.execute(params![wallet_id.as_slice(), &op[..]])?;
            } else {
                execute_upsert_utxo(&mut upsert_stmt, wallet_id, utxo, true)?;
            }
        }
    }
    if !cs.instant_locks_for_non_final_records.is_empty() {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO core_instant_locks (wallet_id, txid, islock_blob, verified) \
             VALUES (?1, ?2, ?3, 1) \
             ON CONFLICT(wallet_id, txid) DO UPDATE SET islock_blob = excluded.islock_blob, \
             verified = 1",
        )?;
        for (txid, islock) in &cs.instant_locks_for_non_final_records {
            let payload = blob::encode(islock)?;
            stmt.execute(params![
                wallet_id.as_slice(),
                AsRef::<[u8]>::as_ref(txid),
                payload
            ])?;
        }
    }
    let chainlock_height = cs
        .last_applied_chain_lock
        .as_ref()
        .map(|cl| cl.block_height);
    let heights_advanced = cs.last_processed_height.is_some()
        || cs.synced_height.is_some()
        || chainlock_height.is_some();
    if heights_advanced {
        let cl_bytes = cs
            .last_applied_chain_lock
            .as_ref()
            .map(encode_chain_lock)
            .transpose()?;
        upsert_sync_state(
            tx,
            wallet_id,
            cs.last_processed_height,
            cs.synced_height,
            cl_bytes,
            chainlock_height,
        )?;
    }
    // Sweeps run last so a winner arriving in this very changeset has its
    // own rows committed before the removal below touches the coins it took,
    // and batch by batch in order: each sweep is only true of the wallet it
    // saw, so a later one keeping a coin spent has to be able to correct an
    // earlier one that freed it.
    if cs.sweeps.is_empty() {
        // The ordinary round. Everything below serves the sweep loop, and
        // building the survivor set would hash every input of every record
        // for a loop that never runs — with the write transaction open.
        if heights_advanced {
            collect_finalized_tombstones(tx, wallet_id)?;
        }
        return Ok(());
    }

    // The surviving claims are a property of the whole changeset, not of any
    // one batch, so they are built once: the adapter folds up to a full drain
    // into a single store, and rebuilding them per batch would re-hash every
    // swept txid and every surviving record input once per sweep, with the
    // write transaction open the whole time.
    //
    // `apply_sweep` below is what attributes a held input to `superseded_by`
    // via `spent_in_txid`, and that only happens once it runs — so at this
    // point in the round the table cannot yet tell a live claim in *this*
    // round from the one a sweep is about to displace. The changeset carries
    // the answer instead: any record in this round that is not swept by *any*
    // batch and spends a released outpoint is that live claim, and the coin
    // stays spent.
    let swept_txids: HashSet<dashcore::Txid> = cs
        .sweeps
        .iter()
        .flat_map(|b| b.txids.iter())
        .copied()
        .collect();
    // Only a round that actually releases something reads this, and the
    // common sweep — a resend whose winner spends every input its loser did
    // — releases nothing. Hashing every surviving record's inputs for such a
    // round would pay a per-record cost, with the writer held, for a set
    // nothing consults. Same reasoning as the lazily-built `stored_claims`
    // below.
    let releases_anything = cs
        .sweeps
        .iter()
        .any(|batch| !batch.released_outpoints.is_empty());
    let claimed_by_survivors: HashSet<dashcore::OutPoint> = if releases_anything {
        cs.records
            .iter()
            .filter(|record| !swept_txids.contains(&record.txid))
            .flat_map(|record| record.transaction.input.iter())
            .map(|input| input.previous_output)
            .collect()
    } else {
        HashSet::new()
    };
    // The changeset is not the whole answer, though. Upstream computes
    // `released_outpoints` from its *live* records, and under the default
    // `keep-finalized-transactions = off` a chainlocked record is pruned to
    // its bare txid — the pinned `TransactionsSwept::released_outpoints`
    // doc records this exact limitation ("the inputs of a pruned record
    // survive nowhere else, so this cannot be resolved at this layer").
    // It CAN be resolved at this layer: this store never prunes a
    // `core_transactions` row on finalization, so the full input set of
    // every settled spend the wallet has forgotten is still on disk. A
    // release naming a coin such a record still claims is upstream
    // reporting its own amnesia — honouring it flips the materialized UTXO
    // to `spent = 0` and hands a provably consumed coin back as spendable
    // after the next load, a guaranteed double spend. The same applies
    // after a restart for every NETWORK-FINAL record (IS-locked, in-block,
    // chainlocked): hydration rebuilds the in-memory wallet without its
    // transaction history, so every settled claim the store holds is one
    // upstream can no longer see. Bare mempool rows are deliberately not
    // part of the veto — see `surviving_stored_input_claims` for why a
    // stale one must not strand a legitimately released coin.
    //
    // `stored_input_claims` is therefore upstream's own `retain_unclaimed`
    // predicate — "drop outpoints some surviving record still spends" —
    // re-evaluated against the unpruned history. Built lazily and at most
    // once per round: only a batch whose released set survives the
    // in-round filter above pays for it, and the common sweep (a resend
    // whose winner spends every input its loser did) releases nothing.
    let mut stored_claims: Option<HashSet<dashcore::OutPoint>> = None;
    for batch in &cs.sweeps {
        // Only this stays per batch: a release is true of the wallet its own
        // sweep saw, which is what lets a later batch correct an earlier one.
        let mut released: HashSet<dashcore::OutPoint> = batch
            .released_outpoints
            .iter()
            .filter(|outpoint| !claimed_by_survivors.contains(outpoint))
            .copied()
            .collect();
        if !released.is_empty() {
            let claims = match stored_claims.as_ref() {
                Some(claims) => claims,
                None => {
                    stored_claims =
                        Some(surviving_stored_input_claims(tx, wallet_id, &swept_txids)?);
                    stored_claims.as_ref().expect("just assigned")
                }
            };
            released.retain(|outpoint| !claims.contains(outpoint));
        }
        for loser_txid in &batch.txids {
            apply_sweep(
                tx,
                wallet_id,
                loser_txid,
                &batch.superseded_by,
                &released,
                &swept_txids,
                batch.winner_mined_height,
            )?;
        }
        // Releases are outpoint-keyed facts, so they are applied by outpoint
        // once the batch's losers are done — not only through each loser's
        // decoded inputs above. A chained-sweep claim is a `core_utxos`
        // placeholder that exists independently of any transaction row, and
        // the loser now freeing it need not have one: a fatal flush error
        // wipes a buffered round (the winner's record with it) while the
        // faulted wallet keeps persisting later rounds, and `apply_sweep`
        // above returns before its input loop when the swept txid has no
        // row. Dropping the release set there would leave the held
        // placeholder in place, with `execute_upsert_utxo`'s valve keeping
        // it spent through every funding upsert, forever — the release is
        // the one channel that clears it. Running after the loser loop
        // rather than inside it changes nothing for inputs the loop already
        // freed (same UPDATE, idempotent), and a coin a surviving record in
        // this round re-claimed was already filtered out of `released`
        // above.
        if !released.is_empty() {
            // A released claim that never materialised is deleted outright
            // rather than flipped to `spent = 0`: the row is all placeholder
            // (`value = 0`, `script = X''`, placeholder flag set), so releasing it in
            // place would surface a zero-value phantom coin through
            // `list_unspent_utxos`. No row is the correct end state — if the
            // funding output ever classifies, its ordinary upsert creates
            // the real row freshly unspent, exactly as if the dead claim had
            // never existed. Materialised rows carry real funding data and
            // are released in place as before.
            //
            // An output of a transaction swept in this very round is the
            // one exception, and it is deleted whatever its shape: a coin
            // created by a dead transaction cannot be unspent, only gone.
            // The loser loop already refuses to release such an outpoint
            // (it deletes the row and moves on), but this pass runs
            // regardless of whether the parent's own record survived —
            // that is its whole point — and with the parent's row lost
            // nothing above has removed the parent's materialised output,
            // so releasing it in place would hand back a spendable coin
            // from a transaction that can never confirm.
            let mut swept_output_drop_stmt =
                tx.prepare_cached("DELETE FROM core_utxos WHERE wallet_id = ?1 AND outpoint = ?2")?;
            let mut release_drop_stmt = tx.prepare_cached(
                "DELETE FROM core_utxos \
                 WHERE wallet_id = ?1 AND outpoint = ?2 AND is_sweep_placeholder = 1",
            )?;
            let mut release_stmt = tx.prepare_cached(
                "UPDATE core_utxos SET spent = 0, spent_in_txid = NULL \
                 WHERE wallet_id = ?1 AND outpoint = ?2",
            )?;
            for outpoint in &released {
                let key = blob::encode_outpoint(outpoint)?;
                if swept_txids.contains(&outpoint.txid) {
                    swept_output_drop_stmt.execute(params![wallet_id.as_slice(), &key[..]])?;
                    continue;
                }
                let dropped = release_drop_stmt.execute(params![wallet_id.as_slice(), &key[..]])?;
                if dropped == 0 {
                    release_stmt.execute(params![wallet_id.as_slice(), &key[..]])?;
                }
            }
        }
    }
    if heights_advanced {
        collect_finalized_tombstones(tx, wallet_id)?;
    }
    Ok(())
}

/// The union of every input outpoint claimed by a surviving
/// `core_transactions` row — every row except this round's swept losers,
/// whose deletion the round itself performs.
///
/// This is the durable mirror of upstream's `retain_unclaimed` claimed-set,
/// with one decisive difference: it includes records the in-memory wallet
/// has pruned (chainlocked, under the default
/// `keep-finalized-transactions = off`) or lost across a restart.
///
/// Only NETWORK-FINAL claimants count: InstantSend-locked (settled under
/// DIP-10 the moment the lock lands), in-block, or chainlocked. A bare
/// `Mempool` row is deliberately not settled-spend evidence, because it is
/// the one context that can go stale forever: an evicted or abandoned
/// mempool transaction has no removal path in this store other than a later
/// sweep (upstream's abandon path emits no events —
/// dashpay/rust-dashcore#976), and restoration deliberately does not
/// repopulate ordinary transaction history, so nothing ever re-asserts or
/// retracts the row. Letting it veto an authoritative release would leave
/// the coin attributed to an unrelated winner and durably spent — the
/// mirror image of the wrong-release bug this guard exists to stop. This is
/// also exactly the mobile stores' rule: their link guard protects a
/// network-final spender's link and lets a mempool link be replaced. A LIVE
/// mempool claim loses nothing here: in-session upstream holds the record
/// and never names its inputs released, and within the round
/// `claimed_by_survivors` carries the changeset's own mempool records. The
/// one accepted trade: after a restart a still-alive mempool claimant on
/// disk no longer vetoes, so the release wins and the coin may be
/// transiently re-offered while that pending spend races — self-resolving
/// when the pending spend confirms or dies, and strictly better than a
/// permanent strand.
///
/// Fails CLOSED. This scan is the final guard against re-crediting a
/// consumed coin, so a malformed stored key must fail the round rather than
/// silently drop that row's veto: a `txid` column of the wrong length and a
/// record blob whose decoded `TransactionRecord::txid` disagrees with the
/// typed key (the key is what excludes a row as a swept loser) are both
/// `BlobDecode` errors, matching the other typed-column readers.
///
/// One pass over the wallet's rows, decoding each blob once — the same
/// build-the-set-then-probe shape (and rationale) as upstream's
/// `retain_unclaimed`: released sets follow the input count of a
/// transaction a remote peer picks, so probing per candidate would be
/// `O(released × history)` instead. The pass itself is `O(history)` blob
/// decodes, paid only by a round whose sweep actually frees candidate
/// coins — rare organically, and an attacker can only force one per
/// on-chain final transaction they pay for.
fn surviving_stored_input_claims(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
    swept_txids: &HashSet<dashcore::Txid>,
) -> Result<HashSet<dashcore::OutPoint>, WalletStorageError> {
    use dashcore::hashes::Hash;

    let locks = verified_instant_locks(tx, wallet_id)?;
    let mut stmt =
        tx.prepare_cached("SELECT txid, record_blob FROM core_transactions WHERE wallet_id = ?1 AND record_blob IS NOT NULL")?;
    let mut rows = stmt.query(params![wallet_id.as_slice()])?;
    let mut claims: HashSet<dashcore::OutPoint> = HashSet::new();
    while let Some(row) = rows.next()? {
        let txid_bytes: Vec<u8> = row.get(0)?;
        let Ok(txid_array) = <[u8; 32]>::try_from(txid_bytes.as_slice()) else {
            return Err(WalletStorageError::blob_decode(
                "core_transactions.txid must be exactly 32 bytes",
            ));
        };
        let key_txid = dashcore::Txid::from_byte_array(txid_array);
        if swept_txids.contains(&key_txid) {
            continue;
        }
        let blob_bytes: Vec<u8> = row.get(1)?;
        let record: TransactionRecord = blob::decode(&blob_bytes)?;
        if record.txid != key_txid {
            return Err(WalletStorageError::blob_decode(
                "core_transactions.txid disagrees with the decoded record's txid",
            ));
        }

        if matches!(
            effective_context(&record.context, locks.get(&key_txid)),
            TransactionContext::Mempool
        ) {
            continue;
        }
        claims.extend(
            record
                .transaction
                .input
                .iter()
                .map(|input| input.previous_output),
        );
    }
    Ok(claims)
}

/// Undo what a build without the pending-spend check stored for an
/// unconfirmed transaction that spends one of the wallet's coins without its
/// owner's signature. Such a transaction is now ignored on arrival, but an
/// older build recorded it and marked the coin spent, and a load restores
/// only unspent coins, so the coin stayed missing.
///
/// A transaction counts as such only when it is neither mined nor backed by
/// a lock row stored as verified, and [`verify_input_authorization`] proves
/// one of its inputs unsigned for the stored coin it spends, the rule the
/// wallet applies on arrival. Its row, its lock row and its unspent outputs
/// go; each coin it claimed is unspent again unless another stored
/// transaction spends it too. Running it again finds nothing more.
///
/// [`verify_input_authorization`]: key_wallet::transaction_checking::verify_input_authorization
pub(crate) fn drop_unauthorized_pending_spends(
    tx: &Transaction<'_>,
) -> Result<usize, WalletStorageError> {
    let mut pending: Vec<(WalletId, TransactionRecord)> = Vec::new();
    {
        let mut stmt = tx.prepare_cached(
            "SELECT wallet_id, txid, length(record_blob), record_blob FROM core_transactions \
             WHERE height IS NULL AND record_blob IS NOT NULL",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let wallet_id: Vec<u8> = row.get(0)?;
            let Ok(wallet_id) = WalletId::try_from(wallet_id.as_slice()) else {
                continue;
            };
            let Some(record) = readable_record(row.get(1)?, row.get(2)?, row.get(3)?) else {
                continue;
            };
            pending.push((wallet_id, record));
        }
    }

    let mut dropped: BTreeMap<WalletId, Vec<TransactionRecord>> = BTreeMap::new();
    {
        let mut coin_stmt = tx.prepare_cached(
            "SELECT value, script FROM core_utxos \
             WHERE wallet_id = ?1 AND outpoint = ?2 AND is_sweep_placeholder = 0",
        )?;
        for (wallet_id, record) in pending {
            if record.block_info().is_some()
                || verified_instant_lock(tx, &wallet_id, &record.txid)?.is_some()
            {
                continue;
            }
            let mut unauthorized = false;
            for (index, input) in record.transaction.input.iter().enumerate() {
                let op = blob::encode_outpoint(&input.previous_output)?;
                let Some((value, script)) = coin_stmt
                    .query_row(params![wallet_id.as_slice(), &op[..]], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .optional()?
                else {
                    continue;
                };
                let Ok(value) = u64::try_from(value) else {
                    return Err(WalletStorageError::blob_decode(
                        "core_utxos.value must not be negative",
                    ));
                };
                let prevout = dashcore::TxOut {
                    value,
                    script_pubkey: dashcore::ScriptBuf::from_bytes(script),
                };
                if key_wallet::transaction_checking::verify_input_authorization(
                    &record.transaction,
                    index,
                    &prevout,
                ) == Ok(false)
                {
                    unauthorized = true;
                    break;
                }
            }
            if unauthorized {
                dropped.entry(wallet_id).or_default().push(record);
            }
        }
    }

    let mut count = 0;
    for (wallet_id, records) in dropped {
        let dropped_txids: HashSet<dashcore::Txid> = records.iter().map(|r| r.txid).collect();
        let Some(claimed) = stored_input_claims_except(tx, &wallet_id, &dropped_txids)? else {
            continue;
        };
        for record in records {
            let txid: &[u8] = record.txid.as_ref();
            let mut deleted = Vec::new();
            for vout in 0..record.transaction.output.len() {
                let Ok(vout) = u32::try_from(vout) else {
                    break;
                };
                let op = blob::encode_outpoint(&dashcore::OutPoint {
                    txid: record.txid,
                    vout,
                })?;
                if let Some(row) = kept_output_row(tx, &wallet_id, &op)? {
                    deleted.push((op, row));
                }
            }
            let mut released = Vec::new();
            for input in &record.transaction.input {
                if claimed.contains(&input.previous_output) {
                    continue;
                }
                let op = blob::encode_outpoint(&input.previous_output)?;
                if let Some(row) = releasable_coin_row(tx, &wallet_id, &op, txid)? {
                    released.push((op, row));
                }
            }
            let json = |rows: &[(Vec<u8>, String)]| {
                format!(
                    "[{}]",
                    rows.iter()
                        .map(|(_, row)| row.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            tx.execute(
                "INSERT INTO core_dropped_unsigned_spends \
                    (wallet_id, txid, record_blob, islock_blob, islock_verified, \
                     deleted_outputs, released_coins) \
                 SELECT t.wallet_id, t.txid, t.record_blob, l.islock_blob, l.verified, ?3, ?4 \
                 FROM core_transactions t LEFT JOIN core_instant_locks l \
                    ON l.wallet_id = t.wallet_id AND l.txid = t.txid \
                 WHERE t.wallet_id = ?1 AND t.txid = ?2",
                params![wallet_id.as_slice(), txid, json(&deleted), json(&released)],
            )?;
            tx.execute(
                "DELETE FROM core_transactions WHERE wallet_id = ?1 AND txid = ?2",
                params![wallet_id.as_slice(), txid],
            )?;
            tx.execute(
                "DELETE FROM core_instant_locks WHERE wallet_id = ?1 AND txid = ?2",
                params![wallet_id.as_slice(), txid],
            )?;
            for (op, _) in &deleted {
                tx.execute(
                    "DELETE FROM core_utxos WHERE wallet_id = ?1 AND outpoint = ?2",
                    params![wallet_id.as_slice(), &op[..]],
                )?;
            }
            for (op, _) in &released {
                tx.execute(
                    "UPDATE core_utxos SET spent = 0, spent_in_txid = NULL \
                     WHERE wallet_id = ?1 AND outpoint = ?2",
                    params![wallet_id.as_slice(), &op[..]],
                )?;
            }
            count += 1;
        }
    }
    if count > 0 {
        tracing::warn!(
            count,
            "dropped unconfirmed transactions that spend a coin without its owner's \
             signature; kept in core_dropped_unsigned_spends"
        );
    }
    Ok(count)
}

/// The JSON object of each `core_utxos` column, blobs in hex, for a kept row.
const KEPT_UTXO_COLUMNS: &str = "json_object('outpoint', hex(outpoint), 'value', value, \
    'script', hex(script), 'spent', spent, 'spent_in_txid', hex(spent_in_txid), \
    'winner_mined_height', winner_mined_height, 'is_sweep_placeholder', is_sweep_placeholder)";

/// The unspent, materialised output row at `outpoint`, kept as JSON.
fn kept_output_row(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
    outpoint: &[u8],
) -> Result<Option<String>, WalletStorageError> {
    let mut stmt = tx.prepare_cached(&format!(
        "SELECT {KEPT_UTXO_COLUMNS} FROM core_utxos \
         WHERE wallet_id = ?1 AND outpoint = ?2 AND spent = 0 AND is_sweep_placeholder = 0"
    ))?;
    Ok(stmt
        .query_row(params![wallet_id.as_slice(), outpoint], |row| row.get(0))
        .optional()?)
}

/// The row at `outpoint`, kept as JSON, if dropping `dropper` may give its
/// coin back: a materialised row held spent by nothing but `dropper` (no
/// sweep named another winner for it), whose script one of the wallet's own
/// address pools derived, not a contact's.
fn releasable_coin_row(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
    outpoint: &[u8],
    dropper: &[u8],
) -> Result<Option<String>, WalletStorageError> {
    let mut stmt = tx.prepare_cached(&format!(
        "SELECT {KEPT_UTXO_COLUMNS} FROM core_utxos u \
         WHERE u.wallet_id = ?1 AND u.outpoint = ?2 AND u.spent = 1 \
           AND u.is_sweep_placeholder = 0 \
           AND (u.spent_in_txid IS NULL OR u.spent_in_txid = ?3) \
           AND EXISTS (SELECT 1 FROM core_address_pool p \
                       WHERE p.wallet_id = u.wallet_id AND p.script = u.script \
                         AND p.account_type <> 'dashpay_external')"
    ))?;
    Ok(stmt
        .query_row(params![wallet_id.as_slice(), outpoint, dropper], |row| {
            row.get(0)
        })
        .optional()?)
}

/// A stored record the repair can trust, or `None` for a row the readers
/// report under the load policy instead.
fn readable_record(txid: Vec<u8>, length: i64, blob_bytes: Vec<u8>) -> Option<TransactionRecord> {
    blob::check_size(length).ok()?;
    let record: TransactionRecord = blob::decode(&blob_bytes).ok()?;
    (AsRef::<[u8]>::as_ref(&record.txid) == txid.as_slice()).then_some(record)
}

/// Every outpoint a stored transaction of the wallet spends, whatever its
/// finality, except the transactions in `except`; `None` when a row cannot
/// be read, so no claim can be ruled out.
fn stored_input_claims_except(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
    except: &HashSet<dashcore::Txid>,
) -> Result<Option<HashSet<dashcore::OutPoint>>, WalletStorageError> {
    let mut stmt = tx.prepare_cached(
        "SELECT txid, length(record_blob), record_blob FROM core_transactions \
         WHERE wallet_id = ?1 AND record_blob IS NOT NULL",
    )?;
    let mut rows = stmt.query(params![wallet_id.as_slice()])?;
    let mut claims = HashSet::new();
    while let Some(row) = rows.next()? {
        let Some(record) = readable_record(row.get(0)?, row.get(1)?, row.get(2)?) else {
            return Ok(None);
        };
        if except.contains(&record.txid) {
            continue;
        }
        claims.extend(
            record
                .transaction
                .input
                .iter()
                .map(|input| input.previous_output),
        );
    }
    Ok(Some(claims))
}

/// Delete a swept transaction's row and outputs, then resolve the coins it
/// claimed to spend.
///
/// A swept transaction was a recorded spend that a later, final transaction
/// provably beat to one of its inputs, so it can never confirm — the wallet
/// has already dropped it. Leaving the mirrored row in place would hand it
/// back at the next `load()` and replay a balance the wallet has already
/// corrected. It would also leave an InstantSend loser answerable through
/// `get_core_tx_record`, which sent-payment reconciliation reads as final and
/// would use to advance a dead DashPay payment to `Confirmed`.
///
/// Deleting the row and the UTXOs it created is the easy half. The coins it
/// claimed to *spend* split in two, and `released` — computed upstream and
/// carried on the changeset — is the authority on which is which: an input
/// named there came free, because no surviving transaction spends it too;
/// every other input the loser claimed was taken by the transaction that beat
/// it and is gone for good.
///
/// Recomputing that split here is not an option even though this schema
/// stores whole records. The transaction that took the rest need not be
/// wallet-relevant at all — it can spend our coin while paying only external
/// addresses, and then it is never recorded anywhere in this store — and even
/// a relevant one is not guaranteed to arrive in the same round as the sweep.
///
/// A held input can also have no `core_utxos` row at all: this wallet can
/// persist the loser before its own funding output was ever classified as
/// ours, so the outpoint the loser claims to spend has nothing to update.
/// Losing that claim would matter — the funding transaction has not shown up
/// yet, and when it eventually does, the ordinary UTXO upsert would treat the
/// outpoint as freshly unspent — so a held-but-absent input gets a row of its
/// own here: `spent = 1`, `spent_in_txid = superseded_by`, everything else a
/// placeholder the real funding data overwrites on arrival.
/// `execute_upsert_utxo`'s conflict clause is what makes that placeholder
/// durable — it refuses to clear `spent` on a never-materialised held row
/// (`is_sweep_placeholder = 1 AND spent = 1`), so the claim survives the funding
/// upsert instead of being upserted away by it. The hold is keyed on that
/// shape rather than on `spent_in_txid`, which the
/// `setnull_core_utxos_on_tx_delete` trigger can clear underneath it (see
/// the valve's own comment); the link names the current claimant for the
/// chained-sweep re-point below and is informational otherwise.
///
/// The placeholder is created for EVERY sweep context; only the stamp
/// differs. A BLOCK-CONTEXT sweep (`winner_mined_height` is `Some`)
/// stamps the winner's own mined height — the projection of key-wallet's
/// `observed_spent_outpoints`, which maps each outpoint observed spent in
/// a block to the height of the block that spent it — and
/// `collect_finalized_tombstones` evicts the row once the chainlock
/// finality boundary reaches that height, key-wallet's
/// `prune_finalized_observed_spends` condition verbatim. A
/// MEMPOOL-CONTEXT sweep (IS-locked winner, unmined) writes the same row
/// UNSTAMPED (`winner_mined_height` NULL), and the collector never takes
/// an unstamped row. The in-memory model an unstamped row mirrors is not
/// `observed_spent_outpoints` (which indeed records nothing for an
/// unconfirmed spend) but the account's `spent_outpoints`:
/// `drop_conflicted_transactions` deletes the loser and RETAINS the
/// winner's shared inputs there — a hold that carries no height, because
/// under DIP-10 the IS lock alone settles the input. That set is
/// `serde(skip_serializing)` upstream and rebuilt from live records on
/// load, so after the sweep no record can reconstruct it; this row is the
/// hold's only durable carrier, and dropping it lets a post-restart
/// funding delivery credit a coin the network has already consumed.
///
/// Nothing may collect an unstamped row, ever: an IS-locked winner has no
/// mining deadline, and the funding transaction of an input it spends may
/// itself be IS-locked and unmined (DIP-10 eligibility allows chained
/// locks), so no height watermark can prove the funding output "delivered
/// or never will be". An unstamped row instead leaves the set only
/// through proof: the funding upsert materialises it (a wallet-owned
/// claim — DIP-10 eligibility means the funding tx is mined or will mine,
/// and BIP158 matches its block by our script, so delivery is guaranteed;
/// the row clears its placeholder flag and becomes an ordinary spent coin), a
/// later block-context sweep re-points it and stamps it into the
/// collectible set, or a release deletes it.
///
/// The residue is foreign inputs — a swept INCOMING payment reaches this
/// loop too, and a sender-owned input's funding output never delivers, so
/// its unstamped row is permanent. It cannot be gated by ownership
/// because nothing anywhere can prove an input foreign (`input_details`
/// and `direction` are computed from the wallet's UTXO snapshot AT RECORD
/// TIME; dashpay/rust-dashcore#968 — the once-proposed "held outpoints
/// attested ours" set is empty by construction). What bounds the residue
/// is attack cost, not collection: masternodes lock first-seen, so for
/// the winner to earn the IS lock this sweep requires, the conflicting
/// loser must have been delivered straight to this wallet while withheld
/// from the network, and every batch of rows costs the attacker a
/// fee-paying, network-accepted double-spend. The unconditional-placeholder
/// shape this narrows (every context leaking rows with no collector at
/// all) does not return: block-context rows still collect at the finality
/// boundary, and only the IS-context shared-input residue is permanent.
///
/// Idempotent: a txid this store never recorded is a successful no-op, not an
/// error. A sweep can legitimately name a transaction this wallet dropped, or
/// never derived an address for in the first place. Only the loser-scoped
/// work is skipped in that case — the batch's released outpoints are applied
/// by the caller, outside this function, precisely so a missing row cannot
/// swallow them.
fn apply_sweep(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
    loser_txid: &dashcore::Txid,
    superseded_by: &dashcore::Txid,
    released: &HashSet<dashcore::OutPoint>,
    swept_txids: &HashSet<dashcore::Txid>,
    winner_mined_height: Option<u32>,
) -> Result<(), WalletStorageError> {
    let loser_blob: Option<Vec<u8>> = tx
        .query_row(
            "SELECT record_blob FROM core_transactions WHERE wallet_id = ?1 AND txid = ?2 AND record_blob IS NOT NULL",
            params![wallet_id.as_slice(), AsRef::<[u8]>::as_ref(loser_txid)],
            |row| row.get(0),
        )
        .optional()?;
    // Before the early return, deliberately. `instant_locks_for_non_final_records`
    // is a separate map that merges independently of `records`, so a lock row can
    // outlive its record — a fatal flush that discards a buffered round is the
    // documented way. Nothing ties that table to `core_transactions` (no foreign
    // key, no trigger), so a lock skipped here survives forever, describing a
    // transaction the wallet has removed. The delete is txid-keyed and
    // idempotent, so running it on the missing-record path costs nothing.
    tx.execute(
        "DELETE FROM core_instant_locks WHERE wallet_id = ?1 AND txid = ?2",
        params![wallet_id.as_slice(), AsRef::<[u8]>::as_ref(loser_txid)],
    )?;
    let Some(loser_blob) = loser_blob else {
        // Height-only records carry no input list, but their outputs still belong to the loser.
        tx.execute(
            "DELETE FROM core_transactions WHERE wallet_id = ?1 AND txid = ?2",
            params![wallet_id.as_slice(), AsRef::<[u8]>::as_ref(loser_txid)],
        )?;
        // `encode_outpoint_txid_occupies_bytes_two_to_thirty_three` pins this prefix.
        tx.execute(
            "DELETE FROM core_utxos WHERE wallet_id = ?1 AND substr(outpoint, 2, 32) = ?2",
            params![wallet_id.as_slice(), AsRef::<[u8]>::as_ref(loser_txid)],
        )?;
        return Ok(());
    };
    let loser: TransactionRecord = blob::decode(&loser_blob)?;
    // Fails CLOSED on a key/record disagreement, before anything is deleted
    // or any input is touched. The typed key is what named this row a swept
    // loser — both here and in `surviving_stored_input_claims`, which skips
    // the row on the key alone and so never contributes its blob's claims to
    // the veto set. A row keyed `loser_txid` but holding some other record's
    // blob would therefore have that record's inputs processed as this
    // loser's, with its claimant veto already waived: a release naming a coin
    // the stored record legitimately consumed would mark that coin unspent
    // and delete the only stored evidence of its spender. Same `BlobDecode`
    // verdict as the claim scan's own mismatch check, for the same reason.
    if loser.txid != *loser_txid {
        return Err(WalletStorageError::blob_decode(
            "core_transactions.txid disagrees with the swept record's txid",
        ));
    }

    tx.execute(
        "DELETE FROM core_transactions WHERE wallet_id = ?1 AND txid = ?2",
        params![wallet_id.as_slice(), AsRef::<[u8]>::as_ref(loser_txid)],
    )?;
    let mut delete_output_stmt =
        tx.prepare_cached("DELETE FROM core_utxos WHERE wallet_id = ?1 AND outpoint = ?2")?;
    for vout in 0..loser.transaction.output.len() as u32 {
        let op = blob::encode_outpoint(&dashcore::OutPoint {
            txid: *loser_txid,
            vout,
        })?;
        delete_output_stmt.execute(params![wallet_id.as_slice(), &op[..]])?;
    }

    // Each input is set outright rather than only touched when it changes:
    // whichever way it went, the row must end this round agreeing with the
    // wallet, and a coin the sweep did not free stays out of the unspent
    // query even if nothing had marked it spent yet (upstream sweeps only
    // unconfirmed records, whose spends this schema does not mark).
    // `spent_in_txid` moves with `spent`: a released input clears back to
    // NULL (nobody's claim), a held one is attributed to `superseded_by` so
    // the claim outlives this row's own deletion below.
    // A held, never-materialised claim (`is_sweep_placeholder = 1`) is re-stamped
    // with the NEW winner's mined height when this sweep has one — the
    // claim now belongs to that winner, and its height is what the
    // collector compares against the finality boundary. An IS-locked
    // winner (`?5` NULL) re-points the claim but keeps the existing stamp:
    // the earlier block-context observation stands, exactly as upstream's
    // `observed_spent_outpoints` entry is never retracted by an
    // unconfirmed conflict, and collection at the old height stays sound —
    // the funding output of a spent outpoint is mined at or below the
    // height of ANY block-context spender of it, so the boundary passing
    // that height still proves the funding was delivered or never will be.
    // Materialised rows (placeholder flag clear) keep their NULL stamp — they are
    // outside the collector's reach either way.
    let mut spend_stmt = tx.prepare_cached(
        "UPDATE core_utxos SET spent = ?3, spent_in_txid = ?4, \
            winner_mined_height = CASE \
                WHEN ?3 AND is_sweep_placeholder = 1 THEN COALESCE(?5, winner_mined_height) \
                ELSE winner_mined_height END \
         WHERE wallet_id = ?1 AND outpoint = ?2",
    )?;
    // Only reached for a held input with no existing row — see the doc
    // comment above. `value`/`script` are
    // placeholders; the funding UTXO's own upsert overwrites them (and,
    // thanks to the held-placeholder valve in `execute_upsert_utxo`, does
    // not clear `spent` while doing it). `winner_mined_height` is the
    // winner's own block height when the sweep has one — the row's whole
    // lifetime rule for `collect_finalized_tombstones` — and NULL for an
    // IS-locked, unmined winner, which the collector never touches: the
    // hold then lasts until the funding upsert materialises it, a later
    // block-context sweep stamps it, or a release deletes it.
    let mut tombstone_stmt = tx.prepare_cached(
        "INSERT INTO core_utxos \
            (wallet_id, outpoint, value, script, is_sweep_placeholder, spent, spent_in_txid, \
             winner_mined_height) \
         VALUES (?1, ?2, 0, X'', 1, 1, ?3, ?4)",
    )?;
    for input in &loser.transaction.input {
        let outpoint = input.previous_output;
        // An input funded by a transaction this same changeset also sweeps
        // is a dead parent's output — nobody's coin, not something the
        // winner took: upstream's descendant closure always sweeps parent
        // and child together, and its release computation excludes exactly
        // these outpoints (so `freed` below can never be true for one). The
        // right end state is NO row, deleted here outright rather than
        // assumed away or marked:
        //
        // - Assuming the parent's own pass deleted it fails when the
        //   parent's record was lost (the same record-loss threat the
        //   caller's by-outpoint release pass exists for) — that pass
        //   deletes nothing, and skipping the claim here would leave the
        //   dead output `spent = 0`, a phantom spendable coin `load()`
        //   hands back.
        // - Holding it instead (`spent = 1`, `spent_in_txid = winner`, the
        //   ordinary path below) either survives as a placeholder the
        //   funding upsert's valve then defends — against the chainlocked
        //   reinstatement that is the ONE event that can bring the coin
        //   back, whose re-emitted output must land freshly unspent — or,
        //   for a materialised row, keeps a dead coin on disk until that
        //   reinstatement, with nothing else able to remove it.
        //
        // The delete is idempotent against the parent's own pass in either
        // batch order, and a reinstatement re-creates the real row through
        // the ordinary `utxos_added` upsert with nothing left standing in
        // its way.
        if swept_txids.contains(&outpoint.txid) {
            let key = blob::encode_outpoint(&outpoint)?;
            delete_output_stmt.execute(params![wallet_id.as_slice(), &key[..]])?;
            continue;
        }
        let key = blob::encode_outpoint(&outpoint)?;
        let freed = released.contains(&outpoint);
        let spent_in_txid: Option<&[u8]> = if freed {
            None
        } else {
            Some(AsRef::<[u8]>::as_ref(superseded_by))
        };
        let affected = spend_stmt.execute(params![
            wallet_id.as_slice(),
            &key[..],
            !freed,
            spent_in_txid,
            winner_mined_height.map(i64::from)
        ])?;
        if affected == 0 && !freed {
            // A held input with no row gets a placeholder in EVERY sweep
            // context — `CORE_SWEEP_REMOVAL`'s contract: each non-released
            // input retains a durable spend claim even when its funding
            // TXO has not materialised yet. An IS-locked, unmined winner
            // just leaves the stamp NULL, which the collector never
            // touches — see the doc comment above for what resolves (and
            // what bounds) an unstamped row.
            tombstone_stmt.execute(params![
                wallet_id.as_slice(),
                &key[..],
                AsRef::<[u8]>::as_ref(superseded_by),
                winner_mined_height.map(i64::from)
            ])?;
        }
    }

    Ok(())
}

const UPSERT_UTXO_SQL: &str = "INSERT INTO core_utxos \
        (wallet_id, outpoint, value, script, spent) \
     VALUES (?1, ?2, ?3, ?4, ?5) \
     ON CONFLICT(wallet_id, outpoint) DO UPDATE SET \
        value = excluded.value, \
        script = excluded.script, \
        is_sweep_placeholder = 0, \
        winner_mined_height = NULL, \
        spent = CASE WHEN core_utxos.is_sweep_placeholder = 1 AND core_utxos.spent \
            THEN 1 ELSE excluded.spent END, \
        spent_in_txid = CASE \
            WHEN core_utxos.is_sweep_placeholder = 1 AND core_utxos.spent THEN core_utxos.spent_in_txid \
            WHEN excluded.spent THEN core_utxos.spent_in_txid \
            ELSE NULL END";

/// Upsert one `core_utxos` row; `spent` marks spent-only synthetic rows.
///
/// # Errors
///
/// [`WalletStorageError::EmptyUtxoScript`] when the script is empty. This
/// writes materialized `core_utxos.script` values, so refusing here is what
/// keeps the reader's `Address::from_script` reachable only for scripts
/// that can exist — a stored empty one fails the load of the whole file.
fn execute_upsert_utxo(
    stmt: &mut rusqlite::CachedStatement<'_>,
    wallet_id: &WalletId,
    utxo: &Utxo,
    spent: bool,
) -> Result<(), WalletStorageError> {
    if utxo.txout.script_pubkey.as_bytes().is_empty() {
        return Err(WalletStorageError::EmptyUtxoScript {
            outpoint: utxo.outpoint,
        });
    }
    let op = blob::encode_outpoint(&utxo.outpoint)?;
    stmt.execute(params![
        wallet_id.as_slice(),
        &op[..],
        crate::sqlite::util::safe_cast::u64_to_i64("core_utxos.value", utxo.value())?,
        utxo.txout.script_pubkey.as_bytes(),
        spent,
    ])?;
    Ok(())
}

fn upsert_sync_state(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
    last_processed: Option<u32>,
    synced: Option<u32>,
    chain_lock_bytes: Option<Vec<u8>>,
    chainlock: Option<u32>,
) -> Result<(), WalletStorageError> {
    // Read current row for monotonic-max height merge + to carry forward any
    // existing chain lock when the changeset doesn't include a new one.
    let current_raw: (Option<i64>, Option<i64>, Option<Vec<u8>>) = tx
        .query_row(
            "SELECT last_processed_height, synced_height, last_applied_chain_lock \
             FROM core_sync_state WHERE wallet_id = ?1",
            params![wallet_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .unwrap_or((None, None, None));
    // Monotonic-max semantics for sync watermarks.
    let current = (
        height_column_u32("core_sync_state.last_processed_height", current_raw.0)?,
        height_column_u32("core_sync_state.synced_height", current_raw.1)?,
    );
    let lp = match (current.0, last_processed) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let sy = match (current.1, synced) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    // Chain lock: monotonic-max by height like the sync watermarks above.
    // A new chain lock replaces the stored one only when its height is >=
    // the stored height, so an out-of-order lower-height update can't
    // regress the finalized checkpoint. `None` (no update) keeps existing.
    let cl_final = match (chain_lock_bytes, current_raw.2) {
        (Some(new_bytes), Some(existing_bytes)) => {
            if chain_lock_height(&new_bytes) >= chain_lock_height(&existing_bytes) {
                Some(new_bytes)
            } else {
                Some(existing_bytes)
            }
        }
        (Some(new_bytes), None) => Some(new_bytes),
        (None, existing) => existing,
    };
    let existing_height = read_sync_heights(tx, wallet_id)?.2;
    let cl = existing_height.into_iter().chain(chainlock).max();
    tx.execute(
        "INSERT INTO core_sync_state \
            (wallet_id, last_processed_height, synced_height, last_applied_chain_lock, chainlock_height) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(wallet_id) DO UPDATE SET \
            last_processed_height = excluded.last_processed_height, \
            synced_height = excluded.synced_height, \
            last_applied_chain_lock = excluded.last_applied_chain_lock, \
            chainlock_height = excluded.chainlock_height",
        params![
            wallet_id.as_slice(),
            lp.map(i64::from),
            sy.map(i64::from),
            cl_final,
            cl.map(i64::from),
        ],
    )?;
    Ok(())
}

/// Bulk-reconstruct the keyless [`CoreChangeSet`] projection for one wallet
/// from the `core_*` tables, plus the per-outpoint owning-account side channel.
/// PUBLIC material only; mints no `Wallet`. `network` (from `wallets`) turns a
/// persisted `script` back into an `Address`.
///
/// [`CoreChangeSet::new_utxos`] cannot carry each UTXO's owning account (it is a
/// bare `Vec<Utxo>`), so the returned map surfaces, per unspent outpoint, the
/// funds account that owns it — resolved by matching the UTXO's script against
/// `core_address_pool`. [`apply_persisted_core_state`](crate::sqlite::rehydrate::apply_persisted_core_state)
/// consumes it to route each UTXO to its true account. An outpoint whose script
/// matches no pool row is absent from the map and falls back to the first funds
/// account (the one-way historical-attribution default; re-warms on next sync).
///
/// # Reconstructed (safety-critical-correct)
///
/// - **Unspent UTXOs** (`new_utxos`): every `spent = 0` row — the balance
///   source (no-silent-zero); confirmation height comes from the matching
///   `core_transactions` row. A missing row or height loads as unconfirmed.
/// - **Transaction records**: height-only rows supply UTXO confirmation
///   metadata but are not emitted as records. Blob-bearing rows are decoded
///   and checked against their typed txid and height columns.
/// - **IS-locks** / **sync watermarks**: decoded bit-exact, fail-hard on a
///   corrupt blob.
///
/// # Deferred to the first post-load `sync` (safe re-warm)
///
/// - **`is_coinbase` / `is_instantlocked` / `is_trusted` / `used` flags**: not
///   carried by `core_utxos`; defaulted and refreshed on the next scan.
pub fn load_state(
    conn: &Connection,
    wallet_id: &WalletId,
    network: dashcore::Network,
    ctx: &LoadCtx,
) -> Result<
    (
        CoreChangeSet,
        std::collections::HashMap<dashcore::OutPoint, OwningAccount>,
    ),
    WalletStorageError,
> {
    let mut cs = CoreChangeSet::default();
    let mut utxo_accounts: HashMap<dashcore::OutPoint, OwningAccount> = HashMap::new();

    let mut transaction_heights: HashMap<dashcore::Txid, Option<u32>> = HashMap::new();
    let mut blob_backed_transaction_heights = HashSet::new();
    {
        use dashcore::hashes::Hash;

        // Pre-read length gates keep fixed-width txids and record blobs from
        // being materialized before their stored sizes are validated.
        let mut stmt = conn.prepare(
            "SELECT length(txid), txid, height, length(record_blob), record_blob \
             FROM core_transactions WHERE wallet_id = ?1",
        )?;
        let mut rows = stmt.query(params![wallet_id.as_slice()])?;
        while let Some(row) = rows.next()? {
            blob::check_fixed_width(row.get::<_, i64>(0)?, 32, "core_transactions.txid")?;
            let txid_bytes: Vec<u8> = row.get(1)?;
            let txid = dashcore::Txid::from_slice(&txid_bytes)?;
            let height =
                height_column_u32("core_transactions.height", row.get::<_, Option<i64>>(2)?)?;
            let mut effective_txid = txid;
            let mut effective_height = height;
            if let Some(record_blob_len) = row.get::<_, Option<i64>>(3)? {
                blob::check_size(record_blob_len)?;
                let payload: Vec<u8> = row.get(4)?;
                let record = blob::decode::<TransactionRecord>(&payload)?;
                effective_txid = record.txid;
                effective_height = record.block_info().map(|block_info| block_info.height());
                if let Err(mismatch) =
                    ensure_transaction_record_matches_columns(&txid, height, &record)
                {
                    // The blob is authoritative, so the projection keeps
                    // using it; the typed columns are left exactly as found.
                    ctx.tolerate(LoadSite::CoreTransactionColumnDrift, mismatch)?;
                }
                cs.records.push(record);
                transaction_heights.insert(effective_txid, effective_height);
                blob_backed_transaction_heights.insert(effective_txid);
            } else if !blob_backed_transaction_heights.contains(&effective_txid) {
                transaction_heights
                    .entry(effective_txid)
                    .or_insert(effective_height);
            }
        }
    }

    // Unspent UTXOs → new_utxos (the balance source).
    // Pre-read `length()` gates on `outpoint` and `script` before materializing
    // the Vec so tampered oversize values are caught before heap allocation.
    // Uses `prepare + query + while let` (not `query_map`) so the typed
    // `BlobTooLarge` error can be returned from the loop body directly.
    {
        let mut stmt = conn.prepare(
            "SELECT length(outpoint), outpoint, value, length(script), script \
             FROM core_utxos WHERE wallet_id = ?1 AND spent = 0",
        )?;
        let mut rows = stmt.query(params![wallet_id.as_slice()])?;
        while let Some(row) = rows.next()? {
            // col 0: length(outpoint) — gate before materializing
            blob::check_size(row.get::<_, i64>(0)?)?;
            let op_bytes: Vec<u8> = row.get(1)?;
            let value: i64 = row.get(2)?;
            // col 3: length(script) — gate before materializing
            blob::check_size(row.get::<_, i64>(3)?)?;
            let script_bytes: Vec<u8> = row.get(4)?;
            let outpoint = blob::decode_outpoint(&op_bytes)?;
            let value = crate::sqlite::util::safe_cast::i64_to_u64("core_utxos.value", value)?;
            let height = transaction_heights.get(&outpoint.txid).copied().flatten();
            let script = dashcore::ScriptBuf::from_bytes(script_bytes);
            if let Some(owner) = owning_account_for_script(conn, wallet_id, script.as_bytes())? {
                utxo_accounts.insert(outpoint, owner);
            }
            // TODO(unspent-script-recovery-tolerance): Recovery tolerance
            // for an undecodable unspent script is deliberately deferred.
            // This stays fail-hard because it is the balance source —
            // tolerating a failed decode drops a UTXO and silently
            // under-reports the balance. The cost of deferring is severe
            // and measured: `load()` builds every healthy wallet in the
            // file, then discards all of it when a later wallet hits this
            // line, because the per-wallet loop returns `Ok(state)` only
            // after it completes. Under Recovery — the mode whose purpose
            // is to hand back whatever it can — one bad row still costs
            // the user every wallet in the file.
            let address = dashcore::Address::from_script(&script, network)?;
            let utxo = Utxo {
                outpoint,
                txout: dashcore::TxOut {
                    value,
                    script_pubkey: script,
                },
                address,
                height: height.unwrap_or(0),
                is_coinbase: false,
                is_confirmed: height.is_some(),
                is_instantlocked: false,
                is_locked: false,
                is_trusted: false,
            };
            cs.new_utxos.push(utxo);
        }
    }

    cs.instant_locks_for_non_final_records = verified_instant_locks(conn, wallet_id)?;
    for record in &mut cs.records {
        let verified = cs.instant_locks_for_non_final_records.get(&record.txid);
        record.context = effective_context(&record.context, verified);
    }

    // Sync watermarks + persisted chain lock. Read `length()` first so an
    // oversize chain-lock blob is rejected before the Vec is allocated.
    {
        let mut stmt = conn.prepare(
            "SELECT last_processed_height, synced_height, \
                    length(last_applied_chain_lock), last_applied_chain_lock \
             FROM core_sync_state WHERE wallet_id = ?1",
        )?;
        let mut rows = stmt.query(params![wallet_id.as_slice()])?;
        if let Some(row) = rows.next()? {
            let lp: Option<i64> = row.get(0)?;
            let sy: Option<i64> = row.get(1)?;
            // Gate before materializing: NULL length means no chain lock.
            if let Some(n) = row.get::<_, Option<i64>>(2)? {
                blob::check_size(n)?;
            }
            let cl_bytes: Option<Vec<u8>> = row.get(3)?;
            // Fail-hard on an out-of-range watermark (corruption never skipped).
            cs.last_processed_height =
                height_column_u32("core_sync_state.last_processed_height", lp)?;
            cs.synced_height = height_column_u32("core_sync_state.synced_height", sy)?;
            // Policy decides: strict aborts on a corrupt chain-lock blob,
            // recovery leaves the field None for the next ChainLock event.
            if let Some(bytes) = cl_bytes {
                cs.last_applied_chain_lock = decode_chain_lock(&bytes, ctx)?;
            }
        }
    }

    Ok((cs, utxo_accounts))
}

/// Every address that has ever held a `core_utxos` row for this wallet —
/// spent **and** unspent — deduplicated, each paired with its resolved
/// owning account. The rehydration address-reuse guard: an address whose
/// UTXO was since spent must still be marked used so it's never handed back
/// out as a fresh receive address.
///
/// `core_utxos` carries no unambiguous account attribution, so ownership is
/// resolved per script via [`owning_account_for_script`]; the result is
/// `None` when the script matches no pool row (the caller then routes to the
/// first funds account). `network` turns each persisted `script` back into an
/// [`Address`](dashcore::Address). An invalid script is fatal under Strict;
/// Recovery counts and skips that address while continuing with the rest.
/// This compatibility entry point uses Strict; rehydration calls
/// [`load_used_addresses_with_ctx`] with its policy context.
pub fn load_used_addresses(
    conn: &Connection,
    wallet_id: &WalletId,
    network: dashcore::Network,
) -> Result<Vec<(dashcore::Address, Option<OwningAccount>)>, WalletStorageError> {
    load_used_addresses_with_ctx(conn, wallet_id, network, &LoadCtx::strict())
}

/// [`load_used_addresses`] under an explicit load policy.
pub fn load_used_addresses_with_ctx(
    conn: &Connection,
    wallet_id: &WalletId,
    network: dashcore::Network,
    ctx: &LoadCtx,
) -> Result<Vec<(dashcore::Address, Option<OwningAccount>)>, WalletStorageError> {
    // Gate the largest stored `script` with a cheap aggregate BEFORE the
    // `DISTINCT ... ORDER BY script` read materializes or sorts any blob, so a
    // corrupt/oversize column raises a typed `BlobTooLarge` (the crate's 16 MiB
    // cap) rather than SQLite's own `TooBig` mid-sort, and never OOMs the host.
    // `core_utxos` has no `(wallet_id, script)` index, so the read would sort
    // the blob; the aggregate gate fires first regardless of query plan.
    blob::check_max_column_len(
        conn,
        "SELECT MAX(length(script)) FROM core_utxos WHERE wallet_id = ?1",
        wallet_id,
    )?;
    // Materialize the scripts before resolving ownership: `owning_account_for_script`
    // prepares its own statement on `conn`, so the reader statement must be
    // finished first.
    let scripts: Vec<Vec<u8>> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT script FROM core_utxos WHERE wallet_id = ?1 AND is_sweep_placeholder = 0 ORDER BY script",
        )?;
        let rows = stmt.query_map(params![wallet_id.as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.collect::<Result<_, _>>()?
    };
    let mut out = Vec::with_capacity(scripts.len());
    for raw in scripts {
        let owner = owning_account_for_script(conn, wallet_id, &raw)?;
        let address = match blob::decode_script_to_address(raw, network) {
            Ok(address) => address,
            Err(error) => {
                ctx.tolerate(LoadSite::UndecodableAddressScript, error)?;
                continue;
            }
        };
        out.push((address, owner));
    }
    Ok(out)
}

/// The wallet's `(last_processed_height, synced_height, chainlock_height)`
/// watermark triple as read back from `core_sync_state`.
type SyncHeights = (Option<u32>, Option<u32>, Option<u32>);

/// Read the wallet's [`SyncHeights`] watermarks. All-`None` when the row
/// is absent.
fn read_sync_heights(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
) -> Result<SyncHeights, WalletStorageError> {
    let raw: (Option<i64>, Option<i64>, Option<i64>) = tx
        .query_row(
            "SELECT last_processed_height, synced_height, chainlock_height \
             FROM core_sync_state WHERE wallet_id = ?1",
            params![wallet_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .unwrap_or((None, None, None));
    Ok((
        height_column_u32("core_sync_state.last_processed_height", raw.0)?,
        height_column_u32("core_sync_state.synced_height", raw.1)?,
        height_column_u32("core_sync_state.chainlock_height", raw.2)?,
    ))
}

/// Evict never-materialised sweep tombstones once the chainlock finality
/// boundary reaches their winner's mined height — the storage-side mirror
/// of key-wallet's `prune_finalized_observed_spends`, same condition
/// verbatim: an entry whose spend height is at or below
/// `min(chainlock_height, synced_height)` is safe to forget, because the
/// spend at that height is chain-locked and every BIP158 filter below the
/// boundary has been matched with no false negatives, so the funding
/// transaction of the outpoint it guards — necessarily mined at or below
/// the spend's own height — has either been delivered (materialising the
/// row) or provably never will be. No observation-age margin: the stamp IS
/// the winner's height, carried on the sweep event itself, so nothing here
/// guesses when the winner mined. Rows with no stamp are never collected:
/// a mempool-context sweep (IS-locked winner, unmined) deliberately
/// writes its placeholder unstamped, because such a winner has no mining
/// deadline and no watermark can prove its inputs' funding "delivered or
/// never will be" — an unstamped row is a live hold, resolved only by the
/// funding upsert materialising it, a later block-context sweep stamping
/// it, or a release deleting it (see `apply_sweep`).
///
/// One pass, narrowed to `is_sweep_placeholder = 1` (only the tombstone insert
/// sets the placeholder flag, so the set is exactly the never-materialised
/// rows, served by the partial index): held rows whose winner height is
/// at or below the boundary are collected. There is no released-leftover
/// shape to sweep up — a release deletes a never-materialised row in-line
/// (see the release pass in [`apply`]), and the loser loop's transient
/// `spent = 0` on a placeholder is always followed by that pass in the
/// same transaction.
///
/// Like upstream, a no-op until a chainlock height has been persisted —
/// without a finality boundary nothing can be proven final.
fn collect_finalized_tombstones(
    tx: &Transaction<'_>,
    wallet_id: &WalletId,
) -> Result<(), WalletStorageError> {
    let (_, sy, cl) = read_sync_heights(tx, wallet_id)?;
    let (Some(sy), Some(cl)) = (sy, cl) else {
        return Ok(());
    };
    let boundary = cl.min(sy);
    let mut stmt = tx.prepare_cached(
        "DELETE FROM core_utxos \
         WHERE wallet_id = ?1 AND is_sweep_placeholder = 1 AND spent = 1 \
           AND winner_mined_height <= ?2",
    )?;
    stmt.execute(params![wallet_id.as_slice(), i64::from(boundary)])?;
    Ok(())
}

/// Convert a stored sync-height column to `u32`, erroring on overflow
/// rather than silently truncating a corrupt/out-of-range value.
fn height_column_u32(
    field: &'static str,
    value: Option<i64>,
) -> Result<Option<u32>, WalletStorageError> {
    value
        .map(|v| crate::sqlite::util::safe_cast::i64_to_u32(field, v))
        .transpose()
}

/// Fetch a single transaction record by txid.
///
/// Returns `Ok(None)` when the row is absent or carries only confirmation
/// height metadata.
/// A height-only row is not synthesized because UTXO height is not attested
/// block context and must not masquerade as a `BlockInfo`.
pub fn get_tx_record(
    conn: &Connection,
    wallet_id: &WalletId,
    txid: &dashcore::Txid,
    ctx: &LoadCtx,
) -> Result<Option<TransactionRecord>, WalletStorageError> {
    // Pre-read `length()` gate before materializing, consistent with the
    // bulk load_state path above.
    let mut stmt = conn.prepare_cached(
        "SELECT height, length(record_blob), record_blob FROM core_transactions \
         WHERE wallet_id = ?1 AND txid = ?2",
    )?;
    let mut rows = stmt.query(params![wallet_id.as_slice(), AsRef::<[u8]>::as_ref(txid)])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let height = height_column_u32("core_transactions.height", row.get::<_, Option<i64>>(0)?)?;
    let Some(record_blob_len) = row.get::<_, Option<i64>>(1)? else {
        return Ok(None);
    };
    blob::check_size(record_blob_len)?;
    let payload: Vec<u8> = row.get(2)?;
    let mut record: TransactionRecord = blob::decode(&payload)?;
    drop(rows);
    drop(stmt);
    if record.block_info().is_none() {
        let verified = verified_instant_lock(conn, wallet_id, txid)?;
        record.context = effective_context(&record.context, verified.as_ref());
    }
    if let Err(mismatch) = ensure_transaction_record_matches_columns(txid, height, &record) {
        // Captured before `mismatch` moves: only a txid disagreement means
        // the row is a different transaction from the one asked for.
        let names_another_transaction = record.txid != *txid;
        ctx.tolerate(LoadSite::CoreTransactionColumnDrift, mismatch)?;
        // Recovery tolerated the drift, which licenses continuing the load —
        // not answering a point read with someone else's transaction. Height
        // drift keeps the blob authoritative and still serves the record.
        if names_another_transaction {
            return Ok(None);
        }
    }
    Ok(Some(record))
}

/// How final a stored transaction is, the one rule history, coin
/// restoration and the sweep share: a mined record stands on its block; any
/// other is InstantSend-locked on `verified`, its lock row stored as verified,
/// and otherwise in the mempool, whatever context its blob was written with.
fn effective_context(
    context: &TransactionContext,
    verified: Option<&InstantLock>,
) -> TransactionContext {
    if context.block_info().is_some() {
        return context.clone();
    }
    verified.map_or(TransactionContext::Mempool, |lock| {
        TransactionContext::InstantSend(lock.clone())
    })
}

/// A lock row stored as verified, decoded; `None` when its lock is for
/// another transaction than the row's key.
fn verified_lock_of_row(
    txid: &dashcore::Txid,
    blob_bytes: &[u8],
) -> Result<Option<InstantLock>, WalletStorageError> {
    let lock: InstantLock = blob::decode(blob_bytes)?;
    if lock.txid != *txid {
        tracing::warn!(%txid, lock_txid = %lock.txid, "a stored lock names another transaction; ignored");
        return Ok(None);
    }
    Ok(Some(lock))
}

/// Every lock row of the wallet stored as verified, by transaction.
fn verified_instant_locks(
    conn: &Connection,
    wallet_id: &WalletId,
) -> Result<BTreeMap<dashcore::Txid, InstantLock>, WalletStorageError> {
    // Same pre-read length gate as `record_blob`. `txid` is a raw 32-byte
    // hash, so its width is gated fixed before materializing.
    let mut stmt = conn.prepare_cached(
        "SELECT length(txid), txid, length(islock_blob), islock_blob \
         FROM core_instant_locks WHERE wallet_id = ?1 AND verified = 1",
    )?;
    let mut rows = stmt.query(params![wallet_id.as_slice()])?;
    let mut locks = BTreeMap::new();
    while let Some(row) = rows.next()? {
        use dashcore::hashes::Hash;
        blob::check_fixed_width(row.get::<_, i64>(0)?, 32, "core_instant_locks.txid")?;
        let txid_bytes: Vec<u8> = row.get(1)?;
        blob::check_size(row.get::<_, i64>(2)?)?;
        let blob_bytes: Vec<u8> = row.get(3)?;
        let txid = dashcore::Txid::from_slice(&txid_bytes)?;
        if let Some(lock) = verified_lock_of_row(&txid, &blob_bytes)? {
            locks.insert(txid, lock);
        }
    }
    Ok(locks)
}

/// The lock row stored as verified for `txid`, if any.
fn verified_instant_lock(
    conn: &Connection,
    wallet_id: &WalletId,
    txid: &dashcore::Txid,
) -> Result<Option<InstantLock>, WalletStorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT length(islock_blob), islock_blob FROM core_instant_locks \
         WHERE wallet_id = ?1 AND txid = ?2 AND verified = 1",
    )?;
    let mut rows = stmt.query(params![wallet_id.as_slice(), AsRef::<[u8]>::as_ref(txid)])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    blob::check_size(row.get::<_, i64>(0)?)?;
    let blob_bytes: Vec<u8> = row.get(1)?;
    verified_lock_of_row(txid, &blob_bytes)
}

/// Diagnose typed txid/height columns that disagree with the authoritative blob.
fn ensure_transaction_record_matches_columns(
    typed_txid: &dashcore::Txid,
    typed_height: Option<u32>,
    record: &TransactionRecord,
) -> Result<(), WalletStorageError> {
    let blob_height = record.block_info().map(|block_info| block_info.height());
    if record.txid != *typed_txid || blob_height != typed_height {
        return Err(WalletStorageError::CoreTransactionEntryMismatch {
            typed_txid: typed_txid.to_string(),
            blob_txid: record.txid.to_string(),
            typed_height,
            blob_height,
        });
    }
    Ok(())
}

/// Row representing one unspent UTXO. Used by tests that probe the
/// `core_utxos` table without going through full `Wallet` reconstruction.
#[cfg(any(test, feature = "__test-helpers"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnspentRow {
    pub outpoint: dashcore::OutPoint,
    pub value: u64,
    pub script: Vec<u8>,
    pub account_index: u32,
}

/// All UTXOs for a wallet that have not been spent yet, bucketed by the
/// account index resolved from `core_address_pool` during the read.
#[cfg(any(test, feature = "__test-helpers"))]
pub fn list_unspent_utxos(
    conn: &Connection,
    wallet_id: &WalletId,
) -> Result<BTreeMap<u32, Vec<UnspentRow>>, WalletStorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT outpoint, value, script \
         FROM core_utxos WHERE wallet_id = ?1 AND spent = 0",
    )?;
    let rows = stmt.query_map(params![wallet_id.as_slice()], |row| {
        let op_bytes: Vec<u8> = row.get(0)?;
        let value: i64 = row.get(1)?;
        let script: Vec<u8> = row.get(2)?;
        Ok((op_bytes, value, script))
    })?;
    let mut by_account: BTreeMap<u32, Vec<UnspentRow>> = BTreeMap::new();
    for r in rows {
        let (op_bytes, value, script_bytes) = r?;
        let outpoint = blob::decode_outpoint(&op_bytes)?;
        let value = crate::sqlite::util::safe_cast::i64_to_u64("core_utxos.value", value)?;
        let account_index = owning_account_for_script(conn, wallet_id, &script_bytes)?
            .map(|owner| owner.account_index)
            .unwrap_or(0);
        let row = UnspentRow {
            outpoint,
            value,
            script: script_bytes,
            account_index,
        };
        by_account.entry(account_index).or_default().push(row);
    }
    Ok(by_account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::address::Payload;
    use dashcore::hashes::Hash;
    use dashcore::{BlockHash, OutPoint, PubkeyHash, Transaction, TxOut, Txid};
    use key_wallet::account::{AccountType, StandardAccountType};
    use key_wallet::managed_account::transaction_record::{
        TransactionDirection, TransactionRecord,
    };
    use key_wallet::transaction_checking::{BlockInfo, TransactionContext, TransactionType};

    fn transaction_record(txid: Txid, context: TransactionContext) -> TransactionRecord {
        let mut record = TransactionRecord::new(
            Transaction {
                version: 3,
                lock_time: 0,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            context,
            TransactionType::Standard,
            TransactionDirection::Incoming,
            Vec::new(),
            Vec::new(),
            100,
        );
        record.txid = txid;
        record
    }

    fn sample_utxo(txid: Txid, height: u32, is_confirmed: bool) -> Utxo {
        let address = dashcore::Address::new(
            dashcore::Network::Testnet,
            Payload::PubkeyHash(PubkeyHash::from_byte_array([0x23u8; 20])),
        );
        Utxo {
            outpoint: OutPoint { txid, vout: 0 },
            txout: TxOut {
                value: 150_000,
                script_pubkey: address.script_pubkey(),
            },
            address,
            height,
            is_coinbase: false,
            is_confirmed,
            is_instantlocked: false,
            is_locked: false,
            is_trusted: false,
        }
    }

    fn sample_chain_lock(height: u32) -> ChainLock {
        ChainLock {
            block_height: height,
            block_hash: BlockHash::from_byte_array([0x11u8; 32]),
            signature: [0x22u8; 96].into(),
        }
    }

    /// A tampered `core_instant_locks.txid` that overflows the blob cap must
    /// raise `BlobTooLarge` from the fixed-width gate BEFORE the oversize `Vec`
    /// is materialized — not `BlobDecode` after `Txid::from_slice` on a
    /// multi-megabyte allocation.
    #[test]
    fn load_state_rejects_oversize_instant_lock_txid() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let w = [0xABu8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&w[..]],
        )
        .unwrap();

        // Plant a txid one byte past the 16 MiB cap; islock_blob content is
        // irrelevant — the txid gate fires before it is read.
        let oversize_txid = vec![0u8; crate::SIZE_LIMIT_BYTES + 1];
        conn.execute(
            "INSERT INTO core_instant_locks (wallet_id, txid, islock_blob, verified) \
             VALUES (?1, ?2, ?3, 1)",
            params![&w[..], oversize_txid.as_slice(), &[0u8; 4][..]],
        )
        .unwrap();

        let err = load_state(&conn, &w, dashcore::Network::Testnet, &LoadCtx::strict())
            .expect_err("load_state must reject an oversize instant-lock txid");
        assert!(
            matches!(err, WalletStorageError::BlobTooLarge { .. }),
            "expected BlobTooLarge from the pre-materialization gate, got {err:?}"
        );
    }

    /// A lock row of unknown provenance, as a build before the verified-lock
    /// rule wrote it, is not restored and does not make its coins final; a
    /// lock stored through `apply`, which only verified locks reach, is.
    #[test]
    fn load_state_trusts_only_locks_stored_as_verified() {
        use dashcore::ephemerealdata::instant_lock::InstantLock;

        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let w = [0xACu8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&w[..]],
        )
        .unwrap();
        let lock = |byte: u8| InstantLock {
            txid: Txid::from_byte_array([byte; 32]),
            ..InstantLock::default()
        };
        let legacy = lock(0x11);
        conn.execute(
            "INSERT INTO core_instant_locks (wallet_id, txid, islock_blob) VALUES (?1, ?2, ?3)",
            params![
                &w[..],
                AsRef::<[u8]>::as_ref(&legacy.txid),
                blob::encode(&legacy).unwrap()
            ],
        )
        .unwrap();
        let stored = lock(0x22);
        let mut cs = CoreChangeSet::default();
        cs.instant_locks_for_non_final_records
            .insert(stored.txid, stored.clone());
        let unbacked = lock(0x33);
        cs.records = [&legacy, &stored, &unbacked]
            .map(|l| transaction_record(l.txid, TransactionContext::InstantSend(l.clone())))
            .to_vec();
        let tx = conn.transaction().unwrap();
        apply(&tx, &w, &cs).unwrap();
        tx.commit().unwrap();

        let (loaded, _) =
            load_state(&conn, &w, dashcore::Network::Testnet, &LoadCtx::strict()).unwrap();
        assert_eq!(
            loaded.instant_locks_for_non_final_records,
            BTreeMap::from([(stored.txid, stored.clone())])
        );
        let expected = BTreeMap::from([
            (legacy.txid, TransactionContext::Mempool),
            (stored.txid, TransactionContext::InstantSend(stored)),
            (unbacked.txid, TransactionContext::Mempool),
        ]);
        let contexts: BTreeMap<Txid, TransactionContext> = (loaded.records.iter())
            .map(|r| (r.txid, r.context.clone()))
            .collect();
        assert_eq!(contexts, expected);
        for (txid, context) in &expected {
            let read = get_tx_record(&conn, &w, txid, &LoadCtx::strict())
                .unwrap()
                .expect("stored record");
            assert_eq!(&read.context, context, "a point read of {txid}");
        }
    }

    mod unauthorized_pending_spends {
        use super::*;
        use dashcore::secp256k1::Message;
        use dashcore::sighash::SighashCache;
        use dashcore::TxIn;

        struct Owner {
            key: dashcore::secp256k1::Keypair,
            public: dashcore::PublicKey,
            address: dashcore::Address,
        }

        fn owner(byte: u8) -> Owner {
            let key = format!("{byte:02x}")
                .repeat(32)
                .parse::<dashcore::secp256k1::Keypair>()
                .unwrap();
            let public = dashcore::PublicKey::new(key.public_key());
            let address = dashcore::Address::p2pkh(&public, dashcore::Network::Testnet);
            Owner {
                key,
                public,
                address,
            }
        }

        fn coin(owner: &Owner, outpoint: OutPoint, value: u64) -> Utxo {
            Utxo {
                outpoint,
                txout: TxOut {
                    value,
                    script_pubkey: owner.address.script_pubkey(),
                },
                address: owner.address.clone(),
                height: 50,
                is_coinbase: false,
                is_confirmed: true,
                is_instantlocked: false,
                is_locked: false,
                is_trusted: false,
            }
        }

        /// A spend of `coin` to `outputs`, signed by `signer` with the coin
        /// owner's public key in the input script.
        fn spend(coin: &Utxo, owner: &Owner, signer: &Owner, outputs: Vec<TxOut>) -> Transaction {
            let mut tx = Transaction {
                version: 3,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: coin.outpoint,
                    ..TxIn::default()
                }],
                output: outputs,
                special_transaction_payload: None,
            };
            tx.input[0].script_sig = script_sig(&tx, 0, coin, signer, &owner.public);
            tx
        }

        /// An input script for input `index` of `tx`, spending `coin`: a
        /// `SIGHASH_ALL` signature by `signer`, then `key`.
        fn script_sig(
            tx: &Transaction,
            index: usize,
            coin: &Utxo,
            signer: &Owner,
            key: &dashcore::PublicKey,
        ) -> dashcore::ScriptBuf {
            let digest = SighashCache::new(tx)
                .legacy_signature_hash(index, &coin.txout.script_pubkey, 1)
                .unwrap();
            let signature = dashcore::secp256k1::ecdsa::sign(
                Message::from_digest(digest.to_byte_array()),
                &(&signer.key).into(),
            );
            let mut signature = signature.serialize_der().to_vec();
            signature.push(1);
            dashcore::blockdata::script::Builder::new()
                .push_slice(<&dashcore::script::PushBytes>::try_from(signature.as_slice()).unwrap())
                .push_key(key)
                .into_script()
        }

        fn spend_record(tx: Transaction, context: TransactionContext) -> TransactionRecord {
            let txid = tx.txid();
            let mut record = transaction_record(txid, context);
            record.transaction = tx;
            record
        }

        fn unspent(conn: &rusqlite::Connection, w: &[u8; 32]) -> Vec<OutPoint> {
            let (loaded, _) =
                load_state(conn, w, dashcore::Network::Testnet, &LoadCtx::strict()).unwrap();
            let mut outpoints: Vec<_> = loaded.new_utxos.iter().map(|u| u.outpoint).collect();
            outpoints.sort();
            outpoints
        }

        fn repair(conn: &mut rusqlite::Connection) -> usize {
            let tx = conn.transaction().unwrap();
            let dropped = drop_unauthorized_pending_spends(&tx).unwrap();
            tx.commit().unwrap();
            dropped
        }

        /// What a build without the pending-spend check stored: the wallet's
        /// coin, then a peer's unconfirmed spend of it, in `context`, with
        /// change to the wallet, and the coin marked spent.
        fn old_build_store(
            w: &[u8; 32],
            signer: u8,
            context: impl Fn(&Transaction) -> TransactionContext,
        ) -> (rusqlite::Connection, Utxo, Utxo, Transaction) {
            old_build_store_in(wallet_db(w), w, signer, context)
        }

        fn old_build_store_in(
            mut conn: rusqlite::Connection,
            w: &[u8; 32],
            signer: u8,
            context: impl Fn(&Transaction) -> TransactionContext,
        ) -> (rusqlite::Connection, Utxo, Utxo, Transaction) {
            let (held, change, claim) = claim_in_store(&mut conn, w, 0x61, signer, context);
            (conn, held, change, claim)
        }

        /// A coin of the wallet's from funding transaction `funding`, then a
        /// spend of it signed by `signer` in `context`, with change to the
        /// wallet, stored the way a build without the pending-spend check
        /// stored it: the coin marked spent.
        fn claim_in_store(
            conn: &mut rusqlite::Connection,
            w: &[u8; 32],
            funding: u8,
            signer: u8,
            context: impl Fn(&Transaction) -> TransactionContext,
        ) -> (Utxo, Utxo, Transaction) {
            let me = owner(0x31);
            let held = coin(
                &me,
                OutPoint {
                    txid: Txid::from_byte_array([funding; 32]),
                    vout: 0,
                },
                500_000,
            );
            store(
                conn,
                w,
                &CoreChangeSet {
                    new_utxos: vec![held.clone()],
                    ..Default::default()
                },
            );
            own_pool_row(conn, w, &held);
            let (change, claim) = claim_with_change(&held, signer);
            let mut cs = CoreChangeSet {
                records: vec![spend_record(claim.clone(), context(&claim))],
                new_utxos: vec![change.clone()],
                spent_utxos: vec![held.clone()],
                ..Default::default()
            };
            if let TransactionContext::InstantSend(lock) = context(&claim) {
                cs.instant_locks_for_non_final_records
                    .insert(claim.txid(), lock);
            }
            store(conn, w, &cs);
            (held, change, claim)
        }

        /// A spend of `held` signed by `signer`, paying 300,000 away and
        /// 190,000 back to the wallet, and the wallet's coin of that change.
        fn claim_with_change(held: &Utxo, signer: u8) -> (Utxo, Transaction) {
            let me = owner(0x31);
            let claim = spend(
                held,
                &me,
                &owner(signer),
                vec![
                    TxOut {
                        value: 300_000,
                        script_pubkey: owner(0x77).address.script_pubkey(),
                    },
                    TxOut {
                        value: 190_000,
                        script_pubkey: me.address.script_pubkey(),
                    },
                ],
            );
            let change = coin(
                &me,
                OutPoint {
                    txid: claim.txid(),
                    vout: 1,
                },
                190_000,
            );
            (change, claim)
        }

        /// The wallet's own BIP44 pool row for `coin`'s script.
        fn own_pool_row(conn: &rusqlite::Connection, w: &[u8; 32], coin: &Utxo) {
            conn.execute(
                "INSERT OR IGNORE INTO core_address_pool \
                    (wallet_id, account_type, account_index, pool_type, address_index, script) \
                 VALUES (?1, 'standard_bip44', 0, 0, 0, ?2)",
                params![&w[..], coin.txout.script_pubkey.as_bytes()],
            )
            .unwrap();
        }

        fn mined(_: &Transaction) -> TransactionContext {
            TransactionContext::InBlock(BlockInfo::new(
                90,
                BlockHash::from_byte_array([0x09; 32]),
                1_700_000_000,
            ))
        }

        fn locked(tx: &Transaction) -> TransactionContext {
            TransactionContext::InstantSend(InstantLock {
                txid: tx.txid(),
                ..InstantLock::default()
            })
        }

        fn pending(_: &Transaction) -> TransactionContext {
            TransactionContext::Mempool
        }

        fn open_store(path: &std::path::Path) {
            drop(
                crate::sqlite::persister::SqlitePersister::open(
                    crate::sqlite::config::SqlitePersisterConfig::new(path),
                )
                .unwrap(),
            );
        }

        fn kept(conn: &rusqlite::Connection, w: &[u8; 32]) -> Vec<(Txid, String, String)> {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT txid, deleted_outputs, released_coins \
                     FROM core_dropped_unsigned_spends WHERE wallet_id = ?1 ORDER BY id",
                )
                .unwrap();
            stmt.query_map(params![&w[..]], |row| {
                let txid: Vec<u8> = row.get(0)?;
                Ok((
                    Txid::from_byte_array(txid.try_into().unwrap()),
                    row.get(1)?,
                    row.get(2)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
        }

        fn backups(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            match std::fs::read_dir(dir.join("backups").join("auto")) {
                Ok(entries) => entries.map(|e| e.unwrap().path()).collect(),
                Err(_) => Vec::new(),
            }
        }

        fn outpoint_hex(outpoint: &OutPoint) -> String {
            blob::encode_outpoint(outpoint)
                .unwrap()
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect()
        }

        fn has_record(conn: &rusqlite::Connection, w: &[u8; 32], txid: Txid) -> bool {
            get_tx_record(conn, w, &txid, &LoadCtx::strict())
                .unwrap()
                .is_some()
        }

        /// Takes a store back to how a fork V1 build left it.
        fn as_fork_v1_left_it(conn: &rusqlite::Connection) {
            conn.execute_batch(&format!(
                "DELETE FROM {} WHERE version >= 2;
                 DROP TABLE core_dropped_unsigned_spends;
                 ALTER TABLE core_instant_locks DROP COLUMN verified;",
                crate::sqlite::migrations::FORK_HISTORY_TABLE
            ))
            .unwrap();
        }

        /// A data root written by a fork V1 build: the first open copies it
        /// before migrating, gives back the coin an unsigned claim took,
        /// keeps the claim in the recovery record, and leaves a mined spend
        /// and an owner-signed one alone.
        #[test]
        fn a_v1_root_is_copied_then_repaired_on_its_first_open() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wallet.db");
            let w = [0xC1u8; 32];
            let mut conn = wallet_db_in(rusqlite::Connection::open(&path).unwrap(), &w);
            let (unsigned_coin, unsigned_change, unsigned) =
                claim_in_store(&mut conn, &w, 0x61, 0x99, pending);
            let (_, mined_change, mined_claim) = claim_in_store(&mut conn, &w, 0x62, 0x99, mined);
            let (_, signed_change, signed) = claim_in_store(&mut conn, &w, 0x63, 0x31, pending);
            as_fork_v1_left_it(&conn);
            let mut before = [
                unsigned_change.outpoint,
                mined_change.outpoint,
                signed_change.outpoint,
            ];
            before.sort();
            drop(conn);

            open_store(&path);

            let conn = rusqlite::Connection::open(&path).unwrap();
            let mut after = vec![
                unsigned_coin.outpoint,
                mined_change.outpoint,
                signed_change.outpoint,
            ];
            after.sort();
            assert_eq!(unspent(&conn, &w), after);
            assert!(!has_record(&conn, &w, unsigned.txid()));
            assert!(has_record(&conn, &w, mined_claim.txid()));
            assert!(has_record(&conn, &w, signed.txid()));
            let kept = kept(&conn, &w);
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].0, unsigned.txid());
            assert!(kept[0].1.contains(&outpoint_hex(&unsigned_change.outpoint)));
            assert!(kept[0].2.contains(&outpoint_hex(&unsigned_coin.outpoint)));

            let copies = backups(dir.path());
            assert_eq!(copies.len(), 1, "{copies:?}");
            let copy = rusqlite::Connection::open_with_flags(
                &copies[0],
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let check: String = copy
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .unwrap();
            assert_eq!(check, "ok");
            let held_claim: i64 = copy
                .query_row(
                    "SELECT COUNT(*) FROM core_transactions WHERE wallet_id = ?1 AND txid = ?2",
                    params![&w[..], AsRef::<[u8]>::as_ref(&unsigned.txid())],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(held_claim, 1, "the copy still holds the dropped claim");
            drop(copy);

            let elsewhere = tempfile::tempdir().unwrap();
            let reopened = elsewhere.path().join("wallet.db");
            std::fs::copy(&copies[0], &reopened).unwrap();
            open_store(&reopened);
        }

        /// A store already at the current schema: an open that finds an
        /// unsigned claim keeps it without needing a copy, leaves a
        /// verified-locked unsigned spend alone, and the next open finds
        /// nothing more.
        #[test]
        fn a_later_open_keeps_what_it_drops_and_a_second_finds_nothing() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wallet.db");
            let w = [0xC2u8; 32];
            let mut conn = wallet_db_in(rusqlite::Connection::open(&path).unwrap(), &w);
            let (unsigned_coin, _, unsigned) = claim_in_store(&mut conn, &w, 0x64, 0x99, pending);
            let (_, locked_change, locked_claim) =
                claim_in_store(&mut conn, &w, 0x65, 0x99, locked);
            drop(conn);

            open_store(&path);
            let conn = rusqlite::Connection::open(&path).unwrap();
            let mut expected = vec![unsigned_coin.outpoint, locked_change.outpoint];
            expected.sort();
            assert_eq!(unspent(&conn, &w), expected);
            assert!(has_record(&conn, &w, locked_claim.txid()));
            let first = kept(&conn, &w);
            assert_eq!(
                first.iter().map(|k| k.0).collect::<Vec<_>>(),
                vec![unsigned.txid()]
            );
            assert!(backups(dir.path()).is_empty(), "no migration, no copy");
            drop(conn);

            open_store(&path);
            let conn = rusqlite::Connection::open(&path).unwrap();
            assert_eq!(kept(&conn, &w), first);
            assert_eq!(unspent(&conn, &w), expected);
        }

        /// A spend recorded before the wallet knew the coin it spends, because
        /// it also paid the wallet, is proven unsigned on the open after the
        /// coin's funding arrives: the coin comes back and the change it paid
        /// the wallet goes, since that transaction can never confirm.
        #[test]
        fn a_claim_proven_unsigned_once_its_coin_arrives_is_dropped_on_the_next_open() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("wallet.db");
            let w = [0xC3u8; 32];
            let me = owner(0x31);
            let held = coin(
                &me,
                OutPoint {
                    txid: Txid::from_byte_array([0x66; 32]),
                    vout: 0,
                },
                500_000,
            );
            let (change, claim) = claim_with_change(&held, 0x99);
            let mut conn = wallet_db_in(rusqlite::Connection::open(&path).unwrap(), &w);
            store(
                &mut conn,
                &w,
                &CoreChangeSet {
                    records: vec![spend_record(claim.clone(), TransactionContext::Mempool)],
                    new_utxos: vec![change.clone()],
                    ..Default::default()
                },
            );
            drop(conn);

            open_store(&path);
            let mut conn = rusqlite::Connection::open(&path).unwrap();
            assert_eq!(
                unspent(&conn, &w),
                vec![change.outpoint],
                "nothing to judge yet"
            );
            assert!(kept(&conn, &w).is_empty());
            store(
                &mut conn,
                &w,
                &CoreChangeSet {
                    spent_utxos: vec![held.clone()],
                    ..Default::default()
                },
            );
            own_pool_row(&conn, &w, &held);
            assert_eq!(unspent(&conn, &w), vec![change.outpoint]);
            drop(conn);

            open_store(&path);
            let conn = rusqlite::Connection::open(&path).unwrap();
            assert_eq!(unspent(&conn, &w), vec![held.outpoint]);
            assert!(!has_record(&conn, &w, claim.txid()));
            assert_eq!(kept(&conn, &w).len(), 1);
        }

        #[test]
        fn a_coin_an_older_build_let_an_unsigned_claim_spend_is_back_after_the_repair() {
            let w = [0xB1u8; 32];
            let (mut conn, held, change, claim) =
                old_build_store(&w, 0x99, |_| TransactionContext::Mempool);
            assert_eq!(
                unspent(&conn, &w),
                vec![change.outpoint],
                "before the repair the coin is missing and the claim's change is counted"
            );

            assert_eq!(repair(&mut conn), 1);
            assert_eq!(unspent(&conn, &w), vec![held.outpoint]);
            assert!(get_tx_record(&conn, &w, &claim.txid(), &LoadCtx::strict())
                .unwrap()
                .is_none());

            assert_eq!(repair(&mut conn), 0, "a second run finds nothing");
            assert_eq!(unspent(&conn, &w), vec![held.outpoint]);
        }

        /// A pending transaction that spends two of the wallet's coins, one
        /// signed by the wallet and one whose input script is not the
        /// owner's signature, is dropped whole, and both coins are free.
        #[test]
        fn a_spend_with_one_garbage_input_script_is_dropped_whole() {
            let me = owner(0x31);
            let other = owner(0x99);
            let unparseable = dashcore::ScriptBuf::from_bytes(vec![0x4c, 0xff, 0x01]);
            type InputScript<'a> = &'a dyn Fn(&Transaction, &Utxo) -> dashcore::ScriptBuf;
            let forms: [(u8, InputScript<'_>); 3] = [
                (0xC1, &|_, _| unparseable.clone()),
                (0xC2, &|tx, coin| {
                    script_sig(tx, 1, coin, &other, &other.public)
                }),
                (0xC3, &|tx, coin| {
                    script_sig(tx, 1, coin, &other, &me.public)
                }),
            ];
            for (byte, garbage) in forms {
                let w = [byte; 32];
                let mut conn = wallet_db(&w);
                let signed = coin(
                    &me,
                    OutPoint::new(Txid::from_byte_array([0x62; 32]), 0),
                    400_000,
                );
                let listed = coin(
                    &me,
                    OutPoint::new(Txid::from_byte_array([0x63; 32]), 0),
                    300_000,
                );
                store(
                    &mut conn,
                    &w,
                    &CoreChangeSet {
                        new_utxos: vec![signed.clone(), listed.clone()],
                        ..Default::default()
                    },
                );
                own_pool_row(&conn, &w, &signed);
                let mut claim = Transaction {
                    version: 3,
                    lock_time: 0,
                    input: [&signed, &listed]
                        .map(|coin| TxIn {
                            previous_output: coin.outpoint,
                            ..TxIn::default()
                        })
                        .to_vec(),
                    output: vec![TxOut {
                        value: 690_000,
                        script_pubkey: owner(0x77).address.script_pubkey(),
                    }],
                    special_transaction_payload: None,
                };
                claim.input[0].script_sig = script_sig(&claim, 0, &signed, &me, &me.public);
                claim.input[1].script_sig = garbage(&claim, &listed);
                store(
                    &mut conn,
                    &w,
                    &CoreChangeSet {
                        records: vec![spend_record(claim.clone(), TransactionContext::Mempool)],
                        spent_utxos: vec![signed.clone(), listed.clone()],
                        ..Default::default()
                    },
                );
                assert_eq!(unspent(&conn, &w), Vec::<OutPoint>::new(), "form {byte:#x}");

                assert_eq!(repair(&mut conn), 1, "form {byte:#x}");
                assert_eq!(unspent(&conn, &w), vec![signed.outpoint, listed.outpoint]);
                assert!(!has_record(&conn, &w, claim.txid()));
            }
        }

        /// A coin a sweep holds spent for a final winner the store has no
        /// record of stays spent when an unsigned claim on it is dropped.
        #[test]
        fn a_coin_a_sweep_holds_for_a_winner_stays_spent() {
            let w = [0xB7u8; 32];
            let (mut conn, held, _, _) = old_build_store(&w, 0x99, pending);
            conn.execute(
                "UPDATE core_utxos SET spent_in_txid = ?2 WHERE wallet_id = ?1 AND outpoint = ?3",
                params![
                    &w[..],
                    &[0x5Au8; 32][..],
                    blob::encode_outpoint(&held.outpoint).unwrap()
                ],
            )
            .unwrap();
            assert_eq!(repair(&mut conn), 1);
            assert_eq!(unspent(&conn, &w), Vec::<OutPoint>::new());
            assert_eq!(kept(&conn, &w)[0].2, "[]");
        }

        /// A coin only a contact's pool knows is the contact's, so dropping an
        /// unsigned claim on it does not make it the wallet's.
        #[test]
        fn a_contacts_coin_is_not_given_back() {
            let w = [0xB8u8; 32];
            let (mut conn, _, _, _) = old_build_store(&w, 0x99, pending);
            conn.execute(
                "UPDATE core_address_pool SET account_type = 'dashpay_external' WHERE wallet_id = ?1",
                params![&w[..]],
            )
            .unwrap();
            assert_eq!(repair(&mut conn), 1);
            assert_eq!(unspent(&conn, &w), Vec::<OutPoint>::new());
            assert_eq!(kept(&conn, &w)[0].2, "[]");
        }

        #[test]
        fn a_spend_the_owner_signed_stays_spent() {
            let w = [0xB2u8; 32];
            let (mut conn, _, change, claim) =
                old_build_store(&w, 0x31, |_| TransactionContext::Mempool);
            assert_eq!(repair(&mut conn), 0);
            assert_eq!(unspent(&conn, &w), vec![change.outpoint]);
            assert!(get_tx_record(&conn, &w, &claim.txid(), &LoadCtx::strict())
                .unwrap()
                .is_some());
        }

        #[test]
        fn a_mined_or_verified_locked_spend_stays_spent_even_unsigned() {
            for (byte, (mut conn, _, change, claim)) in [
                (0xB3u8, old_build_store(&[0xB3; 32], 0x99, mined)),
                (0xB4u8, old_build_store(&[0xB4; 32], 0x99, locked)),
            ] {
                let w = [byte; 32];
                assert_eq!(repair(&mut conn), 0);
                assert_eq!(unspent(&conn, &w), vec![change.outpoint]);
                assert!(get_tx_record(&conn, &w, &claim.txid(), &LoadCtx::strict())
                    .unwrap()
                    .is_some());
            }
        }

        #[test]
        fn a_coin_another_stored_spend_claims_stays_spent() {
            let w = [0xB5u8; 32];
            let (mut conn, held, _, _) = old_build_store(&w, 0x99, |_| TransactionContext::Mempool);
            let me = owner(0x31);
            let own = spend(
                &held,
                &me,
                &me,
                vec![TxOut {
                    value: 490_000,
                    script_pubkey: owner(0x78).address.script_pubkey(),
                }],
            );
            store(
                &mut conn,
                &w,
                &CoreChangeSet {
                    records: vec![spend_record(own, TransactionContext::Mempool)],
                    ..Default::default()
                },
            );
            assert_eq!(repair(&mut conn), 1);
            assert_eq!(unspent(&conn, &w), Vec::<OutPoint>::new());
        }
    }

    fn wallet_db(w: &[u8; 32]) -> rusqlite::Connection {
        wallet_db_in(rusqlite::Connection::open_in_memory().unwrap(), w)
    }

    fn wallet_db_in(mut conn: rusqlite::Connection, w: &[u8; 32]) -> rusqlite::Connection {
        crate::sqlite::migrations::run(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&w[..]],
        )
        .unwrap();
        conn
    }

    fn store(conn: &mut rusqlite::Connection, w: &[u8; 32], cs: &CoreChangeSet) {
        let tx = conn.transaction().unwrap();
        apply(&tx, w, cs).unwrap();
        tx.commit().unwrap();
    }

    /// A payment received, flushed, then its verified lock, flushed, then a
    /// restart before it is mined: its history reads it locked, and the lock
    /// its coin is restored with is the same.
    #[test]
    fn a_lock_stored_after_its_payment_counts_for_history_and_coin_alike() {
        use dashcore::ephemerealdata::instant_lock::InstantLock;
        let w = [0xADu8; 32];
        let mut conn = wallet_db(&w);
        let txid = Txid::from_byte_array([0x44; 32]);
        store(
            &mut conn,
            &w,
            &CoreChangeSet {
                records: vec![transaction_record(txid, TransactionContext::Mempool)],
                new_utxos: vec![sample_utxo(txid, 0, false)],
                ..Default::default()
            },
        );
        let lock = InstantLock {
            txid,
            ..InstantLock::default()
        };
        let mut locked = CoreChangeSet::default();
        locked
            .instant_locks_for_non_final_records
            .insert(txid, lock.clone());
        store(&mut conn, &w, &locked);

        let (loaded, _) =
            load_state(&conn, &w, dashcore::Network::Testnet, &LoadCtx::strict()).unwrap();
        let locked_context = TransactionContext::InstantSend(lock.clone());
        assert_eq!(
            loaded.records[0].context, locked_context,
            "the history, loaded"
        );
        let read = get_tx_record(&conn, &w, &txid, &LoadCtx::strict())
            .unwrap()
            .expect("stored record");
        assert_eq!(read.context, locked_context, "the history, read alone");
        assert!(loaded.new_utxos.iter().any(|u| u.outpoint.txid == txid));
        assert_eq!(
            loaded.instant_locks_for_non_final_records,
            BTreeMap::from([(txid, lock)]),
            "the coin is restored with the same lock"
        );
    }

    /// A lock row whose lock names another transaction proves nothing for
    /// its key.
    #[test]
    fn a_stored_lock_naming_another_transaction_is_not_trusted() {
        use dashcore::ephemerealdata::instant_lock::InstantLock;
        let w = [0xAEu8; 32];
        let mut conn = wallet_db(&w);
        let txid = Txid::from_byte_array([0x45; 32]);
        store(
            &mut conn,
            &w,
            &CoreChangeSet {
                records: vec![transaction_record(txid, TransactionContext::Mempool)],
                ..Default::default()
            },
        );
        let other = InstantLock {
            txid: Txid::from_byte_array([0x46; 32]),
            ..InstantLock::default()
        };
        conn.execute(
            "INSERT INTO core_instant_locks (wallet_id, txid, islock_blob, verified) \
             VALUES (?1, ?2, ?3, 1)",
            params![
                &w[..],
                AsRef::<[u8]>::as_ref(&txid),
                blob::encode(&other).unwrap()
            ],
        )
        .unwrap();

        let (loaded, _) =
            load_state(&conn, &w, dashcore::Network::Testnet, &LoadCtx::strict()).unwrap();
        assert!(loaded.instant_locks_for_non_final_records.is_empty());
        assert_eq!(loaded.records[0].context, TransactionContext::Mempool);
        let read = get_tx_record(&conn, &w, &txid, &LoadCtx::strict())
            .unwrap()
            .unwrap();
        assert_eq!(read.context, TransactionContext::Mempool);
    }

    /// The sweep's stored claims follow the same rule: an old InstantSend
    /// label without a verified lock claims nothing, a mempool record whose
    /// verified lock came later does, and so does a mined one.
    #[test]
    fn stored_claims_count_only_what_the_effective_context_makes_final() {
        use dashcore::ephemerealdata::instant_lock::InstantLock;
        let w = [0xAFu8; 32];
        let mut conn = wallet_db(&w);
        let spending = |byte: u8, context: TransactionContext| {
            let mut record = transaction_record(Txid::from_byte_array([byte; 32]), context);
            record.transaction.input = vec![dashcore::TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([byte ^ 0xFF; 32]), 0),
                ..Default::default()
            }];
            record
        };
        let lock = |byte: u8| InstantLock {
            txid: Txid::from_byte_array([byte; 32]),
            ..InstantLock::default()
        };
        let mined = TransactionContext::InBlock(BlockInfo::new(
            90,
            BlockHash::from_byte_array([0x09; 32]),
            1_700_000_000,
        ));
        let records = vec![
            spending(0x51, TransactionContext::InstantSend(lock(0x51))),
            spending(0x52, TransactionContext::Mempool),
            spending(0x53, mined),
        ];
        let input_of = |r: &TransactionRecord| r.transaction.input[0].previous_output;
        let (old_label, late_lock, in_block) = (
            input_of(&records[0]),
            input_of(&records[1]),
            input_of(&records[2]),
        );
        let mut cs = CoreChangeSet {
            records,
            ..Default::default()
        };
        cs.instant_locks_for_non_final_records
            .insert(lock(0x52).txid, lock(0x52));
        store(&mut conn, &w, &cs);
        conn.execute(
            "INSERT INTO core_instant_locks (wallet_id, txid, islock_blob) VALUES (?1, ?2, ?3)",
            params![
                &w[..],
                &[0x51u8; 32][..],
                blob::encode(&lock(0x51)).unwrap()
            ],
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        let claims = surviving_stored_input_claims(&tx, &w, &HashSet::new()).unwrap();
        assert_eq!(claims, HashSet::from([late_lock, in_block]));
        assert!(!claims.contains(&old_label));
    }

    #[test]
    fn load_state_reconciles_utxo_height_from_confirmed_transaction_record() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x42u8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let txid = Txid::from_byte_array([0x7Eu8; 32]);
        let utxo = sample_utxo(txid, 123, true);
        let outpoint = utxo.outpoint;

        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    new_utxos: vec![utxo],
                    records: vec![transaction_record(txid, TransactionContext::Mempool)],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let confirmed_height = 321;
        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    records: vec![transaction_record(
                        txid,
                        TransactionContext::InChainLockedBlock(BlockInfo::new(
                            confirmed_height,
                            BlockHash::from_byte_array([0x34u8; 32]),
                            1_735_689_600,
                        )),
                    )],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::strict(),
        )
        .unwrap();
        let loaded = state
            .new_utxos
            .iter()
            .find(|candidate| candidate.outpoint == outpoint)
            .expect("matching UTXO must be loaded");
        assert_eq!(loaded.height, confirmed_height);
        assert!(loaded.is_confirmed);
    }

    #[test]
    fn load_state_restores_confirmed_recordless_utxo_height() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x44u8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let txid = Txid::from_byte_array([0x80u8; 32]);
        let utxo = sample_utxo(txid, 456, true);
        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    new_utxos: vec![utxo],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::strict(),
        )
        .unwrap();
        let loaded = state.new_utxos.first().expect("recordless UTXO must load");
        assert_eq!(loaded.height, 456);
        assert!(loaded.is_confirmed);
        assert!(state.records.is_empty());
        assert!(get_tx_record(&conn, &wallet_id, &txid, &LoadCtx::strict())
            .unwrap()
            .is_none());
    }

    #[test]
    fn height_only_placeholder_does_not_regress() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x49u8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let txid = Txid::from_byte_array([0x86u8; 32]);
        let mut utxo = sample_utxo(txid, 500, true);
        for stale in [
            CoreChangeSet {
                new_utxos: vec![utxo.clone()],
                ..Default::default()
            },
            {
                utxo.height = 400;
                CoreChangeSet {
                    new_utxos: vec![utxo.clone()],
                    ..Default::default()
                }
            },
            {
                utxo.height = 0;
                utxo.is_confirmed = false;
                CoreChangeSet {
                    new_utxos: vec![utxo],
                    ..Default::default()
                }
            },
        ] {
            let tx = conn.transaction().unwrap();
            apply(&tx, &wallet_id, &stale).unwrap();
            tx.commit().unwrap();
        }

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::strict(),
        )
        .unwrap();
        assert_eq!(state.new_utxos[0].height, 500);
        assert!(state.new_utxos[0].is_confirmed);
    }

    #[test]
    fn load_state_treats_height_zero_as_confirmed() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x4Au8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let txid = Txid::from_byte_array([0x87u8; 32]);
        let tx = conn.transaction().unwrap();
        apply(
            &tx,
            &wallet_id,
            &CoreChangeSet {
                new_utxos: vec![sample_utxo(txid, 0, true)],
                ..Default::default()
            },
        )
        .unwrap();
        tx.commit().unwrap();

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::strict(),
        )
        .unwrap();
        assert_eq!(state.new_utxos[0].height, 0);
        assert!(state.new_utxos[0].is_confirmed);
    }

    #[test]
    fn transaction_record_always_overrides_height_only_placeholder() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x45u8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let txid = Txid::from_byte_array([0x81u8; 32]);
        let mut utxo = sample_utxo(txid, 456, true);
        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    new_utxos: vec![utxo.clone()],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }

        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    records: vec![transaction_record(txid, TransactionContext::Mempool)],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }

        utxo.height = 789;
        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    new_utxos: vec![utxo],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::strict(),
        )
        .unwrap();
        assert_eq!(state.new_utxos[0].height, 0);
        assert!(!state.new_utxos[0].is_confirmed);
        assert_eq!(state.records.len(), 1);

        let confirmed_height = 900;
        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    records: vec![transaction_record(
                        txid,
                        TransactionContext::InChainLockedBlock(BlockInfo::new(
                            confirmed_height,
                            BlockHash::from_byte_array([0x35u8; 32]),
                            1_735_689_700,
                        )),
                    )],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::strict(),
        )
        .unwrap();
        assert_eq!(state.new_utxos[0].height, confirmed_height);
        assert!(state.new_utxos[0].is_confirmed);
    }

    #[test]
    fn load_state_defaults_utxo_without_transaction_record_to_unconfirmed() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x43u8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let txid = Txid::from_byte_array([0x7Fu8; 32]);
        let address = dashcore::Address::new(
            dashcore::Network::Testnet,
            Payload::PubkeyHash(PubkeyHash::from_byte_array([0x24u8; 20])),
        );
        let outpoint = OutPoint { txid, vout: 0 };
        let utxo = Utxo::new(
            outpoint,
            TxOut {
                value: 175_000,
                script_pubkey: address.script_pubkey(),
            },
            address,
            777,
            false,
        );

        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    new_utxos: vec![utxo],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::strict(),
        )
        .unwrap();
        let loaded = state
            .new_utxos
            .iter()
            .find(|candidate| candidate.outpoint == outpoint)
            .expect("matching UTXO must be loaded");
        assert_eq!(loaded.height, 0);
        assert!(!loaded.is_confirmed);
    }

    #[test]
    fn load_state_tolerates_transaction_blob_txid_drift_in_recovery_without_repairing() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x46u8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let blob_txid = Txid::from_byte_array([0x82u8; 32]);
        let typed_txid = Txid::from_byte_array([0x83u8; 32]);
        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    records: vec![transaction_record(blob_txid, TransactionContext::Mempool)],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }
        conn.execute(
            "UPDATE core_transactions SET txid = ?1 WHERE wallet_id = ?2",
            params![AsRef::<[u8]>::as_ref(&typed_txid), wallet_id.as_slice()],
        )
        .unwrap();

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::recovery(),
        )
        .expect("recovery mode must reconstruct from the authoritative blob");
        assert_eq!(state.records[0].txid, blob_txid);
        let on_disk: Vec<u8> = conn
            .query_row(
                "SELECT txid FROM core_transactions WHERE wallet_id = ?1",
                params![wallet_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            on_disk,
            AsRef::<[u8]>::as_ref(&typed_txid),
            "a read must never rewrite the row it read"
        );
    }

    #[test]
    fn load_state_blob_height_wins_over_drifted_typed_column_in_either_scan_order() {
        for (case, typed_byte) in [0x10, 0xF0].into_iter().enumerate() {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            crate::sqlite::migrations::run(&mut conn).unwrap();
            let wallet_id = [0x50 + case as u8; 32];
            conn.execute(
                "INSERT INTO wallets (wallet_id, network, birth_height) \
                 VALUES (?1, 'testnet', 0)",
                params![&wallet_id[..]],
            )
            .unwrap();

            let blob_txid = Txid::from_byte_array([0x80; 32]);
            let typed_txid = Txid::from_byte_array([typed_byte; 32]);
            let confirmed_utxo = sample_utxo(blob_txid, 500, true);
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    new_utxos: vec![confirmed_utxo.clone()],
                    records: vec![transaction_record(
                        blob_txid,
                        TransactionContext::InChainLockedBlock(BlockInfo::new(
                            500,
                            BlockHash::from_byte_array([0x38; 32]),
                            1_735_690_000,
                        )),
                    )],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
            conn.execute(
                "UPDATE core_transactions SET txid = ?1 WHERE wallet_id = ?2",
                params![AsRef::<[u8]>::as_ref(&typed_txid), wallet_id.as_slice()],
            )
            .unwrap();

            let mut stale_utxo = confirmed_utxo;
            stale_utxo.height = 100;
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    new_utxos: vec![stale_utxo],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();

            let (state, _) = load_state(
                &conn,
                &wallet_id,
                dashcore::Network::Testnet,
                &LoadCtx::recovery(),
            )
            .expect("recovery mode must still reconstruct blob-authoritative state");
            let loaded = state.new_utxos.first().expect("UTXO must load");
            assert_eq!(loaded.height, 500, "failed scan-order case {case}");
            assert!(loaded.is_confirmed);
        }
    }

    #[test]
    fn load_state_tolerates_transaction_blob_height_drift_in_recovery_without_repairing() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x47u8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let txid = Txid::from_byte_array([0x84u8; 32]);
        {
            let tx = conn.transaction().unwrap();
            apply(
                &tx,
                &wallet_id,
                &CoreChangeSet {
                    records: vec![transaction_record(
                        txid,
                        TransactionContext::InChainLockedBlock(BlockInfo::new(
                            500,
                            BlockHash::from_byte_array([0x36u8; 32]),
                            1_735_689_800,
                        )),
                    )],
                    ..Default::default()
                },
            )
            .unwrap();
            tx.commit().unwrap();
        }
        conn.execute(
            "UPDATE core_transactions SET height = 501 WHERE wallet_id = ?1",
            params![wallet_id.as_slice()],
        )
        .unwrap();

        let (state, _) = load_state(
            &conn,
            &wallet_id,
            dashcore::Network::Testnet,
            &LoadCtx::recovery(),
        )
        .expect("recovery mode must reconstruct from the authoritative blob");
        assert_eq!(state.records[0].height(), Some(500));
        let on_disk: Option<i64> = conn
            .query_row(
                "SELECT height FROM core_transactions WHERE wallet_id = ?1",
                params![wallet_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            on_disk,
            Some(501),
            "a read must never rewrite the row it read"
        );
    }

    /// A txid-drifted row names a DIFFERENT transaction than the one asked
    /// for, so recovery mode must decline to answer rather than hand back
    /// the wrong record. Contrast the height-drift sibling below, where the
    /// blob stays authoritative and the record is still served.
    #[test]
    fn get_tx_record_declines_a_txid_drifted_row_in_recovery_without_repairing() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x4Bu8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let blob_txid = Txid::from_byte_array([0x88u8; 32]);
        let typed_txid = Txid::from_byte_array([0x89u8; 32]);
        let tx = conn.transaction().unwrap();
        apply(
            &tx,
            &wallet_id,
            &CoreChangeSet {
                records: vec![transaction_record(blob_txid, TransactionContext::Mempool)],
                ..Default::default()
            },
        )
        .unwrap();
        tx.commit().unwrap();
        conn.execute(
            "UPDATE core_transactions SET txid = ?1 WHERE wallet_id = ?2",
            params![AsRef::<[u8]>::as_ref(&typed_txid), wallet_id.as_slice()],
        )
        .unwrap();

        assert!(
            get_tx_record(&conn, &wallet_id, &typed_txid, &LoadCtx::recovery())
                .expect("recovery mode tolerates the drift instead of erroring")
                .is_none(),
            "the row's blob names a different transaction than the one asked \
             for; recovery must decline rather than serve the wrong record"
        );
        // The row was NOT repaired, so the blob txid still matches no row.
        assert!(
            get_tx_record(&conn, &wallet_id, &blob_txid, &LoadCtx::recovery())
                .unwrap()
                .is_none(),
            "a read must never rewrite the row it read"
        );
        // Declining is not deleting: the drifted row is still on disk under
        // its typed txid, for an operator or a later repair pass to find.
        let still_present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM core_transactions WHERE wallet_id = ?1 AND txid = ?2",
                params![wallet_id.as_slice(), AsRef::<[u8]>::as_ref(&typed_txid)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(still_present, 1, "a read must never delete the row it read");
    }

    #[test]
    fn get_tx_record_tolerates_blob_height_drift_in_recovery_without_repairing() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x4Cu8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();

        let txid = Txid::from_byte_array([0x8Au8; 32]);
        let tx = conn.transaction().unwrap();
        apply(
            &tx,
            &wallet_id,
            &CoreChangeSet {
                records: vec![transaction_record(
                    txid,
                    TransactionContext::InChainLockedBlock(BlockInfo::new(
                        600,
                        BlockHash::from_byte_array([0x37u8; 32]),
                        1_735_689_900,
                    )),
                )],
                ..Default::default()
            },
        )
        .unwrap();
        tx.commit().unwrap();
        conn.execute(
            "UPDATE core_transactions SET height = 601 WHERE wallet_id = ?1",
            params![wallet_id.as_slice()],
        )
        .unwrap();

        let record = get_tx_record(&conn, &wallet_id, &txid, &LoadCtx::recovery())
            .expect("recovery mode must still serve the point read")
            .expect("blob-bearing row must return its record");
        assert_eq!(record.height(), Some(600));
        let on_disk: Option<i64> = conn
            .query_row(
                "SELECT height FROM core_transactions WHERE wallet_id = ?1",
                params![wallet_id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            on_disk,
            Some(601),
            "a read must never rewrite the row it read"
        );
    }

    /// `load_used_addresses` (the address-reuse-guard rehydration path called
    /// from `persister.rs`) must surface `AddressDecode` — carrying the
    /// upstream `dashcore::address::Error` — when a stored `core_utxos.script`
    /// parses as bytes but not as an address, not the context-free `BlobDecode`.
    #[test]
    fn load_used_addresses_wraps_address_error_as_address_decode() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let w = [0x99u8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&w[..]],
        )
        .unwrap();
        // A bare OP_RETURN script is well-formed bytes but not any address
        // type, so `Address::from_script` returns `UnrecognizedScript`.
        let bad_script = [0x6au8];
        conn.execute(
            "INSERT INTO core_utxos \
                (wallet_id, outpoint, value, script, spent) \
             VALUES (?1, ?2, 0, ?3, 0)",
            params![&w[..], &[0u8; 36][..], &bad_script[..]],
        )
        .unwrap();

        let err =
            load_used_addresses_with_ctx(&conn, &w, dashcore::Network::Testnet, &LoadCtx::strict())
                .expect_err("an unparseable script must be a hard error");
        assert!(
            matches!(err, WalletStorageError::AddressDecode { .. }),
            "expected AddressDecode carrying the upstream error, got {err:?}"
        );
    }

    /// An empty `script` must be refused by the WRITER, not discovered by
    /// the reader. `load()` turns every stored script back into an address,
    /// so one such row rejects the load of the entire database file — the
    /// shape migration V015 had to purge. `execute_upsert_utxo` is the only
    /// writer of `core_utxos.script`, so guarding it closes the producer.
    #[test]
    fn apply_refuses_an_empty_script_on_a_new_utxo() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x5Bu8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();
        let mut utxo = sample_utxo(Txid::from_byte_array([0x5Bu8; 32]), 10, true);
        utxo.txout.script_pubkey = dashcore::ScriptBuf::from_bytes(Vec::new());
        let outpoint = utxo.outpoint;
        let cs = CoreChangeSet {
            new_utxos: vec![utxo],
            ..Default::default()
        };

        let tx = conn.transaction().unwrap();
        let err = apply(&tx, &wallet_id, &cs).expect_err("an empty script must be refused");
        match err {
            WalletStorageError::EmptyUtxoScript { outpoint: got } => {
                assert_eq!(got, outpoint, "the error must name the offending outpoint");
            }
            other => panic!("expected EmptyUtxoScript, got {other:?}"),
        }
        let rows: i64 = tx
            .query_row("SELECT COUNT(*) FROM core_utxos", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0, "the guard must refuse before binding the row");
    }

    /// The spend path synthesises a `spent = 1` row when the UTXO has no
    /// existing row, which is exactly the shape V015 had to delete. It runs
    /// through the same writer, so it must be refused on the same terms.
    #[test]
    fn apply_refuses_an_empty_script_on_a_synthetic_spent_row() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x5Cu8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();
        let mut utxo = sample_utxo(Txid::from_byte_array([0x5Cu8; 32]), 10, true);
        utxo.txout.script_pubkey = dashcore::ScriptBuf::from_bytes(Vec::new());
        let cs = CoreChangeSet {
            spent_utxos: vec![utxo],
            ..Default::default()
        };

        let tx = conn.transaction().unwrap();
        let err = apply(&tx, &wallet_id, &cs).expect_err("an empty script must be refused");
        assert!(
            matches!(err, WalletStorageError::EmptyUtxoScript { .. }),
            "the synthetic spent-row insert must be guarded too, got {err:?}"
        );
        let rows: i64 = tx
            .query_row("SELECT COUNT(*) FROM core_utxos", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0, "the guard must refuse before binding the row");
    }

    /// Marking an EXISTING row spent never rewrites `script`, so a healthy
    /// row must still be spendable — the guard must not turn a legitimate
    /// spend into a write failure.
    #[test]
    fn apply_still_marks_an_existing_utxo_spent() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::sqlite::migrations::run(&mut conn).unwrap();
        let wallet_id = [0x5Du8; 32];
        conn.execute(
            "INSERT INTO wallets (wallet_id, network, birth_height) VALUES (?1, 'testnet', 0)",
            params![&wallet_id[..]],
        )
        .unwrap();
        let utxo = sample_utxo(Txid::from_byte_array([0x5Du8; 32]), 10, true);
        let tx = conn.transaction().unwrap();
        apply(
            &tx,
            &wallet_id,
            &CoreChangeSet {
                new_utxos: vec![utxo.clone()],
                ..Default::default()
            },
        )
        .expect("a well-formed script must still be accepted");
        apply(
            &tx,
            &wallet_id,
            &CoreChangeSet {
                spent_utxos: vec![utxo],
                ..Default::default()
            },
        )
        .expect("spending an existing row must still be accepted");
        let spent: bool = tx
            .query_row("SELECT spent FROM core_utxos", [], |row| row.get(0))
            .unwrap();
        assert!(spent, "the existing row must be marked spent");
    }

    #[test]
    fn chain_lock_height_rejects_trailing_bytes() {
        let bytes = encode_chain_lock(&sample_chain_lock(100_000)).expect("encode");
        assert_eq!(chain_lock_height(&bytes), Some(100_000));

        // A corrupt blob (valid prefix + trailing garbage) must not yield a
        // height, else it stays stuck atop later valid lower-height updates.
        let mut corrupt = bytes.clone();
        corrupt.extend_from_slice(&[0xFFu8; 4]);
        assert_eq!(chain_lock_height(&corrupt), None);
    }
}
