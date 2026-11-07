//! Storage abstraction for shielded wallet state.
//!
//! The `ShieldedStore` trait decouples `ShieldedWallet` from any
//! particular persistence backend. Consumers provide their own
//! implementation (e.g. SwiftData via the host persister) while
//! tests can use [`InMemoryShieldedStore`].
//!
//! # Multi-tenant scoping
//!
//! Decrypted notes, nullifier bookkeeping, and per-account sync
//! watermarks are scoped by [`SubwalletId`] (a `(wallet_id,
//! account_index)` tuple) so a single store can host every wallet
//! and every shielded account on the same network. The Orchard
//! commitment tree itself is **not** scoped — the on-chain
//! commitment stream is identical for every consumer on a given
//! network, so one tree backs them all.
//!
//! # Note format
//!
//! `ShieldedNote::note_data` is a serialized `orchard::Note` (115
//! bytes). The witness path returned by [`ShieldedStore::witness`]
//! is the typed `grovedb_commitment_tree::MerklePath` because that
//! type doesn't implement serde — a bytes contract would force
//! every caller through a serializer that doesn't exist.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;

use super::balance::ShieldedBalanceSource;
use crate::wallet::platform_wallet::WalletId;

/// Identifies a single shielded "subwallet" — one Orchard account
/// within one wallet. Used to scope notes, nullifier indices, and
/// sync watermarks inside a [`ShieldedStore`] so a single store
/// can hold state for many wallets/accounts without leakage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubwalletId {
    /// 32-byte wallet identifier (matches `PlatformWallet::wallet_id`).
    pub wallet_id: [u8; 32],
    /// ZIP-32 account index (`m / 32' / coin_type' / account'`).
    pub account_index: u32,
}

impl SubwalletId {
    /// Construct a [`SubwalletId`] from its parts.
    pub fn new(wallet_id: [u8; 32], account_index: u32) -> Self {
        Self {
            wallet_id,
            account_index,
        }
    }
}

/// A note decrypted and owned by a specific subwallet.
///
/// Carries the bookkeeping the spend pipeline needs without
/// pulling the orchard crate into this trait. The actual
/// `orchard::Note` is in `note_data` as 115 bytes
/// (`recipient(43) || value(8 LE) || rho(32) || rseed(32)`).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShieldedNote {
    /// Global position in the commitment tree.
    pub position: u64,
    /// Extracted note commitment (32 bytes).
    pub cmx: [u8; 32],
    /// Nullifier for detecting when spent (32 bytes).
    pub nullifier: [u8; 32],
    /// Proven platform height of the chunk fetch that surfaced the note.
    /// Stamped per-batch — the SAME height OVK-recovered outgoing notes
    /// from that chunk get — so the activity deriver can cluster one
    /// bundle's incoming change and outgoing send together by height.
    ///
    /// This is an *observed at-or-before* bound (the tip the fetch was
    /// proven at), NOT the note's inclusion height, which the proof
    /// doesn't carry. It is a grouping key only — never surface it as
    /// when the note was mined (scan-derived activity entries carry
    /// `block_height: None` for exactly this reason).
    pub block_height: u64,
    /// Whether the nullifier was seen on-chain (spent).
    pub is_spent: bool,
    /// Note value in credits.
    pub value: u64,
    /// Serialized `orchard::Note` bytes (115 bytes).
    pub note_data: Vec<u8>,
}

/// A note this subwallet **sent**, recovered during the note scan via
/// the wallet's Outgoing Viewing Key (the Zcash outgoing-transaction-
/// history mechanism).
///
/// Unlike [`ShieldedNote`] (which is a note the wallet *received* and
/// can later spend), this is a minimal record of an *outgoing*
/// payment — who the wallet paid, how much, and with what memo —
/// kept purely for send-history display. It carries no spend
/// bookkeeping (no nullifier / position / witness) because the wallet
/// cannot spend a note it sent to someone else.
///
/// Keyed by `cmx` (the recovered output note's commitment), which is
/// globally unique on-chain, so recording the same recovered note
/// twice (a re-scan of the same chunk) is idempotent.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ShieldedOutgoingNote {
    /// Extracted note commitment (32 bytes) of the note that was sent.
    /// Primary key — unique per on-chain output.
    pub cmx: [u8; 32],
    /// Recipient's raw Orchard address (43 bytes,
    /// `Address::to_raw_address_bytes`). The wallet paid this address.
    /// Stored as a `Vec` rather than `[u8; 43]` because `serde`'s derive
    /// only covers fixed arrays up to length 32; always 43 bytes for a
    /// recovered note.
    pub recipient: Vec<u8>,
    /// Value sent, in credits.
    pub value: u64,
    /// Raw Dash memo bytes (`DashMemo`, 36 bytes). Stored as a `Vec`
    /// rather than `[u8; 36]` so the persisted shape stays flexible if
    /// the memo size ever changes; always 36 bytes for a recovered note.
    pub memo: Vec<u8>,
    /// Proven platform height of the chunk fetch that recovered the
    /// note — the same per-batch *observed at-or-before* bound (and
    /// grouping key) as [`ShieldedNote::block_height`]; NOT the height
    /// the send was mined at.
    pub block_height: u64,
}

/// A pending reservation that carries a recorded anchor:
/// `(nullifier, anchor, activity_id)`. Yielded by
/// [`ShieldedStore::stale_pending_spends`] for the sync reconcile,
/// which releases the reservation once `anchor` is no longer in
/// Platform's recorded set (the spend can then never execute).
pub type StalePendingSpend = ([u8; 32], [u8; 32], Option<[u8; 32]>);

/// An unresolved signed transition and its durable retry guard: the signed
/// transition bytes plus everything the sync-time re-drive needs to
/// resolve the ambiguity actively — re-broadcast the transition
/// ([`nullifiers`](Self::nullifiers) detect a landing, `anchor` feeds
/// the prune backstop, `activity_id` links the UI row, `attempts`
/// bounds the retries.
///
/// Identity-funded shields arm this record before broadcast and have no input
/// nullifiers. Their guard survives even after rebroadcasting stops. Note spends
/// arm it only on the ambiguous outcome (`ShieldedSpendUnconfirmed`):
/// the broadcast was accepted but the result wait failed, so the spend
/// may or may not have executed. Re-broadcasting the byte-identical
/// transition is fund-safe — identical nullifiers cannot double-spend —
/// and converts silence into either a confirmation (next scan sees the
/// nullifiers spent) or a definitive consensus verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRedrive {
    /// Activity-entry id of the spend (sha256 of visible output cmxs);
    /// the spend-level key — every nullifier of one spend shares it.
    pub activity_id: [u8; 32],
    /// Platform-recorded anchor the spend was built against.
    pub anchor: [u8; 32],
    /// Nullifiers of every note the spend consumes.
    pub nullifiers: Vec<[u8; 32]>,
    /// The signed state transition, platform-serialized byte-exact as
    /// originally broadcast.
    pub st_bytes: Vec<u8>,
    /// Re-broadcast attempts made so far.
    pub attempts: u32,
    /// A proven identity nonce has made this exact debit impossible to execute
    /// again. Stop broadcasting, but keep its unresolved-payment guard until
    /// the scan confirms the outputs. Always false for note-spend redrives.
    pub identity_nonce_finalized: bool,
    /// The host explicitly accepted that this payment may have executed or may
    /// still execute. Retain the signed record for reconciliation/audit, but stop
    /// automatic retries and permit separately authorized new payments.
    /// This is never a proof of failure and is always false for note spends.
    pub identity_user_abandoned: bool,
}

impl PendingRedrive {
    /// SHA-256 of [`st_bytes`](Self::st_bytes), and the key the spend's
    /// disposition is recorded under. For bytes that are a transition's
    /// platform serialization, as the library writes them, this equals that
    /// transition's `StateTransition::transaction_id()`. Computed from the
    /// bytes, so it needs no decode and also exists for a record whose bytes
    /// no longer deserialize.
    pub fn st_hash(&self) -> [u8; 32] {
        dpp::util::hash::hash_single(&self.st_bytes)
    }
}

/// Why a durable note-spend record was resolved, as evidence about whether its
/// signed transition executed on Platform.
///
/// Consumers read these as evidence, so each value is written only with the
/// proof its documentation names, and a missing record is never evidence of
/// either outcome. When neither outcome is proved, the value is
/// [`Unresolved`](Self::Unresolved). The enum is deliberately exhaustive: a new
/// value is a breaking change, so no reader can fold it into a default arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShieldedSpendDisposition {
    /// Proof that this transition executed: Platform reported its input
    /// nullifiers spent while this record still reserved those notes, so no
    /// other spend by this wallet could have consumed them.
    Executed,
    /// Proof that this transition has not executed and never can; the reason
    /// names the proof.
    NotExecuted(NotExecutedReason),
    /// The record is gone without proof of either outcome. The transition may
    /// have executed or may still execute.
    Unresolved(UnresolvedReason),
}

/// The proof behind [`ShieldedSpendDisposition::NotExecuted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotExecutedReason {
    /// The host's dispatch hook refused the transition before its first
    /// broadcast. Nothing was sent.
    Refused,
    /// The user abandoned the transition before anything was broadcast.
    /// Nothing was sent.
    Abandoned,
    /// Platform returned a definitive consensus rejection for these exact
    /// transition bytes.
    Rejected,
    /// The anchor the transition was built against left Platform's recorded
    /// anchor set while its nullifiers were still unspent, so its proof can
    /// never verify.
    Pruned,
}

/// Why a record was resolved as [`ShieldedSpendDisposition::Unresolved`].
/// None of these values proves either outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnresolvedReason {
    /// The stored transition bytes no longer deserialize, so the record was
    /// dropped without a rebroadcast. The bytes may still have executed.
    DeserializeDropped,
    /// A wallet or account purge removed the record without proof of either
    /// outcome.
    Purged,
}

/// A stored disposition string that this build does not know. Decoding never
/// substitutes a default for it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown shielded spend disposition {kind:?} with reason {reason:?}")]
pub struct UnknownDispositionValue {
    /// The stored disposition string.
    pub kind: String,
    /// The stored reason string, if any.
    pub reason: Option<String>,
}

impl ShieldedSpendDisposition {
    /// Stable stored string for the disposition kind.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::NotExecuted(_) => "not_executed",
            Self::Unresolved(_) => "unresolved",
        }
    }

    /// Stable stored string for the reason. `None` exactly for
    /// [`Executed`](Self::Executed).
    pub fn reason_str(&self) -> Option<&'static str> {
        match self {
            Self::Executed => None,
            Self::NotExecuted(NotExecutedReason::Refused) => Some("refused"),
            Self::NotExecuted(NotExecutedReason::Abandoned) => Some("abandoned"),
            Self::NotExecuted(NotExecutedReason::Rejected) => Some("rejected"),
            Self::NotExecuted(NotExecutedReason::Pruned) => Some("pruned"),
            Self::Unresolved(UnresolvedReason::DeserializeDropped) => Some("deserialize_dropped"),
            Self::Unresolved(UnresolvedReason::Purged) => Some("purged"),
        }
    }

    /// Decode the strings written by [`kind_str`](Self::kind_str) and
    /// [`reason_str`](Self::reason_str). Any other combination, including a
    /// known reason under the wrong kind, is an error.
    pub fn from_stored(kind: &str, reason: Option<&str>) -> Result<Self, UnknownDispositionValue> {
        let decoded = match (kind, reason) {
            ("executed", None) => Some(Self::Executed),
            ("not_executed", Some("refused")) => {
                Some(Self::NotExecuted(NotExecutedReason::Refused))
            }
            ("not_executed", Some("abandoned")) => {
                Some(Self::NotExecuted(NotExecutedReason::Abandoned))
            }
            ("not_executed", Some("rejected")) => {
                Some(Self::NotExecuted(NotExecutedReason::Rejected))
            }
            ("not_executed", Some("pruned")) => Some(Self::NotExecuted(NotExecutedReason::Pruned)),
            ("unresolved", Some("deserialize_dropped")) => {
                Some(Self::Unresolved(UnresolvedReason::DeserializeDropped))
            }
            ("unresolved", Some("purged")) => Some(Self::Unresolved(UnresolvedReason::Purged)),
            _ => None,
        };
        decoded.ok_or_else(|| UnknownDispositionValue {
            kind: kind.to_owned(),
            reason: reason.map(str::to_owned),
        })
    }
}

/// An unacknowledged disposition, kept until
/// [`ShieldedStore::ack_disposition`] removes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedSpendDispositionRecord {
    /// The subwallet that owned the resolved record.
    pub subwallet: SubwalletId,
    /// [`PendingRedrive::st_hash`] of the transition; the key.
    pub st_hash: [u8; 32],
    /// Activity-entry id of the spend.
    pub activity_id: [u8; 32],
    /// The evidence.
    pub disposition: ShieldedSpendDisposition,
    /// Wall-clock milliseconds since the Unix epoch when it was written.
    pub at_ms: u64,
}

/// A disposition write or redrive resolution the store refused. Nothing was
/// changed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShieldedDispositionRefusal {
    /// No armed redrive exists for `activity_id` in this subwallet.
    #[error("no armed shielded redrive for activity {}", hex::encode(activity_id))]
    RedriveNotFound { activity_id: [u8; 32] },
    /// The redrive is an identity-debit guard (no input nullifiers). Those
    /// keep their own recovery model and are never resolved by disposition.
    #[error(
        "shielded redrive for activity {} is an identity debit, not a note spend",
        hex::encode(activity_id)
    )]
    IdentityDebit { activity_id: [u8; 32] },
    /// [`ShieldedSpendDisposition::Executed`] was asked for while another
    /// armed redrive also reserves one of this record's notes, so a spent
    /// nullifier does not show which of the two executed.
    #[error(
        "shielded redrive for activity {} shares a reserved note with activity {}; its execution is not provable",
        hex::encode(activity_id),
        hex::encode(other_activity_id)
    )]
    ReservationShared {
        activity_id: [u8; 32],
        other_activity_id: [u8; 32],
    },
    /// A redrive for this transition or activity is still armed in the
    /// wallet, so the disposition must be written by resolving it.
    #[error(
        "shielded redrive for activity {} is still armed; resolve it instead",
        hex::encode(activity_id)
    )]
    RedriveArmed { activity_id: [u8; 32] },
    /// An unacknowledged disposition for `st_hash` in the same wallet
    /// already holds different evidence (another value, activity or account).
    #[error(
        "transition {} already has disposition {existing:?} for account {existing_account_index} activity {}; refusing {attempted:?} for account {attempted_account_index} activity {}",
        hex::encode(st_hash),
        hex::encode(existing_activity_id),
        hex::encode(attempted_activity_id)
    )]
    Conflict {
        st_hash: [u8; 32],
        existing_account_index: u32,
        existing_activity_id: [u8; 32],
        existing: ShieldedSpendDisposition,
        attempted_account_index: u32,
        attempted_activity_id: [u8; 32],
        attempted: ShieldedSpendDisposition,
    },
}

/// Access to the [`ShieldedDispositionRefusal`] a store error carries, so
/// code generic over [`ShieldedStore`] can tell a refusal from a storage
/// failure.
pub trait AsDispositionRefusal {
    /// The refusal this error is, if it is one.
    fn disposition_refusal(&self) -> Option<&ShieldedDispositionRefusal>;
}

/// Decide a disposition write against the unacknowledged one already stored
/// for the same wallet and `st_hash`: `Ok(Some(record))` is the record to
/// write, `Ok(None)` is an identical no-op, and different evidence is a
/// conflict.
pub(super) fn disposition_to_write(
    existing: Option<&ShieldedSpendDispositionRecord>,
    id: SubwalletId,
    st_hash: &[u8; 32],
    activity_id: &[u8; 32],
    disposition: ShieldedSpendDisposition,
) -> Result<Option<ShieldedSpendDispositionRecord>, ShieldedDispositionRefusal> {
    match existing {
        Some(existing)
            if existing.subwallet == id
                && existing.activity_id == *activity_id
                && existing.disposition == disposition =>
        {
            Ok(None)
        }
        Some(existing) => Err(ShieldedDispositionRefusal::Conflict {
            st_hash: *st_hash,
            existing_account_index: existing.subwallet.account_index,
            existing_activity_id: existing.activity_id,
            existing: existing.disposition,
            attempted_account_index: id.account_index,
            attempted_activity_id: *activity_id,
            attempted: disposition,
        }),
        None => Ok(Some(ShieldedSpendDispositionRecord {
            subwallet: id,
            st_hash: *st_hash,
            activity_id: *activity_id,
            disposition,
            at_ms: crate::util::now_ms(),
        })),
    }
}

/// What the wallet knows about an identity debit's local recovery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityDebitRecoveryStatus {
    /// The original signed transaction may still be retried.
    Retrying,
    /// Its nonce is unavailable; output confirmation is still missing.
    Parked,
    /// The user accepted an unknown outcome and stopped automatic recovery.
    Unknown,
}

/// An active or explicitly abandoned identity debit retained by the wallet.
/// Missing decoded fields indicate a damaged record; the wallet/account/activity
/// key still allows a deliberate, precisely scoped recovery decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDebitRecoveryRecord {
    pub account_index: u32,
    pub activity_id: [u8; 32],
    pub identity_id: Option<[u8; 32]>,
    pub nonce: Option<u64>,
    pub amount: Option<u64>,
    pub status: IdentityDebitRecoveryStatus,
}

/// The result of [`SubwalletState::mark_spent`].
///
/// `newly_spent` preserves the historical `bool` return (the
/// unspent→spent transition, which the durable store keys its
/// note-row write on). `dropped_redrives` carries the activity ids of
/// any redrive records resolved by this nullifier so the durable store
/// can mirror the SQLite deletion — even on the already-spent path,
/// where the in-memory drop happens but `newly_spent` is false.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct MarkSpentOutcome {
    pub newly_spent: bool,
    pub dropped_redrives: Vec<[u8; 32]>,
}

/// Storage abstraction for shielded wallet state.
///
/// Consumers implement this for their persistence layer. The
/// trait is object-safe (no generics on method signatures) so it
/// can be stored behind `Arc<RwLock<dyn ShieldedStore>>`.
///
/// All mutating methods take `&mut self` so implementations can
/// batch writes without interior mutability.
pub trait ShieldedStore: Send + Sync {
    /// The error type returned by storage operations.
    type Error: StdError + AsDispositionRefusal + Send + Sync + 'static;

    // ── Notes (per-subwallet) ──────────────────────────────────────────

    /// Persist a newly decrypted note for `id`.
    fn save_note(&mut self, id: SubwalletId, note: &ShieldedNote) -> Result<(), Self::Error>;

    /// Return all unspent notes for `id`.
    fn get_unspent_notes(&self, id: SubwalletId) -> Result<Vec<ShieldedNote>, Self::Error>;

    /// The same reservation-aware sum used by sync and local balance reads.
    /// Implementations must reject sums exceeding `u64::MAX` with their storage
    /// error, rather than wrapping, saturating, or panicking.
    fn spendable_balance(&self, id: SubwalletId) -> Result<u64, Self::Error>;

    /// Return all notes (spent and unspent) for `id`.
    fn get_all_notes(&self, id: SubwalletId) -> Result<Vec<ShieldedNote>, Self::Error>;

    /// Mark `id`'s note with `nullifier` as spent. Returns `true`
    /// if a matching unspent note was found.
    fn mark_spent(&mut self, id: SubwalletId, nullifier: &[u8; 32]) -> Result<bool, Self::Error>;

    /// Reserve `id`'s note with `nullifier` against an in-flight
    /// spend so concurrent callers can't pick the same note.
    /// Returns `true` if the nullifier was newly added to the
    /// pending set, `false` if it was already pending.
    ///
    /// Pending state is **in-memory only** — it does not survive
    /// a process restart. The crash-during-broadcast case is
    /// reconciled by the next note-scan pass after the transition
    /// lands (scan-based spend detection marks the spent note via
    /// its nullifier), or, on rejection, leaves the notes
    /// observable as unspent again on the next launch.
    ///
    /// `unspent_notes` skips notes whose nullifier is in the
    /// pending set, so a successful `mark_pending` immediately
    /// removes the note from selection candidates.
    fn mark_pending(&mut self, id: SubwalletId, nullifier: &[u8; 32]) -> Result<bool, Self::Error>;

    /// Release the reservation taken by [`Self::mark_pending`].
    /// Returns `true` if the nullifier was actually pending and
    /// got removed; `false` is a no-op (paired clear from the
    /// rollback path on a transition that never marked pending,
    /// or a stale clear after the spend already promoted to
    /// `mark_spent`).
    fn clear_pending(&mut self, id: SubwalletId, nullifier: &[u8; 32])
        -> Result<bool, Self::Error>;

    /// Attach the recorded `anchor` the spend was built against, and
    /// the linked `activity_id`, to `id`'s pending reservation for
    /// `nullifier` (taken earlier by [`Self::mark_pending`]). No-op
    /// if the nullifier is no longer pending. The sync reconcile uses
    /// the stored anchor to detect a stranded spend whose anchor
    /// Platform has pruned (see [`Self::stale_pending_spends`]).
    fn set_pending_spend(
        &mut self,
        id: SubwalletId,
        nullifier: &[u8; 32],
        anchor: [u8; 32],
        activity_id: [u8; 32],
    ) -> Result<(), Self::Error>;

    /// Pending reservations for `id` that carry a recorded anchor —
    /// `(nullifier, anchor, activity_id)` per built-but-unconfirmed
    /// spend. Empty when `id` has no anchored reservations (the common
    /// case, which lets the sync reconcile skip its network round-trip).
    /// The reconcile checks each anchor against Platform's recorded set
    /// and releases the reservation via [`Self::clear_pending`] when the
    /// anchor is pruned — the spend can then never execute.
    fn stale_pending_spends(&self, id: SubwalletId) -> Result<Vec<StalePendingSpend>, Self::Error>;

    // ── Re-drivable unconfirmed spends (per-subwallet) ─────────────────

    /// Persist a re-drivable record for a broadcast-accepted spend whose
    /// result wait failed ambiguously. Keyed by `redrive.activity_id`;
    /// re-arming the same id overwrites. Unlike the bare `mark_pending`
    /// reservations, redrive records survive a restart where the backend
    /// persists them (the file store does): on reopen both the record
    /// and its note reservations are rehydrated, so the re-drive — and
    /// the linked activity row's eventual Confirmed/Failed flip —
    /// continue across relaunches.
    fn arm_redrive(&mut self, id: SubwalletId, redrive: PendingRedrive) -> Result<(), Self::Error>;

    /// Every armed redrive record for `id`.
    fn pending_redrives(&self, id: SubwalletId) -> Result<Vec<PendingRedrive>, Self::Error>;

    /// Every armed redrive record for a wallet, paired with the subwallet
    /// that owns its durable row. Previously bound accounts remain visible
    /// here while they retain a wallet-wide identity-debit guard.
    fn pending_redrives_for_wallet(
        &self,
        wallet_id: WalletId,
    ) -> Result<Vec<(SubwalletId, PendingRedrive)>, Self::Error>;

    /// Increment the attempt counter on `id`'s redrive keyed by
    /// `activity_id`, returning the new count (`0` when no such record
    /// exists).
    fn bump_redrive_attempts(
        &mut self,
        id: SubwalletId,
        activity_id: &[u8; 32],
    ) -> Result<u32, Self::Error>;

    /// Drop the redrive record keyed by `activity_id` — the spend
    /// resolved (landed, definitively rejected, or released by the
    /// anchor-prune backstop). Implementations also drop the record
    /// implicitly when [`Self::mark_spent`] or [`Self::clear_pending`]
    /// resolves one of its nullifiers, since a transition lands or dies
    /// atomically for all of its nullifiers.
    fn clear_redrive(&mut self, id: SubwalletId, activity_id: &[u8; 32])
        -> Result<(), Self::Error>;

    // ── Spend dispositions ─────────────────────────────────────────────

    /// Resolve `id`'s note-spend redrive keyed by `activity_id` as one atomic
    /// step: record `disposition` under the redrive's
    /// [`st_hash`](PendingRedrive::st_hash), delete the redrive record, and
    /// release its note reservations. Returns the removed record.
    ///
    /// A reservation that another armed redrive also carries stays reserved
    /// for that redrive, which stays armed; `Executed` is then refused with
    /// [`ShieldedDispositionRefusal::ReservationShared`]. An identical
    /// unacknowledged disposition for the same `st_hash` in the wallet is
    /// kept as is; a different one is [`ShieldedDispositionRefusal::Conflict`].
    /// A missing record is [`ShieldedDispositionRefusal::RedriveNotFound`]
    /// and an identity-debit guard is
    /// [`ShieldedDispositionRefusal::IdentityDebit`].
    ///
    /// Resolution releases reservations but never marks notes spent. After
    /// resolving as `Executed`, mark the notes spent with
    /// [`Self::mark_spent`] under the same store guard, so the spend is
    /// reported as newly detected.
    ///
    /// Durable implementations commit every durable effect in one transaction
    /// before changing memory. On any error nothing changed: the record, its
    /// reservations and the stored dispositions are as they were.
    fn resolve_redrive(
        &mut self,
        id: SubwalletId,
        activity_id: &[u8; 32],
        disposition: ShieldedSpendDisposition,
    ) -> Result<PendingRedrive, Self::Error>;

    /// Record a disposition for a transition that has no armed redrive
    /// record, persisted before anything else changes. Returns `false` when an
    /// identical unacknowledged disposition already exists. Different
    /// evidence for the same `st_hash` anywhere in the wallet is
    /// [`ShieldedDispositionRefusal::Conflict`], and a redrive for `st_hash`
    /// or `activity_id` still armed in any of the wallet's accounts is
    /// [`ShieldedDispositionRefusal::RedriveArmed`]; nothing changes in
    /// either case.
    fn record_disposition(
        &mut self,
        id: SubwalletId,
        st_hash: &[u8; 32],
        activity_id: &[u8; 32],
        disposition: ShieldedSpendDisposition,
    ) -> Result<bool, Self::Error>;

    /// Every unacknowledged disposition for `wallet_id`, across all of its
    /// accounts, ordered by account index then `st_hash`. Purges leave
    /// dispositions in place, so this includes accounts that are no longer
    /// bound. A stored value this build cannot decode is an error, never
    /// skipped or defaulted.
    fn dispositions(
        &self,
        wallet_id: WalletId,
    ) -> Result<Vec<ShieldedSpendDispositionRecord>, Self::Error>;

    /// Remove exactly the disposition for `id` and `st_hash`, once the caller
    /// has durably settled it. Returns `false` if there was none.
    fn ack_disposition(&mut self, id: SubwalletId, st_hash: &[u8; 32])
        -> Result<bool, Self::Error>;

    // ── Outgoing history (per-subwallet) ───────────────────────────────

    /// Record an outgoing (sent) note recovered via OVK for `id`.
    ///
    /// Idempotent by `note.cmx`: re-recording a note already on file
    /// (a re-scan of the same chunk) is a no-op and returns `false`;
    /// a genuinely new outgoing note is stored and returns `true`.
    /// Outgoing notes are append-only send history — there is no
    /// "mark spent" / mutation path for them.
    fn record_outgoing_note(
        &mut self,
        id: SubwalletId,
        note: &ShieldedOutgoingNote,
    ) -> Result<bool, Self::Error>;

    /// Return every outgoing (sent) note recovered for `id`, in the
    /// order they were recorded.
    fn get_outgoing_notes(&self, id: SubwalletId)
        -> Result<Vec<ShieldedOutgoingNote>, Self::Error>;

    // ── Derived activity log (per-subwallet) ───────────────────────────

    /// Upsert a derived [`ShieldedActivityEntry`] for `id`, keyed by
    /// `entry.id` (the sha256 of the visible output cmxs — see
    /// [`crate::wallet::shielded::activity`]).
    ///
    /// Re-saving an entry with the same `entry.id` overwrites the
    /// existing one in place. This is what lets a coarse scan-derived
    /// `ShieldedSpend` be upgraded to a specific kind when a later live
    /// entry (or correlation pass) re-emits the same id, and what lets a
    /// `Pending` entry flip to `Confirmed`/`Failed`.
    fn save_activity(
        &mut self,
        id: SubwalletId,
        entry: &super::activity::ShieldedActivityEntry,
    ) -> Result<(), Self::Error>;

    /// Return a page of derived activity for `id`, sorted for display
    /// (pendings first, then by `block_height` desc, tiebreak by
    /// `created_at_ms` then `id`), sliced by `[offset, offset+limit)`.
    /// `limit == 0` returns an empty page.
    fn get_activity(
        &self,
        id: SubwalletId,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<super::activity::ShieldedActivityEntry>, Self::Error>;

    /// Look up a single activity entry by its `entry.id`. `None` if no
    /// entry with that id exists for `id`.
    fn get_activity_by_entry_id(
        &self,
        id: SubwalletId,
        entry_id: &[u8; 32],
    ) -> Result<Option<super::activity::ShieldedActivityEntry>, Self::Error>;

    /// Return the set of all entry ids already recorded for `id`. Used by
    /// the scan deriver to skip clusters a live entry already owns.
    fn get_activity_ids(&self, id: SubwalletId) -> Result<BTreeSet<[u8; 32]>, Self::Error>;

    // ── Commitment tree (network-shared) ───────────────────────────────

    /// Append a note commitment to the shared tree.
    ///
    /// `marked` controls whether shardtree retains the
    /// authentication path for this position (Marked) or prunes it
    /// (Ephemeral). The sync path passes `true` for **every**
    /// position: the tree is a chain-wide structure shared by all
    /// wallets, and wallets bind at different times, so deciding
    /// retention from "is this position owned right now" loses the
    /// ability to witness a note whose owner binds later
    /// (shardtree can't retroactively mark). Per-wallet ownership
    /// is tracked separately in the per-`SubwalletId` note store.
    /// The `marked` parameter is kept for store-level flexibility
    /// and tests.
    fn append_commitment(&mut self, cmx: &[u8; 32], marked: bool) -> Result<(), Self::Error>;

    /// Create a tree checkpoint at the given identifier.
    fn checkpoint_tree(&mut self, checkpoint_id: u32) -> Result<(), Self::Error>;

    /// Return the current tree root (Sinsemilla anchor, 32 bytes).
    fn tree_anchor(&self) -> Result<[u8; 32], Self::Error>;

    /// Generate a Merkle authentication path for `position` as of the
    /// checkpoint at `depth` (0 = current tree state, 1 = the previous
    /// checkpoint, and so on). Returns `Ok(None)` when no witness is
    /// available at that depth — the position is unmarked/pruned, the
    /// requested checkpoint depth doesn't exist, or the position was
    /// appended after that checkpoint.
    ///
    /// Building a spend against an older-but-recorded checkpoint is how the
    /// wallet keeps its anchor consistent with a root Platform actually
    /// recorded: Platform records one anchor per block while an index-chunk
    /// sync routinely leaves the tree mid-block, so the depth-0 root is often
    /// one Platform never recorded.
    fn witness_at_depth(
        &self,
        position: u64,
        depth: usize,
    ) -> Result<Option<grovedb_commitment_tree::MerklePath>, Self::Error>;

    /// Generate a Merkle authentication path for `position` against the
    /// current tree state. Returns `Ok(None)` if no witness is available
    /// (position not marked, or pruned).
    ///
    /// Delegates to [`Self::witness_at_depth`] at depth 0.
    fn witness(
        &self,
        position: u64,
    ) -> Result<Option<grovedb_commitment_tree::MerklePath>, Self::Error> {
        self.witness_at_depth(position, 0)
    }

    /// Number of leaves currently in the shared commitment tree
    /// (= highest appended position + 1, or 0 when empty).
    ///
    /// This is the append watermark for the tree itself, distinct
    /// from any per-subwallet `last_synced_note_index`. The sync
    /// path gates [`Self::append_commitment`] on this value — never
    /// on a per-subwallet watermark — so a re-fetch from a chunk
    /// boundary (forced when a lagging subwallet rewinds the fetch
    /// start) re-appends nothing already in the tree. Double-append
    /// corrupts the shardtree's internal nodes and makes per-position
    /// witnesses resolve against inconsistent roots ("Anchor not
    /// found in the recorded anchors tree" at spend time).
    fn tree_size(&self) -> Result<u64, Self::Error>;

    // ── Sync state (per-subwallet) ─────────────────────────────────────

    /// Sync watermark for `id`: the count of note positions already
    /// scanned, i.e. the next global commitment-tree index to scan.
    /// `0` means nothing scanned yet; `N` means positions `0..N` are
    /// done. Exclusive upper bound — *not* the last index scanned
    /// (scanning through position `N-1` sets this to `N`).
    fn last_synced_note_index(&self, id: SubwalletId) -> Result<u64, Self::Error>;

    /// Persist the sync watermark (next index to scan) for `id`.
    fn set_last_synced_note_index(
        &mut self,
        id: SubwalletId,
        index: u64,
    ) -> Result<(), Self::Error>;

    // ── Per-subwallet lifecycle ────────────────────────────────────────

    /// Drop ALL in-memory per-subwallet state (decrypted notes,
    /// spent marks, `last_synced_note_index`, nullifier
    /// checkpoints, pending reservations) for every subwallet
    /// belonging to `wallet_id`. The shared commitment tree is
    /// left untouched — it's a chain-wide structure, not
    /// per-wallet. Used when a wallet is removed or its shielded
    /// binding is cleared so a later re-bind resyncs from index 0
    /// rather than resuming behind the stale watermark.
    fn purge_wallet(&mut self, wallet_id: WalletId) -> Result<(), Self::Error>;

    /// Drop the account-scoped state and nullifier-backed redrives for exactly
    /// one subwallet, leaving every other subwallet and the shared commitment
    /// tree intact. Empty-nullifier identity-debit guards are wallet-wide and
    /// survive until authenticated resolution or an explicit wallet purge.
    ///
    /// The account-scoped sibling of [`Self::purge_wallet`]. Used by
    /// the coordinator when a re-bind changes a wallet's account set:
    /// only the accounts that were dropped (or whose viewing key
    /// changed — their stored notes belong to the old key) are
    /// purged, so the accounts that remain bound keep their fresh
    /// in-memory notes and watermarks across the re-bind.
    fn purge_subwallet(&mut self, id: SubwalletId) -> Result<(), Self::Error>;

    /// Drop ALL in-memory per-subwallet state for every subwallet
    /// of every wallet. The shared commitment tree is left
    /// untouched. Used by `NetworkShieldedCoordinator::clear()`.
    fn purge_all_subwallets(&mut self) -> Result<(), Self::Error>;

    /// Empty the shared commitment tree back to zero leaves.
    ///
    /// After this returns, [`Self::tree_size`] reports `0` and the
    /// next [`Self::append_commitment`] starts at position `0`. The
    /// per-subwallet watermarks ([`Self::last_synced_note_index`])
    /// are *not* touched here — callers that want a cold rebuild
    /// pair this with [`Self::purge_all_subwallets`] so the
    /// re-download watermark and the tree reset together.
    ///
    /// Used by `NetworkShieldedCoordinator::clear()` so the host's
    /// "Clear" action is a true cold reset rather than a watermark
    /// rewind into an already-full tree. Without it, Clear leaves
    /// the tree at its full size while the watermark drops to 0, so
    /// every re-fetched position is gate-skipped (`global_pos <
    /// tree_size`) and the "Checked" progress bar stays pinned at
    /// the stale leaf count while "Downloaded" climbs from 0.
    fn reset_commitment_tree(&mut self) -> Result<(), Self::Error>;
}

// ── Per-subwallet bookkeeping ──────────────────────────────────────────

/// In-flight-spend bookkeeping for a single reserved nullifier.
///
/// A reservation starts life bare (both fields `None`) the moment
/// [`SubwalletState::mark_pending`] excludes the note from selection.
/// Once the spend is actually built, [`SubwalletState::set_pending_spend`]
/// records the Platform-**recorded** anchor it was built against and the
/// linked activity-log entry, so the sync reconcile can later detect a
/// stranded (broadcast-accepted-but-never-landed) spend: once that anchor
/// is pruned from Platform's recorded set the spend can never execute, and
/// with the nullifier still unspent the reservation is provably dead and
/// its note can be freed. All in-memory only — a restart drops every
/// reservation regardless.
#[derive(Debug, Clone, Default)]
pub(super) struct PendingSpend {
    /// The recorded anchor the spend was built against, once known.
    /// `None` while the note is reserved but the spend isn't built yet.
    pub anchor: Option<[u8; 32]>,
    /// The linked activity-log entry id, so a released reservation can
    /// flip its "Pending" row to "Failed" instead of stranding it.
    pub activity_id: Option<[u8; 32]>,
}

/// Per-subwallet note + sync state used by both the in-memory and
/// file-backed stores. Kept in this module so both share the
/// exact same shape and the persister callback can serialize it
/// without re-defining the structure on the host side.
#[derive(Debug, Default, Clone)]
pub(super) struct SubwalletState {
    /// All known notes (spent + unspent), in insertion order.
    pub notes: Vec<ShieldedNote>,
    /// Nullifier → index into `notes`, for O(1) `mark_spent`.
    pub nullifier_index: BTreeMap<[u8; 32], usize>,
    /// Sync watermark: count of note positions scanned = the next
    /// global index to scan (exclusive). `0` = nothing scanned yet.
    pub last_synced_index: u64,
    /// Session-only provenance; durable watermarks are still ordinary u64 rows.
    pub last_scanned_index: Option<u64>,
    pub balance_source: ShieldedBalanceSource,
    /// Nullifiers of notes currently being spent in an in-flight
    /// transition, mapped to the [`PendingSpend`] bookkeeping the
    /// sync reconcile needs. Excluded from `unspent_notes()` so
    /// concurrent callers can't double-select. Held in memory; a
    /// pre-broadcast reservation dies with the process, but a
    /// reservation belonging to an armed [`PendingRedrive`] is
    /// rehydrated on file-store open (the redrive row carries its
    /// nullifiers), so an unconfirmed broadcast keeps its notes
    /// reserved across restarts.
    pub pending_nullifiers: BTreeMap<[u8; 32], PendingSpend>,
    /// Armed re-drivable unconfirmed spends, keyed by activity id.
    /// See [`PendingRedrive`]. Kept consistent with
    /// `pending_nullifiers`: resolving any of a redrive's nullifiers
    /// (mark_spent / clear_pending) drops the whole record — a
    /// transition lands or dies atomically for all its nullifiers.
    pub redrives: BTreeMap<[u8; 32], PendingRedrive>,
    /// Notes this subwallet SENT, recovered via OVK during the scan.
    /// Append-only send history in recording order.
    pub outgoing_notes: Vec<ShieldedOutgoingNote>,
    /// `cmx` set of recorded outgoing notes, for O(log n) idempotency
    /// on `record_outgoing_note` (Orchard cmx is globally unique).
    pub outgoing_cmx_index: BTreeSet<[u8; 32]>,
    /// Derived activity entries keyed by `entry.id` (sha256 of the
    /// visible output cmxs). Upsert-by-id: a later live entry or a
    /// correlation pass that re-emits the same id overwrites the row.
    pub activity: BTreeMap<[u8; 32], super::activity::ShieldedActivityEntry>,
}

impl SubwalletState {
    /// Save (or overwrite-by-nullifier) a note.
    ///
    /// Re-saving a note with a known nullifier overwrites the
    /// existing entry instead of appending a duplicate — Orchard
    /// nullifiers are globally unique, so a re-scan of the same
    /// chunk shouldn't double-count.
    pub(super) fn save_note(&mut self, note: &ShieldedNote) {
        if let Some(&existing_idx) = self.nullifier_index.get(&note.nullifier) {
            self.notes[existing_idx] = note.clone();
            return;
        }
        let idx = self.notes.len();
        self.nullifier_index.insert(note.nullifier, idx);
        self.notes.push(note.clone());
    }

    /// Borrow the selectable notes so balance reads do not clone note payloads.
    fn unspent_notes_iter(&self) -> impl Iterator<Item = &ShieldedNote> {
        self.notes
            .iter()
            .filter(|note| !note.is_spent && !self.pending_nullifiers.contains_key(&note.nullifier))
    }

    pub(super) fn unspent_notes(&self) -> Vec<ShieldedNote> {
        self.unspent_notes_iter().cloned().collect()
    }

    /// Both stores use the same borrowed, reservation-aware checked sum.
    /// Each caller maps overflow into its own storage error.
    pub(super) fn spendable_balance(&self) -> Option<u64> {
        self.unspent_notes_iter()
            .try_fold(0u64, |total, note| total.checked_add(note.value))
    }

    pub(super) fn all_notes(&self) -> Vec<ShieldedNote> {
        self.notes.clone()
    }

    pub(super) fn mark_spent(&mut self, nullifier: &[u8; 32]) -> MarkSpentOutcome {
        let Some(&idx) = self.nullifier_index.get(nullifier) else {
            return MarkSpentOutcome::default();
        };
        let newly_spent = !self.notes[idx].is_spent;
        self.notes[idx].is_spent = true;
        // Resolve the reservation + redrive record whenever the
        // nullifier is KNOWN, not only on the first unspent→spent
        // transition. A note restored from disk already `is_spent`
        // (its owning transition landed in a prior session) paired with
        // a rehydrated redrive row would otherwise keep a ghost
        // reservation alive and re-broadcast a transition that already
        // executed. Removing a pending reservation on a spent note is
        // always safe — a spent note can't be re-spent. `dropped` is
        // returned so the durable store can mirror the deletion even
        // when `newly_spent` is false (the in-memory drop still
        // happened here).
        self.pending_nullifiers.remove(nullifier);
        let dropped = self.drop_redrives_containing(nullifier);
        MarkSpentOutcome {
            newly_spent,
            dropped_redrives: dropped,
        }
    }

    /// Drop every redrive record that carries `nullifier`, returning
    /// the dropped activity ids (the file store mirrors the deletions
    /// to SQLite). A transition lands or dies atomically for all of
    /// its nullifiers, so resolving one resolves the record.
    pub(super) fn drop_redrives_containing(&mut self, nullifier: &[u8; 32]) -> Vec<[u8; 32]> {
        let dropped: Vec<[u8; 32]> = self
            .redrives
            .iter()
            .filter(|(_, r)| r.nullifiers.contains(nullifier))
            .map(|(id, _)| *id)
            .collect();
        for id in &dropped {
            self.redrives.remove(id);
        }
        dropped
    }

    /// Reserve `nullifier` against an in-flight spend. Returns
    /// `true` if newly added, `false` if it was already reserved.
    /// Re-reserving is a true no-op: an already-armed entry keeps its
    /// anchor/activity link (selection excludes pending nullifiers, so
    /// this shouldn't happen — but a plain `insert` would silently
    /// wipe the release pass's only handle on a stranded spend if it
    /// ever did).
    pub(super) fn mark_pending(&mut self, nullifier: &[u8; 32]) -> bool {
        match self.pending_nullifiers.entry(*nullifier) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(PendingSpend::default());
                true
            }
            std::collections::btree_map::Entry::Occupied(_) => false,
        }
    }

    /// Attach the built spend's recorded `anchor` and linked
    /// `activity_id` to an existing reservation for `nullifier`.
    /// No-op if the nullifier is no longer pending (e.g. the
    /// reservation was already cleared by a concurrent finalize).
    pub(super) fn set_pending_spend(
        &mut self,
        nullifier: &[u8; 32],
        anchor: [u8; 32],
        activity_id: [u8; 32],
    ) {
        if let Some(pending) = self.pending_nullifiers.get_mut(nullifier) {
            pending.anchor = Some(anchor);
            pending.activity_id = Some(activity_id);
        }
    }

    /// Reservations that carry a recorded anchor — i.e. built,
    /// broadcast-but-unconfirmed spends. Returns `(nullifier,
    /// anchor, activity_id)` per such entry; reservations still
    /// awaiting a built spend (`anchor: None`) are skipped. The
    /// sync reconcile checks each anchor against Platform's recorded
    /// set and releases the reservation when the anchor is pruned.
    pub(super) fn stale_pending_spends(&self) -> Vec<StalePendingSpend> {
        self.pending_nullifiers
            .iter()
            .filter_map(|(nullifier, spend)| {
                spend
                    .anchor
                    .map(|anchor| (*nullifier, anchor, spend.activity_id))
            })
            .collect()
    }

    /// Release a reservation previously taken via `mark_pending`.
    /// Returns `true` if a matching reservation was actually
    /// removed.
    pub(super) fn clear_pending(&mut self, nullifier: &[u8; 32]) -> bool {
        let removed = self.pending_nullifiers.remove(nullifier).is_some();
        if removed {
            // Releasing a reservation resolves its spend for good
            // (definitive rejection or prune backstop) — the redrive
            // record goes with it.
            self.drop_redrives_containing(nullifier);
        }
        removed
    }

    /// Arm (or overwrite by activity id) a re-drivable record.
    pub(super) fn arm_redrive(&mut self, redrive: PendingRedrive) {
        self.redrives.insert(redrive.activity_id, redrive);
    }

    pub(super) fn pending_redrives(&self) -> Vec<PendingRedrive> {
        self.redrives.values().cloned().collect()
    }

    pub(super) fn identity_redrives(&self) -> Vec<PendingRedrive> {
        self.redrives
            .values()
            .filter(|redrive| redrive.nullifiers.is_empty())
            .cloned()
            .collect()
    }

    /// Current attempt count for `activity_id`'s redrive, if armed.
    pub(super) fn redrive_attempts(&self, activity_id: &[u8; 32]) -> Option<u32> {
        self.redrives.get(activity_id).map(|r| r.attempts)
    }

    /// Bump the attempt counter; `0` when no such record exists.
    pub(super) fn bump_redrive_attempts(&mut self, activity_id: &[u8; 32]) -> u32 {
        self.redrives
            .get_mut(activity_id)
            .map(|r| {
                r.attempts = r.attempts.saturating_add(1);
                r.attempts
            })
            .unwrap_or(0)
    }

    pub(super) fn clear_redrive(&mut self, activity_id: &[u8; 32]) {
        self.redrives.remove(activity_id);
    }

    /// The armed note-spend redrive `resolve_redrive` may resolve as
    /// `disposition`. Identity debits carry no input nullifiers and are
    /// refused, and `Executed` is refused while another armed redrive
    /// reserves one of the same notes.
    pub(super) fn redrive_to_resolve(
        &self,
        activity_id: &[u8; 32],
        disposition: ShieldedSpendDisposition,
    ) -> Result<&PendingRedrive, ShieldedDispositionRefusal> {
        let redrive =
            self.redrives
                .get(activity_id)
                .ok_or(ShieldedDispositionRefusal::RedriveNotFound {
                    activity_id: *activity_id,
                })?;
        if redrive.nullifiers.is_empty() {
            return Err(ShieldedDispositionRefusal::IdentityDebit {
                activity_id: *activity_id,
            });
        }
        if disposition == ShieldedSpendDisposition::Executed {
            if let Some(other) = self.redrives.values().find(|other| {
                other.activity_id != *activity_id
                    && other
                        .nullifiers
                        .iter()
                        .any(|nullifier| redrive.nullifiers.contains(nullifier))
            }) {
                return Err(ShieldedDispositionRefusal::ReservationShared {
                    activity_id: *activity_id,
                    other_activity_id: other.activity_id,
                });
            }
        }
        Ok(redrive)
    }

    /// Refuse a standalone disposition while a redrive for the same
    /// transition or activity is still armed.
    pub(super) fn ensure_no_armed_redrive(
        &self,
        st_hash: &[u8; 32],
        activity_id: &[u8; 32],
    ) -> Result<(), ShieldedDispositionRefusal> {
        match self
            .redrives
            .values()
            .find(|redrive| redrive.activity_id == *activity_id || redrive.st_hash() == *st_hash)
        {
            Some(redrive) => Err(ShieldedDispositionRefusal::RedriveArmed {
                activity_id: redrive.activity_id,
            }),
            None => Ok(()),
        }
    }

    /// Remove the redrive keyed by `activity_id` and release each of its
    /// reservations that no remaining armed redrive carries. A reservation
    /// another redrive still carries is repointed to that redrive's anchor
    /// and activity, so the prune backstop judges it by the survivor.
    pub(super) fn remove_redrive_and_release(
        &mut self,
        activity_id: &[u8; 32],
    ) -> Option<PendingRedrive> {
        let redrive = self.redrives.remove(activity_id)?;
        for nullifier in &redrive.nullifiers {
            match self
                .redrives
                .values()
                .find(|other| other.nullifiers.contains(nullifier))
            {
                Some(other) => {
                    if let Some(pending) = self.pending_nullifiers.get_mut(nullifier) {
                        pending.anchor = Some(other.anchor);
                        pending.activity_id = Some(other.activity_id);
                    }
                }
                None => {
                    self.pending_nullifiers.remove(nullifier);
                }
            }
        }
        Some(redrive)
    }

    /// Record an outgoing (sent) note. Idempotent by `cmx`: returns
    /// `true` if newly recorded, `false` if a note with that `cmx`
    /// was already present.
    pub(super) fn record_outgoing_note(&mut self, note: &ShieldedOutgoingNote) -> bool {
        if !self.outgoing_cmx_index.insert(note.cmx) {
            return false;
        }
        self.outgoing_notes.push(note.clone());
        true
    }

    pub(super) fn outgoing_notes(&self) -> Vec<ShieldedOutgoingNote> {
        self.outgoing_notes.clone()
    }

    /// Upsert a derived activity entry by `entry.id`.
    pub(super) fn save_activity(&mut self, entry: &super::activity::ShieldedActivityEntry) {
        self.activity.insert(entry.id, entry.clone());
    }

    /// Display-sorted page of activity entries.
    pub(super) fn activity_page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Vec<super::activity::ShieldedActivityEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let mut all: Vec<super::activity::ShieldedActivityEntry> =
            self.activity.values().cloned().collect();
        super::activity::sort_activity_for_display(&mut all);
        all.into_iter().skip(offset).take(limit).collect()
    }

    pub(super) fn activity_by_id(
        &self,
        entry_id: &[u8; 32],
    ) -> Option<super::activity::ShieldedActivityEntry> {
        self.activity.get(entry_id).cloned()
    }

    pub(super) fn activity_ids(&self) -> BTreeSet<[u8; 32]> {
        self.activity.keys().copied().collect()
    }
}

// ── InMemoryShieldedStore ──────────────────────────────────────────────

/// Error type for the in-memory store: a message, or a typed disposition
/// refusal.
#[derive(Debug, Clone)]
pub struct InMemoryStoreError {
    message: String,
    refusal: Option<ShieldedDispositionRefusal>,
}

impl InMemoryStoreError {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            refusal: None,
        }
    }
}

impl AsDispositionRefusal for InMemoryStoreError {
    fn disposition_refusal(&self) -> Option<&ShieldedDispositionRefusal> {
        self.refusal.as_ref()
    }
}

impl From<ShieldedDispositionRefusal> for InMemoryStoreError {
    fn from(refusal: ShieldedDispositionRefusal) -> Self {
        Self {
            message: refusal.to_string(),
            refusal: Some(refusal),
        }
    }
}

impl fmt::Display for InMemoryStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for InMemoryStoreError {}

/// In-memory implementation of [`ShieldedStore`] for tests and
/// short-lived wallets. Notes are kept per [`SubwalletId`]; the
/// commitment tree is a flat list (anchor is a placeholder, so
/// real witness generation is **not** supported — use a real
/// store for spends).
#[derive(Debug, Default)]
pub struct InMemoryShieldedStore {
    /// Per-subwallet notes + sync state.
    subwallets: BTreeMap<SubwalletId, SubwalletState>,
    /// Flat list of commitments appended to the tree.
    commitments: Vec<[u8; 32]>,
    /// Mark flag per position.
    marked_positions: Vec<bool>,
    /// Checkpoint ids in order.
    checkpoints: Vec<u32>,
    /// Placeholder anchor; production stores compute the real Sinsemilla root.
    anchor: [u8; 32],
    /// Unacknowledged spend dispositions. Held outside `subwallets` so purges
    /// leave them in place.
    dispositions: BTreeMap<(SubwalletId, [u8; 32]), ShieldedSpendDispositionRecord>,
}

impl InMemoryShieldedStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

/// The unacknowledged disposition for `st_hash` in any of the wallet's
/// accounts.
fn wallet_disposition<'a>(
    dispositions: &'a BTreeMap<(SubwalletId, [u8; 32]), ShieldedSpendDispositionRecord>,
    wallet_id: WalletId,
    st_hash: &[u8; 32],
) -> Option<&'a ShieldedSpendDispositionRecord> {
    dispositions
        .values()
        .find(|record| record.subwallet.wallet_id == wallet_id && record.st_hash == *st_hash)
}

impl ShieldedStore for InMemoryShieldedStore {
    type Error = InMemoryStoreError;

    fn save_note(&mut self, id: SubwalletId, note: &ShieldedNote) -> Result<(), Self::Error> {
        self.subwallets.entry(id).or_default().save_note(note);
        Ok(())
    }

    fn get_unspent_notes(&self, id: SubwalletId) -> Result<Vec<ShieldedNote>, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .map(SubwalletState::unspent_notes)
            .unwrap_or_default())
    }

    fn spendable_balance(&self, id: SubwalletId) -> Result<u64, Self::Error> {
        self.subwallets
            .get(&id)
            .map_or(Some(0), SubwalletState::spendable_balance)
            .ok_or_else(|| InMemoryStoreError::message("spendable shielded balance exceeds u64"))
    }

    fn get_all_notes(&self, id: SubwalletId) -> Result<Vec<ShieldedNote>, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .map(SubwalletState::all_notes)
            .unwrap_or_default())
    }

    fn mark_spent(&mut self, id: SubwalletId, nullifier: &[u8; 32]) -> Result<bool, Self::Error> {
        // In-memory store: the redrive map lives in the same
        // `SubwalletState`, so `mark_spent` already dropped any resolved
        // redrives — nothing durable to mirror. Surface `newly_spent`.
        Ok(self
            .subwallets
            .get_mut(&id)
            .map(|sw| sw.mark_spent(nullifier).newly_spent)
            .unwrap_or(false))
    }

    fn mark_pending(&mut self, id: SubwalletId, nullifier: &[u8; 32]) -> Result<bool, Self::Error> {
        Ok(self
            .subwallets
            .entry(id)
            .or_default()
            .mark_pending(nullifier))
    }

    fn clear_pending(
        &mut self,
        id: SubwalletId,
        nullifier: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        Ok(self
            .subwallets
            .get_mut(&id)
            .map(|sw| sw.clear_pending(nullifier))
            .unwrap_or(false))
    }

    fn set_pending_spend(
        &mut self,
        id: SubwalletId,
        nullifier: &[u8; 32],
        anchor: [u8; 32],
        activity_id: [u8; 32],
    ) -> Result<(), Self::Error> {
        if let Some(sw) = self.subwallets.get_mut(&id) {
            sw.set_pending_spend(nullifier, anchor, activity_id);
        }
        Ok(())
    }

    fn stale_pending_spends(&self, id: SubwalletId) -> Result<Vec<StalePendingSpend>, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .map(SubwalletState::stale_pending_spends)
            .unwrap_or_default())
    }

    fn arm_redrive(&mut self, id: SubwalletId, redrive: PendingRedrive) -> Result<(), Self::Error> {
        self.subwallets.entry(id).or_default().arm_redrive(redrive);
        Ok(())
    }

    fn pending_redrives(&self, id: SubwalletId) -> Result<Vec<PendingRedrive>, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .map(SubwalletState::pending_redrives)
            .unwrap_or_default())
    }

    fn pending_redrives_for_wallet(
        &self,
        wallet_id: WalletId,
    ) -> Result<Vec<(SubwalletId, PendingRedrive)>, Self::Error> {
        Ok(self
            .subwallets
            .iter()
            .filter(|(id, _)| id.wallet_id == wallet_id)
            .flat_map(|(id, subwallet)| {
                subwallet
                    .pending_redrives()
                    .into_iter()
                    .map(|redrive| (*id, redrive))
            })
            .collect())
    }

    fn bump_redrive_attempts(
        &mut self,
        id: SubwalletId,
        activity_id: &[u8; 32],
    ) -> Result<u32, Self::Error> {
        Ok(self
            .subwallets
            .get_mut(&id)
            .map(|sw| sw.bump_redrive_attempts(activity_id))
            .unwrap_or(0))
    }

    fn clear_redrive(
        &mut self,
        id: SubwalletId,
        activity_id: &[u8; 32],
    ) -> Result<(), Self::Error> {
        if let Some(sw) = self.subwallets.get_mut(&id) {
            sw.clear_redrive(activity_id);
        }
        Ok(())
    }

    fn resolve_redrive(
        &mut self,
        id: SubwalletId,
        activity_id: &[u8; 32],
        disposition: ShieldedSpendDisposition,
    ) -> Result<PendingRedrive, Self::Error> {
        let sw =
            self.subwallets
                .get_mut(&id)
                .ok_or(ShieldedDispositionRefusal::RedriveNotFound {
                    activity_id: *activity_id,
                })?;
        let st_hash = sw.redrive_to_resolve(activity_id, disposition)?.st_hash();
        let record = disposition_to_write(
            wallet_disposition(&self.dispositions, id.wallet_id, &st_hash),
            id,
            &st_hash,
            activity_id,
            disposition,
        )?;
        let redrive = sw.remove_redrive_and_release(activity_id).ok_or(
            ShieldedDispositionRefusal::RedriveNotFound {
                activity_id: *activity_id,
            },
        )?;
        if let Some(record) = record {
            self.dispositions.insert((id, st_hash), record);
        }
        Ok(redrive)
    }

    fn record_disposition(
        &mut self,
        id: SubwalletId,
        st_hash: &[u8; 32],
        activity_id: &[u8; 32],
        disposition: ShieldedSpendDisposition,
    ) -> Result<bool, Self::Error> {
        for (_, sw) in self
            .subwallets
            .iter()
            .filter(|(subwallet, _)| subwallet.wallet_id == id.wallet_id)
        {
            sw.ensure_no_armed_redrive(st_hash, activity_id)?;
        }
        let Some(record) = disposition_to_write(
            wallet_disposition(&self.dispositions, id.wallet_id, st_hash),
            id,
            st_hash,
            activity_id,
            disposition,
        )?
        else {
            return Ok(false);
        };
        self.dispositions.insert((id, *st_hash), record);
        Ok(true)
    }

    fn dispositions(
        &self,
        wallet_id: WalletId,
    ) -> Result<Vec<ShieldedSpendDispositionRecord>, Self::Error> {
        Ok(self
            .dispositions
            .values()
            .filter(|record| record.subwallet.wallet_id == wallet_id)
            .cloned()
            .collect())
    }

    fn ack_disposition(
        &mut self,
        id: SubwalletId,
        st_hash: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        Ok(self.dispositions.remove(&(id, *st_hash)).is_some())
    }

    fn record_outgoing_note(
        &mut self,
        id: SubwalletId,
        note: &ShieldedOutgoingNote,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .subwallets
            .entry(id)
            .or_default()
            .record_outgoing_note(note))
    }

    fn get_outgoing_notes(
        &self,
        id: SubwalletId,
    ) -> Result<Vec<ShieldedOutgoingNote>, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .map(SubwalletState::outgoing_notes)
            .unwrap_or_default())
    }

    fn save_activity(
        &mut self,
        id: SubwalletId,
        entry: &super::activity::ShieldedActivityEntry,
    ) -> Result<(), Self::Error> {
        self.subwallets.entry(id).or_default().save_activity(entry);
        Ok(())
    }

    fn get_activity(
        &self,
        id: SubwalletId,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<super::activity::ShieldedActivityEntry>, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .map(|sw| sw.activity_page(offset, limit))
            .unwrap_or_default())
    }

    fn get_activity_by_entry_id(
        &self,
        id: SubwalletId,
        entry_id: &[u8; 32],
    ) -> Result<Option<super::activity::ShieldedActivityEntry>, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .and_then(|sw| sw.activity_by_id(entry_id)))
    }

    fn get_activity_ids(&self, id: SubwalletId) -> Result<BTreeSet<[u8; 32]>, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .map(SubwalletState::activity_ids)
            .unwrap_or_default())
    }

    fn append_commitment(&mut self, cmx: &[u8; 32], marked: bool) -> Result<(), Self::Error> {
        self.commitments.push(*cmx);
        self.marked_positions.push(marked);
        Ok(())
    }

    fn checkpoint_tree(&mut self, checkpoint_id: u32) -> Result<(), Self::Error> {
        self.checkpoints.push(checkpoint_id);
        Ok(())
    }

    fn tree_anchor(&self) -> Result<[u8; 32], Self::Error> {
        Ok(self.anchor)
    }

    fn witness_at_depth(
        &self,
        _position: u64,
        _depth: usize,
    ) -> Result<Option<grovedb_commitment_tree::MerklePath>, Self::Error> {
        Err(InMemoryStoreError::message(
            "Merkle witness not supported in in-memory store",
        ))
    }

    fn tree_size(&self) -> Result<u64, Self::Error> {
        Ok(self.commitments.len() as u64)
    }

    fn last_synced_note_index(&self, id: SubwalletId) -> Result<u64, Self::Error> {
        Ok(self
            .subwallets
            .get(&id)
            .map(|sw| sw.last_synced_index)
            .unwrap_or(0))
    }

    fn set_last_synced_note_index(
        &mut self,
        id: SubwalletId,
        index: u64,
    ) -> Result<(), Self::Error> {
        let state = self.subwallets.entry(id).or_default();
        state.last_synced_index = index;
        state.last_scanned_index = Some(index);
        state.balance_source = ShieldedBalanceSource::ScannedThisSession;
        Ok(())
    }

    fn purge_wallet(&mut self, wallet_id: WalletId) -> Result<(), Self::Error> {
        self.subwallets.retain(|id, _| id.wallet_id != wallet_id);
        Ok(())
    }

    fn purge_subwallet(&mut self, id: SubwalletId) -> Result<(), Self::Error> {
        let identity_redrives = self
            .subwallets
            .get(&id)
            .map(SubwalletState::identity_redrives)
            .unwrap_or_default();
        self.subwallets.remove(&id);
        if !identity_redrives.is_empty() {
            let retained = self.subwallets.entry(id).or_default();
            for redrive in identity_redrives {
                retained.arm_redrive(redrive);
            }
        }
        Ok(())
    }

    fn purge_all_subwallets(&mut self) -> Result<(), Self::Error> {
        self.subwallets.clear();
        Ok(())
    }

    fn reset_commitment_tree(&mut self) -> Result<(), Self::Error> {
        // Flat-list backing: clearing the commitment / mark /
        // checkpoint vectors drops `tree_size()` to 0 and makes the
        // next append start at position 0, matching the file-backed
        // store's reset contract.
        self.commitments.clear();
        self.marked_positions.clear();
        self.checkpoints.clear();
        self.anchor = [0u8; 32];
        Ok(())
    }
}

/// Disposition behaviour every [`ShieldedStore`] must show, run against each
/// implementation by its own tests. Each check returns the wallets it used so
/// a durable store can compare them across a reopen.
#[cfg(test)]
pub(super) mod disposition_contract {
    use super::*;

    pub(crate) fn note(nullifier: [u8; 32]) -> ShieldedNote {
        ShieldedNote {
            position: u64::from(nullifier[0]),
            cmx: nullifier,
            nullifier,
            block_height: 1,
            is_spent: false,
            value: 1_000,
            note_data: vec![0u8; 115],
        }
    }

    /// A note-spend record whose bytes, and so its `st_hash`, are unique per `tag`.
    pub(crate) fn spend(tag: u8, nullifiers: &[[u8; 32]]) -> PendingRedrive {
        PendingRedrive {
            activity_id: [tag; 32],
            anchor: [0x5A; 32],
            nullifiers: nullifiers.to_vec(),
            st_bytes: vec![tag; 48],
            attempts: 0,
            identity_nonce_finalized: false,
            identity_user_abandoned: false,
        }
    }

    /// Reserve the record's notes the way a spend does, then arm it.
    pub(crate) fn arm_reserved<S: ShieldedStore>(
        store: &mut S,
        id: SubwalletId,
        redrive: &PendingRedrive,
    ) {
        for nullifier in &redrive.nullifiers {
            store.save_note(id, &note(*nullifier)).unwrap();
            store.mark_pending(id, nullifier).unwrap();
            store
                .set_pending_spend(id, nullifier, redrive.anchor, redrive.activity_id)
                .unwrap();
        }
        store.arm_redrive(id, redrive.clone()).unwrap();
    }

    pub(crate) fn unspent<S: ShieldedStore>(store: &S, id: SubwalletId) -> BTreeSet<[u8; 32]> {
        store
            .get_unspent_notes(id)
            .unwrap()
            .into_iter()
            .map(|note| note.nullifier)
            .collect()
    }

    /// The typed refusal, read through [`AsDispositionRefusal`] as generic
    /// callers would.
    fn refusal<T: fmt::Debug, E: StdError + AsDispositionRefusal>(
        result: Result<T, E>,
    ) -> ShieldedDispositionRefusal {
        let error = result.expect_err("the store must refuse");
        error
            .disposition_refusal()
            .cloned()
            .unwrap_or_else(|| panic!("expected a typed refusal, got {error}"))
    }

    pub(crate) fn resolve_records_removes_and_releases<S: ShieldedStore>(
        store: &mut S,
    ) -> Vec<WalletId> {
        let id = SubwalletId::new([0xC1; 32], 3);
        let redrive = spend(0x11, &[[0xA1; 32], [0xA2; 32]]);
        arm_reserved(store, id, &redrive);
        assert!(unspent(store, id).is_empty());

        let removed = store
            .resolve_redrive(id, &redrive.activity_id, ShieldedSpendDisposition::Executed)
            .expect("resolve");

        assert_eq!(removed, redrive);
        assert!(store.pending_redrives(id).unwrap().is_empty());
        assert_eq!(
            unspent(store, id),
            BTreeSet::from([[0xA1; 32], [0xA2; 32]]),
            "resolution releases every reservation of the record"
        );
        assert!(store.stale_pending_spends(id).unwrap().is_empty());
        let dispositions = store.dispositions(id.wallet_id).unwrap();
        assert_eq!(dispositions.len(), 1);
        assert_eq!(dispositions[0].subwallet, id);
        assert_eq!(dispositions[0].st_hash, redrive.st_hash());
        assert_eq!(dispositions[0].activity_id, redrive.activity_id);
        assert_eq!(
            dispositions[0].disposition,
            ShieldedSpendDisposition::Executed
        );
        assert!(store.dispositions([0xC2; 32]).unwrap().is_empty());
        vec![id.wallet_id]
    }

    pub(crate) fn identical_second_write_is_noop_and_different_conflicts<S: ShieldedStore>(
        store: &mut S,
    ) -> Vec<WalletId> {
        let id = SubwalletId::new([0xC3; 32], 0);
        let st_hash = [0x21; 32];
        let activity_id = [0x31; 32];
        let rejected = ShieldedSpendDisposition::NotExecuted(NotExecutedReason::Rejected);
        let purged = ShieldedSpendDisposition::Unresolved(UnresolvedReason::Purged);
        assert!(store
            .record_disposition(id, &st_hash, &activity_id, rejected)
            .unwrap());
        let before = store.dispositions(id.wallet_id).unwrap();

        assert!(
            !store
                .record_disposition(id, &st_hash, &activity_id, rejected)
                .unwrap(),
            "an identical second write is a no-op"
        );
        assert_eq!(
            refusal(store.record_disposition(id, &st_hash, &activity_id, purged)),
            ShieldedDispositionRefusal::Conflict {
                st_hash,
                existing_account_index: 0,
                existing_activity_id: activity_id,
                existing: rejected,
                attempted_account_index: 0,
                attempted_activity_id: activity_id,
                attempted: purged,
            }
        );
        assert!(matches!(
            refusal(store.record_disposition(id, &st_hash, &[0x32; 32], rejected)),
            ShieldedDispositionRefusal::Conflict { .. }
        ));
        assert!(
            matches!(
                refusal(store.record_disposition(
                    SubwalletId::new(id.wallet_id, 1),
                    &st_hash,
                    &activity_id,
                    rejected
                )),
                ShieldedDispositionRefusal::Conflict {
                    existing_account_index: 0,
                    attempted_account_index: 1,
                    ..
                }
            ),
            "one transition has one piece of evidence across the wallet's accounts"
        );
        assert_eq!(
            store.dispositions(id.wallet_id).unwrap(),
            before,
            "neither the no-op nor a conflict may touch the stored evidence"
        );
        assert!(
            store
                .record_disposition(
                    SubwalletId::new([0xC2; 32], 0),
                    &st_hash,
                    &activity_id,
                    purged
                )
                .unwrap(),
            "another wallet keeps its own evidence"
        );

        // The same rule holds when the write comes from resolving a record.
        let redrive = spend(0x12, &[[0xA3; 32]]);
        assert!(store
            .record_disposition(id, &redrive.st_hash(), &redrive.activity_id, purged)
            .unwrap());
        let before = store.dispositions(id.wallet_id).unwrap();
        arm_reserved(store, id, &redrive);
        assert!(matches!(
            refusal(store.resolve_redrive(
                id,
                &redrive.activity_id,
                ShieldedSpendDisposition::Executed
            )),
            ShieldedDispositionRefusal::Conflict { .. }
        ));
        assert_eq!(
            store.pending_redrives(id).unwrap(),
            vec![redrive.clone()],
            "a conflicting resolution leaves the record armed"
        );
        assert!(
            unspent(store, id).is_empty(),
            "and leaves its reservations in place"
        );
        assert_eq!(store.dispositions(id.wallet_id).unwrap(), before);

        assert_eq!(
            store
                .resolve_redrive(id, &redrive.activity_id, purged)
                .expect("an identical resolution completes"),
            redrive
        );
        assert!(store.pending_redrives(id).unwrap().is_empty());
        assert_eq!(unspent(store, id), BTreeSet::from([[0xA3; 32]]));
        assert_eq!(
            store.dispositions(id.wallet_id).unwrap(),
            before,
            "the existing evidence is kept unchanged"
        );
        vec![id.wallet_id, [0xC2; 32]]
    }

    pub(crate) fn resolve_redrive_refuses_identity_debit_and_missing_activity<S: ShieldedStore>(
        store: &mut S,
    ) -> Vec<WalletId> {
        let id = SubwalletId::new([0xC4; 32], 1);
        let identity_debit = spend(0x13, &[]);
        store.arm_redrive(id, identity_debit.clone()).unwrap();

        assert_eq!(
            refusal(store.resolve_redrive(
                id,
                &identity_debit.activity_id,
                ShieldedSpendDisposition::NotExecuted(NotExecutedReason::Abandoned)
            )),
            ShieldedDispositionRefusal::IdentityDebit {
                activity_id: identity_debit.activity_id
            }
        );
        assert_eq!(
            store.pending_redrives(id).unwrap(),
            vec![identity_debit],
            "an identity debit keeps its own recovery model"
        );
        for (subwallet, activity_id) in [
            (id, [0xEE; 32]),
            (SubwalletId::new([0xC4; 32], 2), [0x13; 32]),
        ] {
            assert_eq!(
                refusal(store.resolve_redrive(
                    subwallet,
                    &activity_id,
                    ShieldedSpendDisposition::Executed
                )),
                ShieldedDispositionRefusal::RedriveNotFound { activity_id }
            );
        }
        assert!(store.dispositions(id.wallet_id).unwrap().is_empty());
        vec![id.wallet_id]
    }

    pub(crate) fn record_disposition_refuses_while_redrive_armed<S: ShieldedStore>(
        store: &mut S,
    ) -> Vec<WalletId> {
        let id = SubwalletId::new([0xC5; 32], 0);
        let redrive = spend(0x14, &[[0xA4; 32]]);
        arm_reserved(store, id, &redrive);
        let executed = ShieldedSpendDisposition::Executed;

        for (subwallet, st_hash, activity_id) in [
            (id, redrive.st_hash(), [0x99; 32]),
            (id, [0x98; 32], redrive.activity_id),
            (
                SubwalletId::new(id.wallet_id, 1),
                redrive.st_hash(),
                redrive.activity_id,
            ),
        ] {
            assert_eq!(
                refusal(store.record_disposition(subwallet, &st_hash, &activity_id, executed)),
                ShieldedDispositionRefusal::RedriveArmed {
                    activity_id: redrive.activity_id
                }
            );
        }
        assert!(store.dispositions(id.wallet_id).unwrap().is_empty());
        assert_eq!(store.pending_redrives(id).unwrap(), vec![redrive.clone()]);
        assert!(unspent(store, id).is_empty());

        let other_wallet = SubwalletId::new([0xCC; 32], 0);
        assert!(
            store
                .record_disposition(
                    other_wallet,
                    &redrive.st_hash(),
                    &redrive.activity_id,
                    executed
                )
                .unwrap(),
            "the armed-record check is scoped to its own wallet"
        );
        vec![id.wallet_id, other_wallet.wallet_id]
    }

    pub(crate) fn ack_removes_only_that_hash<S: ShieldedStore>(store: &mut S) -> Vec<WalletId> {
        let wallet_id = [0xC6; 32];
        let a = SubwalletId::new(wallet_id, 0);
        let b = SubwalletId::new(wallet_id, 1);
        let other = SubwalletId::new([0xC7; 32], 0);
        let rejected = ShieldedSpendDisposition::NotExecuted(NotExecutedReason::Rejected);
        for (id, st_hash) in [
            (a, [0x41; 32]),
            (a, [0x42; 32]),
            (b, [0x43; 32]),
            (other, [0x41; 32]),
        ] {
            assert!(store
                .record_disposition(id, &st_hash, &[0x50; 32], rejected)
                .unwrap());
        }

        assert!(store.ack_disposition(a, &[0x41; 32]).unwrap());

        let left: Vec<_> = store
            .dispositions(wallet_id)
            .unwrap()
            .into_iter()
            .map(|record| (record.subwallet, record.st_hash))
            .collect();
        assert_eq!(left, vec![(a, [0x42; 32]), (b, [0x43; 32])]);
        assert_eq!(store.dispositions(other.wallet_id).unwrap().len(), 1);
        assert!(!store.ack_disposition(a, &[0x41; 32]).unwrap());
        assert!(
            !store.ack_disposition(a, &[0x43; 32]).unwrap(),
            "an ack names its account; another account's evidence stays"
        );
        assert_eq!(store.dispositions(wallet_id).unwrap().len(), 2);
        vec![wallet_id, other.wallet_id]
    }

    pub(crate) fn purges_leave_dispositions<S: ShieldedStore>(store: &mut S) -> Vec<WalletId> {
        let first = SubwalletId::new([0xC8; 32], 0);
        let second = SubwalletId::new([0xC8; 32], 1);
        let other = SubwalletId::new([0xC9; 32], 0);
        for (tag, id) in [(0x15, first), (0x16, second), (0x17, other)] {
            let redrive = spend(tag, &[[tag.wrapping_add(0x80); 32]]);
            arm_reserved(store, id, &redrive);
            store
                .resolve_redrive(
                    id,
                    &redrive.activity_id,
                    ShieldedSpendDisposition::NotExecuted(NotExecutedReason::Pruned),
                )
                .unwrap();
            assert!(store
                .record_disposition(
                    id,
                    &[tag; 32],
                    &[tag; 32],
                    ShieldedSpendDisposition::Unresolved(UnresolvedReason::DeserializeDropped)
                )
                .unwrap());
        }
        let before = (
            store.dispositions(first.wallet_id).unwrap(),
            store.dispositions(other.wallet_id).unwrap(),
        );
        assert_eq!(before.0.len(), 4);
        assert_eq!(before.1.len(), 2);

        store.purge_subwallet(first).unwrap();
        store.purge_wallet(first.wallet_id).unwrap();
        store.purge_all_subwallets().unwrap();

        assert_eq!(
            (
                store.dispositions(first.wallet_id).unwrap(),
                store.dispositions(other.wallet_id).unwrap(),
            ),
            before,
            "purges must leave every unacknowledged disposition"
        );
        vec![first.wallet_id, other.wallet_id]
    }

    pub(crate) fn resolve_keeps_reservations_another_redrive_holds<S: ShieldedStore>(
        store: &mut S,
    ) -> Vec<WalletId> {
        let id = SubwalletId::new([0xCA; 32], 0);
        let shared = [0xB1; 32];
        let first = spend(0x18, &[shared, [0xB2; 32]]);
        let second = PendingRedrive {
            anchor: [0x5B; 32],
            ..spend(0x19, &[shared, [0xB3; 32]])
        };
        arm_reserved(store, id, &first);
        arm_reserved(store, id, &second);

        assert_eq!(
            refusal(store.resolve_redrive(
                id,
                &first.activity_id,
                ShieldedSpendDisposition::Executed
            )),
            ShieldedDispositionRefusal::ReservationShared {
                activity_id: first.activity_id,
                other_activity_id: second.activity_id,
            },
            "a spent shared nullifier cannot show which record executed"
        );
        assert_eq!(store.pending_redrives(id).unwrap().len(), 2);
        assert!(store.dispositions(id.wallet_id).unwrap().is_empty());

        // The shared reservation was last attached to `second`; resolving it
        // must hand the reservation back to `first`, not leave it on `second`.
        store
            .resolve_redrive(
                id,
                &second.activity_id,
                ShieldedSpendDisposition::NotExecuted(NotExecutedReason::Pruned),
            )
            .unwrap();

        assert_eq!(store.pending_redrives(id).unwrap(), vec![first.clone()]);
        assert_eq!(
            unspent(store, id),
            BTreeSet::from([[0xB3; 32]]),
            "a note another armed record carries stays reserved"
        );
        let mut stale = store.stale_pending_spends(id).unwrap();
        stale.sort();
        assert_eq!(
            stale,
            vec![
                (shared, first.anchor, Some(first.activity_id)),
                ([0xB2; 32], first.anchor, Some(first.activity_id)),
            ],
            "the kept reservation now describes the surviving record"
        );

        store
            .resolve_redrive(id, &first.activity_id, ShieldedSpendDisposition::Executed)
            .expect("with no other record on its notes, Executed is allowed");
        assert_eq!(
            unspent(store, id),
            BTreeSet::from([shared, [0xB2; 32], [0xB3; 32]])
        );
        vec![id.wallet_id]
    }

    pub(crate) fn unresolved_roundtrips<S: ShieldedStore>(store: &mut S) -> Vec<WalletId> {
        let id = SubwalletId::new([0xCB; 32], 2);
        let dropped = spend(0x1A, &[[0xB4; 32]]);
        arm_reserved(store, id, &dropped);
        let deserialize_dropped =
            ShieldedSpendDisposition::Unresolved(UnresolvedReason::DeserializeDropped);
        let purged = ShieldedSpendDisposition::Unresolved(UnresolvedReason::Purged);
        store
            .resolve_redrive(id, &dropped.activity_id, deserialize_dropped)
            .unwrap();
        assert!(store
            .record_disposition(id, &[0x1B; 32], &[0x1B; 32], purged)
            .unwrap());

        let got: Vec<_> = store
            .dispositions(id.wallet_id)
            .unwrap()
            .into_iter()
            .map(|record| (record.st_hash, record.activity_id, record.disposition))
            .collect();
        let mut expected = vec![
            (dropped.st_hash(), dropped.activity_id, deserialize_dropped),
            ([0x1B; 32], [0x1B; 32], purged),
        ];
        expected.sort_by_key(|(st_hash, _, _)| *st_hash);
        assert_eq!(got, expected);
        vec![id.wallet_id]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id(account: u32) -> SubwalletId {
        SubwalletId::new([0xAA; 32], account)
    }

    #[test]
    fn should_borrow_spendable_notes_and_preserve_the_selection_filter() {
        let mut state = SubwalletState::default();
        for tag in 1..=4 {
            let mut note = note_with_nullifier([tag; 32]);
            note.value = u64::from(tag) * 100;
            state.save_note(&note);
        }
        state.mark_pending(&[2; 32]);
        state.mark_spent(&[3; 32]);

        let borrowed: Vec<_> = state.unspent_notes_iter().collect();
        assert_eq!(borrowed.len(), 2);
        assert!(std::ptr::eq(borrowed[0], &state.notes[0]));
        assert!(std::ptr::eq(borrowed[1], &state.notes[3]));
        assert_eq!(state.spendable_balance(), Some(500));
        assert_eq!(
            state
                .unspent_notes()
                .iter()
                .map(|note| note.value)
                .collect::<Vec<_>>(),
            vec![100, 400]
        );
        state.clear_pending(&[2; 32]);
        assert_eq!(state.spendable_balance(), Some(700));
    }

    #[test]
    fn should_reject_overflowing_in_memory_spendable_balance() {
        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        for (tag, value) in [(1, u64::MAX), (2, 1)] {
            store
                .save_note(
                    id,
                    &ShieldedNote {
                        position: tag as u64,
                        cmx: [tag; 32],
                        nullifier: [tag; 32],
                        block_height: 100,
                        is_spent: false,
                        value,
                        note_data: vec![],
                    },
                )
                .expect("save test note");
        }
        let error = store
            .spendable_balance(id)
            .expect_err("overflow must not wrap or panic");
        assert!(error.to_string().contains("exceeds u64"));

        // Reservations and spent notes are excluded before checked addition.
        store
            .mark_pending(id, &[2; 32])
            .expect("reserve small note");
        assert_eq!(store.spendable_balance(id).unwrap(), u64::MAX);
        assert_eq!(store.spendable_balance(test_id(1)).unwrap(), 0);
        assert_eq!(
            store
                .spendable_balance(SubwalletId::new([0xBB; 32], 0))
                .unwrap(),
            0
        );
        store
            .clear_pending(id, &[2; 32])
            .expect("release reservation");
        assert!(store.spendable_balance(id).is_err());
        store.mark_spent(id, &[2; 32]).expect("spend small note");
        assert_eq!(store.spendable_balance(id).unwrap(), u64::MAX);
        store
            .mark_spent(id, &[1; 32])
            .expect("spend remaining note");
        assert_eq!(store.spendable_balance(id).unwrap(), 0);
    }

    #[test]
    fn test_save_and_retrieve_notes() {
        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        let note = ShieldedNote {
            position: 42,
            cmx: [1u8; 32],
            nullifier: [2u8; 32],
            block_height: 100,
            is_spent: false,
            value: 1000,
            note_data: vec![0u8; 115],
        };
        store.save_note(id, &note).unwrap();

        let unspent = store.get_unspent_notes(id).unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].value, 1000);
        assert_eq!(unspent[0].position, 42);

        // A different subwallet sees no notes.
        let other = test_id(1);
        assert!(store.get_unspent_notes(other).unwrap().is_empty());
    }

    #[test]
    fn test_mark_spent() {
        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        let nullifier = [3u8; 32];
        let note = ShieldedNote {
            position: 0,
            cmx: [1u8; 32],
            nullifier,
            block_height: 50,
            is_spent: false,
            value: 500,
            note_data: vec![0u8; 115],
        };
        store.save_note(id, &note).unwrap();

        assert!(store.mark_spent(id, &nullifier).unwrap());
        assert!(store.get_unspent_notes(id).unwrap().is_empty());
        let all = store.get_all_notes(id).unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].is_spent);
        // Marking again returns false (already spent).
        assert!(!store.mark_spent(id, &nullifier).unwrap());
    }

    /// Two notes carrying one nullifier must count once.
    ///
    /// A nullifier is what makes a note spendable exactly once, so if two notes in a pool
    /// share one, only one of them can ever be spent and the other's value is unreachable.
    /// A wallet that added both to its balance would show funds it cannot move and would
    /// build transitions that fail against the chain.
    ///
    /// `save_note` keys on the nullifier and overwrites, which gives the right answer. That
    /// behaviour was written to make rescanning idempotent, and its reasoning — that
    /// nullifiers are unique — is exactly what does not hold here. This pins the outcome
    /// rather than the reasoning, so the guarantee survives a future rescan mechanism that
    /// makes the original justification obsolete.
    #[test]
    fn should_count_two_notes_sharing_a_nullifier_once() {
        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        let nullifier = [7u8; 32];
        let note = ShieldedNote {
            position: 3,
            cmx: [9u8; 32],
            nullifier,
            block_height: 10,
            is_spent: false,
            value: 1_000,
            note_data: vec![0u8; 115],
        };
        // The same note observed again at a later tree position: same commitment, same
        // nullifier, different provenance.
        let twin = ShieldedNote {
            position: 11,
            block_height: 12,
            ..note.clone()
        };

        store.save_note(id, &note).unwrap();
        store.save_note(id, &twin).unwrap();

        assert_eq!(
            store.get_all_notes(id).unwrap().len(),
            1,
            "a second note sharing a nullifier must replace the first, not join it"
        );
        assert_eq!(
            store.spendable_balance(id).unwrap(),
            1_000,
            "BALANCE INFLATION: the wallet counted both notes, but only one is spendable, \
             so it would offer the holder funds no transition can move"
        );

        // And the single entry really is the one note: spending it leaves nothing behind.
        assert!(store.mark_spent(id, &nullifier).unwrap());
        assert!(
            store.get_unspent_notes(id).unwrap().is_empty(),
            "spending the shared nullifier must leave no second note live"
        );
    }

    /// Resolving any of a redrive's nullifiers — landing (`mark_spent`)
    /// or release (`clear_pending`) — drops the whole record: a
    /// transition lands or dies atomically for all its nullifiers.
    #[test]
    fn resolving_a_nullifier_drops_the_redrive_record() {
        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        let n1 = [3u8; 32];
        let n2 = [4u8; 32];
        let note = ShieldedNote {
            position: 0,
            cmx: [1u8; 32],
            nullifier: n1,
            block_height: 50,
            is_spent: false,
            value: 500,
            note_data: vec![0u8; 115],
        };
        store.save_note(id, &note).unwrap();
        let redrive = PendingRedrive {
            activity_id: [9u8; 32],
            anchor: [8u8; 32],
            nullifiers: vec![n1, n2],
            st_bytes: vec![1, 2, 3],
            attempts: 0,
            identity_nonce_finalized: false,
            identity_user_abandoned: false,
        };

        // Landing path: mark_spent on one nullifier drops the record.
        store.mark_pending(id, &n1).unwrap();
        store.arm_redrive(id, redrive.clone()).unwrap();
        assert_eq!(store.pending_redrives(id).unwrap().len(), 1);
        assert!(store.mark_spent(id, &n1).unwrap());
        assert!(
            store.pending_redrives(id).unwrap().is_empty(),
            "landed spend drops its redrive record"
        );

        // Release path: clear_pending on a nullifier drops the record.
        store.mark_pending(id, &n2).unwrap();
        store.arm_redrive(id, redrive).unwrap();
        assert!(store.clear_pending(id, &n2).unwrap());
        assert!(
            store.pending_redrives(id).unwrap().is_empty(),
            "released reservation drops its redrive record"
        );
    }

    #[test]
    fn test_sync_state_per_subwallet() {
        let mut store = InMemoryShieldedStore::new();
        let a = test_id(0);
        let b = test_id(1);

        assert_eq!(store.last_synced_note_index(a).unwrap(), 0);
        store.set_last_synced_note_index(a, 100).unwrap();
        assert_eq!(store.last_synced_note_index(a).unwrap(), 100);
        // Different subwallet still at 0.
        assert_eq!(store.last_synced_note_index(b).unwrap(), 0);
    }

    #[test]
    fn test_commitment_tree_operations() {
        let mut store = InMemoryShieldedStore::new();
        store.append_commitment(&[1u8; 32], true).unwrap();
        store.append_commitment(&[2u8; 32], false).unwrap();
        store.checkpoint_tree(1).unwrap();
        assert_eq!(store.tree_anchor().unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_save_activity_upserts_and_paginates() {
        use super::super::activity::{
            ShieldedActivityEntry, ShieldedActivityKind, ShieldedActivityStatus, ShieldedDirection,
        };

        fn entry(
            id: u8,
            height: Option<u64>,
            status: ShieldedActivityStatus,
        ) -> ShieldedActivityEntry {
            ShieldedActivityEntry {
                id: [id; 32],
                kind: ShieldedActivityKind::Sent,
                direction: ShieldedDirection::Out,
                amount: 1,
                fee: None,
                counterparty: None,
                memo: None,
                block_height: height,
                status,
                created_at_ms: 0,
                min_note_position: None,
                note_cmxs: vec![[id; 32]],
                spent_nullifiers: vec![],
            }
        }

        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);

        // Two confirmed at different heights + one pending.
        store
            .save_activity(id, &entry(1, Some(10), ShieldedActivityStatus::Confirmed))
            .unwrap();
        store
            .save_activity(id, &entry(2, Some(20), ShieldedActivityStatus::Confirmed))
            .unwrap();
        store
            .save_activity(id, &entry(3, None, ShieldedActivityStatus::Pending))
            .unwrap();

        // Display order: pending first, then height desc.
        let page = store.get_activity(id, 0, 10).unwrap();
        assert_eq!(page.len(), 3);
        assert_eq!(page[0].id, [3u8; 32], "pending floats to top");
        assert_eq!(page[1].id, [2u8; 32], "height 20 before 10");
        assert_eq!(page[2].id, [1u8; 32]);

        // Upsert by id: re-saving entry 1 as Pending replaces it in place
        // (still 3 entries, but now 1 is pending and floats up).
        store
            .save_activity(id, &entry(1, None, ShieldedActivityStatus::Pending))
            .unwrap();
        let page = store.get_activity(id, 0, 10).unwrap();
        assert_eq!(page.len(), 3, "upsert by id, not append");
        assert_eq!(
            store.get_activity_ids(id).unwrap().len(),
            3,
            "still exactly three distinct ids"
        );

        // Pagination: offset/limit slice the display-sorted list.
        let first_two = store.get_activity(id, 0, 2).unwrap();
        assert_eq!(first_two.len(), 2);
        let last_one = store.get_activity(id, 2, 10).unwrap();
        assert_eq!(last_one.len(), 1);
        // limit 0 => empty page.
        assert!(store.get_activity(id, 0, 0).unwrap().is_empty());

        // Lookup by entry id.
        assert!(store
            .get_activity_by_entry_id(id, &[2u8; 32])
            .unwrap()
            .is_some());
        assert!(store
            .get_activity_by_entry_id(id, &[9u8; 32])
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_reset_commitment_tree_empties_and_reappends_from_zero() {
        let mut store = InMemoryShieldedStore::new();
        store.append_commitment(&[1u8; 32], true).unwrap();
        store.append_commitment(&[2u8; 32], true).unwrap();
        store.checkpoint_tree(2).unwrap();
        assert_eq!(store.tree_size().unwrap(), 2);

        store.reset_commitment_tree().unwrap();
        assert_eq!(
            store.tree_size().unwrap(),
            0,
            "tree_size must be 0 after reset"
        );

        // Re-append starts from position 0 again.
        store.append_commitment(&[3u8; 32], true).unwrap();
        assert_eq!(store.tree_size().unwrap(), 1);
    }

    /// Build a minimal unspent note carrying `nullifier`.
    fn note_with_nullifier(nullifier: [u8; 32]) -> ShieldedNote {
        ShieldedNote {
            position: 0,
            cmx: [1u8; 32],
            nullifier,
            block_height: 1,
            is_spent: false,
            value: 1_000,
            note_data: vec![0u8; 115],
        }
    }

    /// A reservation carrying a recorded anchor surfaces via
    /// `stale_pending_spends`, and the sync reconcile's release decision
    /// (release iff the anchor is absent from the recorded set) must RETAIN
    /// it while the anchor is still recorded — a slow-but-landing spend is
    /// never freed, so its note stays out of the unspent set.
    #[test]
    fn pending_spend_with_recorded_anchor_is_retained() {
        use std::collections::HashSet;

        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        let nullifier = [0x11; 32];
        let anchor = [0x22; 32];
        let activity_id = [0x33; 32];

        store
            .save_note(id, &note_with_nullifier(nullifier))
            .unwrap();
        assert!(
            store.mark_pending(id, &nullifier).unwrap(),
            "newly reserved"
        );
        store
            .set_pending_spend(id, &nullifier, anchor, activity_id)
            .unwrap();

        assert_eq!(
            store.stale_pending_spends(id).unwrap(),
            vec![(nullifier, anchor, Some(activity_id))],
            "an armed reservation surfaces as an anchored (stale-checkable) spend"
        );

        // Anchor IS still recorded → retain.
        let recorded: HashSet<[u8; 32]> = [anchor].into_iter().collect();
        for (n, a, _) in store.stale_pending_spends(id).unwrap() {
            if !recorded.contains(&a) {
                store.clear_pending(id, &n).unwrap();
            }
        }
        assert_eq!(
            store.stale_pending_spends(id).unwrap().len(),
            1,
            "a still-recorded anchor must not be released"
        );
        assert!(
            store.get_unspent_notes(id).unwrap().is_empty(),
            "the retained note stays excluded from selection candidates"
        );
    }

    /// The fund-safe release: once the anchor is pruned (absent from the
    /// recorded set) the spend can never execute, so the reservation is
    /// released and the freed note becomes spendable again.
    #[test]
    fn pending_spend_with_pruned_anchor_is_released() {
        use std::collections::HashSet;

        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        let nullifier = [0x11; 32];
        let anchor = [0x22; 32];
        let activity_id = [0x33; 32];

        store
            .save_note(id, &note_with_nullifier(nullifier))
            .unwrap();
        store.mark_pending(id, &nullifier).unwrap();
        store
            .set_pending_spend(id, &nullifier, anchor, activity_id)
            .unwrap();
        assert!(store.get_unspent_notes(id).unwrap().is_empty());

        // Anchor is ABSENT from the recorded set (pruned) → release.
        let recorded: HashSet<[u8; 32]> = [[0xEE; 32]].into_iter().collect();
        for (n, a, _) in store.stale_pending_spends(id).unwrap() {
            if !recorded.contains(&a) {
                assert!(store.clear_pending(id, &n).unwrap());
            }
        }
        assert!(
            store.stale_pending_spends(id).unwrap().is_empty(),
            "a pruned-anchor reservation must be released"
        );
        let unspent = store.get_unspent_notes(id).unwrap();
        assert_eq!(unspent.len(), 1, "the freed note is spendable again");
        assert_eq!(unspent[0].nullifier, nullifier);
    }

    /// A reserved note is excluded from `unspent_notes` (so a concurrent
    /// spend can't re-select it) and re-included once the reservation is
    /// cleared.
    #[test]
    fn unspent_notes_excludes_pending_and_reincludes_after_clear() {
        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        let nullifier = [0x55; 32];
        store
            .save_note(id, &note_with_nullifier(nullifier))
            .unwrap();
        assert_eq!(store.get_unspent_notes(id).unwrap().len(), 1);

        store.mark_pending(id, &nullifier).unwrap();
        assert!(
            store.get_unspent_notes(id).unwrap().is_empty(),
            "a reserved note is excluded from selection candidates"
        );

        assert!(store.clear_pending(id, &nullifier).unwrap());
        assert_eq!(
            store.get_unspent_notes(id).unwrap().len(),
            1,
            "releasing the reservation re-includes the note"
        );
    }

    /// `stale_pending_spends` ignores a reservation that was `mark_pending`ed
    /// but never armed with an anchor (a just-reserved, not-yet-built spend):
    /// the reconcile must never release such a transient entry.
    #[test]
    fn unarmed_reservation_is_not_stale() {
        let mut store = InMemoryShieldedStore::new();
        let id = test_id(0);
        let nullifier = [0x66; 32];
        store
            .save_note(id, &note_with_nullifier(nullifier))
            .unwrap();
        store.mark_pending(id, &nullifier).unwrap();

        assert!(
            store.stale_pending_spends(id).unwrap().is_empty(),
            "a reservation with no recorded anchor must not surface as stale"
        );
    }

    #[test]
    fn account_purge_retains_wallet_wide_identity_guard_only() {
        let wallet_id = [0x81; 32];
        let id = SubwalletId::new(wallet_id, 4);
        let mut store = InMemoryShieldedStore::new();
        let identity_guard = PendingRedrive {
            activity_id: [0x11; 32],
            anchor: [0x22; 32],
            nullifiers: vec![],
            st_bytes: vec![0x33; 16],
            attempts: 7,
            identity_nonce_finalized: false,
            identity_user_abandoned: false,
        };
        let note_spend = PendingRedrive {
            activity_id: [0x44; 32],
            anchor: [0x55; 32],
            nullifiers: vec![[0x66; 32]],
            st_bytes: vec![0x77; 16],
            attempts: 1,
            identity_nonce_finalized: false,
            identity_user_abandoned: false,
        };
        store.arm_redrive(id, identity_guard.clone()).unwrap();
        store.arm_redrive(id, note_spend).unwrap();

        store.purge_subwallet(id).unwrap();

        assert_eq!(
            store.pending_redrives(id).unwrap(),
            vec![identity_guard.clone()],
            "account removal must keep the unresolved identity debit but discard account spends"
        );
        assert_eq!(
            store.pending_redrives_for_wallet(wallet_id).unwrap(),
            vec![(id, identity_guard)],
            "the retained guard must remain visible to wallet-wide admission and redrive"
        );
    }

    #[test]
    fn st_hash_equals_transaction_id() {
        use dpp::serialization::PlatformSerializable;
        use dpp::state_transition::shielded_transfer_transition::v0::ShieldedTransferTransitionV0;
        use dpp::state_transition::unshield_transition::v0::UnshieldTransitionV0;
        use dpp::state_transition::StateTransition;

        let transfer: StateTransition = ShieldedTransferTransitionV0 {
            actions: vec![],
            value_balance: 1_000,
            anchor: [0x51; 32],
            proof: vec![0x07; 40],
            binding_signature: [0x09; 64],
        }
        .into();
        let unshield: StateTransition = UnshieldTransitionV0 {
            output_address: dpp::address_funds::PlatformAddress::P2pkh([0x0C; 20]),
            actions: vec![],
            unshielding_amount: 2_000,
            anchor: [0x52; 32],
            proof: vec![0x08; 40],
            binding_signature: [0x0A; 64],
        }
        .into();
        for transition in [transfer, unshield] {
            let redrive = PendingRedrive {
                activity_id: [0x01; 32],
                anchor: [0x02; 32],
                nullifiers: vec![[0x03; 32]],
                st_bytes: transition.serialize_to_bytes().unwrap(),
                attempts: 0,
                identity_nonce_finalized: false,
                identity_user_abandoned: false,
            };
            assert_eq!(redrive.st_hash(), transition.transaction_id().unwrap());
        }
    }

    #[test]
    fn disposition_strings_are_stable_and_unknown_values_fail_closed() {
        use ShieldedSpendDisposition::{Executed, NotExecuted, Unresolved};
        let table = [
            (Executed, "executed", None),
            (
                NotExecuted(NotExecutedReason::Refused),
                "not_executed",
                Some("refused"),
            ),
            (
                NotExecuted(NotExecutedReason::Abandoned),
                "not_executed",
                Some("abandoned"),
            ),
            (
                NotExecuted(NotExecutedReason::Rejected),
                "not_executed",
                Some("rejected"),
            ),
            (
                NotExecuted(NotExecutedReason::Pruned),
                "not_executed",
                Some("pruned"),
            ),
            (
                Unresolved(UnresolvedReason::DeserializeDropped),
                "unresolved",
                Some("deserialize_dropped"),
            ),
            (
                Unresolved(UnresolvedReason::Purged),
                "unresolved",
                Some("purged"),
            ),
        ];
        for (disposition, kind, reason) in table {
            assert_eq!(disposition.kind_str(), kind);
            assert_eq!(disposition.reason_str(), reason);
            assert_eq!(
                ShieldedSpendDisposition::from_stored(kind, reason),
                Ok(disposition)
            );
        }
        for (kind, reason) in [
            ("executed", Some("refused")),
            ("not_executed", None),
            ("not_executed", Some("purged")),
            ("unresolved", None),
            ("unresolved", Some("refused")),
            ("unresolved", Some("a_later_reason")),
            ("Executed", None),
            ("pending", None),
            ("", None),
        ] {
            assert_eq!(
                ShieldedSpendDisposition::from_stored(kind, reason),
                Err(UnknownDispositionValue {
                    kind: kind.to_owned(),
                    reason: reason.map(str::to_owned),
                }),
                "{kind:?}/{reason:?} must not decode"
            );
        }
    }

    #[test]
    fn in_memory_resolve_records_removes_and_releases() {
        disposition_contract::resolve_records_removes_and_releases(
            &mut InMemoryShieldedStore::new(),
        );
    }

    #[test]
    fn in_memory_identical_second_write_is_noop_and_different_conflicts() {
        disposition_contract::identical_second_write_is_noop_and_different_conflicts(
            &mut InMemoryShieldedStore::new(),
        );
    }

    #[test]
    fn in_memory_resolve_redrive_refuses_identity_debit_and_missing_activity() {
        disposition_contract::resolve_redrive_refuses_identity_debit_and_missing_activity(
            &mut InMemoryShieldedStore::new(),
        );
    }

    #[test]
    fn in_memory_record_disposition_refuses_while_redrive_armed() {
        disposition_contract::record_disposition_refuses_while_redrive_armed(
            &mut InMemoryShieldedStore::new(),
        );
    }

    #[test]
    fn in_memory_ack_removes_only_that_hash() {
        disposition_contract::ack_removes_only_that_hash(&mut InMemoryShieldedStore::new());
    }

    #[test]
    fn in_memory_purges_leave_dispositions() {
        disposition_contract::purges_leave_dispositions(&mut InMemoryShieldedStore::new());
    }

    #[test]
    fn in_memory_resolve_keeps_reservations_another_redrive_holds() {
        disposition_contract::resolve_keeps_reservations_another_redrive_holds(
            &mut InMemoryShieldedStore::new(),
        );
    }

    #[test]
    fn in_memory_unresolved_roundtrips() {
        disposition_contract::unresolved_roundtrips(&mut InMemoryShieldedStore::new());
    }
}
