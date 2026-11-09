//! The host's dispatch hook for shielded note spends.
//!
//! A host that sets a [`ShieldedDispatch`] on the network's coordinator
//! ([`NetworkShieldedCoordinator::set_shielded_dispatch`]) registers every
//! note spend before anything is broadcast, and fences every later
//! rebroadcast of it:
//!
//! 1. the library persists the spend's redrive record, never broadcast, so
//!    its notes stay reserved across a restart;
//! 2. it awaits [`ShieldedDispatch::dispatch`]. A refusal records the spend
//!    `NotExecuted(Refused)`, frees its notes and sends nothing;
//! 3. only then is the transition broadcast;
//! 4. every rebroadcast of an armed record by a sync pass first awaits
//!    [`ShieldedDispatch::admit`]; a refusal skips it for that pass.
//!
//! [`NetworkShieldedCoordinator::set_shielded_dispatch`]:
//!     super::NetworkShieldedCoordinator::set_shielded_dispatch

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::wallet::platform_wallet::WalletId;

/// The host's hook for shielded note spends (transfer, unshield,
/// withdrawal, identity top-up and identity creation from the pool). See the
/// [module docs](self) for when each method runs.
///
/// # Locks
///
/// Both methods are awaited with no shielded store guard and no coordinator
/// lock held, so they may read the store (for example
/// [`ShieldedStore::get_all_notes`](super::ShieldedStore::get_all_notes)).
/// A running sync pass holds the store's write guard while it scans, so
/// such a read waits for the scan.
///
/// An identity top-up runs with its wallet's shield-class guard held, so a
/// hook must not start a shield, top-up or other shield-class operation on
/// the same wallet: it would wait for itself. Nor may it await a spend of
/// the same coordinator.
///
/// # Failed sends hold their notes
///
/// With a hook set, every spend is armed before its first broadcast, so a
/// first send that then fails, even one that provably never reached the
/// network, is recorded `Unresolved(Cancelled)` and keeps its notes out of
/// selection until the host acknowledges that disposition
/// ([`NetworkShieldedCoordinator::spend_dispositions`]).
///
/// [`NetworkShieldedCoordinator::spend_dispositions`]:
///     super::NetworkShieldedCoordinator::spend_dispositions
#[async_trait]
pub trait ShieldedDispatch: Send + Sync {
    /// Register `payload`'s spend before its first broadcast. Its redrive
    /// record is already durable when this runs. `Ok` lets the broadcast
    /// go ahead; `Err` refuses it, and this call sends nothing.
    ///
    /// `Ok` doesn't guarantee a broadcast: a spend resolved while the hook
    /// ran (for example abandoned, or its wallet removed) is not sent, and
    /// its disposition says why. A spend whose call ends without an answer
    /// (the process stops, the caller drops the future, the hook panics), or
    /// whose refusal can't be recorded, stays armed, and from then on only
    /// [`Self::admit`] decides whether it is ever sent.
    async fn dispatch(&self, payload: ShieldedDispatchPayload) -> Result<(), DispatchRefused>;

    /// Allow a sync pass to send the armed spend of transition `st_hash`,
    /// recorded under `activity_id` in `wallet_id`'s account
    /// `account_index`. `Err` skips it for this pass; the record stays armed
    /// and its attempt count is unchanged.
    ///
    /// This is the only check before such a send, also for a spend whose
    /// [`Self::dispatch`] never returned `Ok` (see there), which may then be
    /// sent for the first time. It must return `Ok` only for an `st_hash`
    /// the host has durably accepted through `dispatch`, and refuse every
    /// other one, including one it has no record of or cannot read its
    /// record for. It isn't called for a transition whose first send is
    /// still in progress.
    ///
    /// A pass without a hook never sends a spend armed while one was set,
    /// even after a restart; it waits for this check.
    async fn admit(
        &self,
        wallet_id: WalletId,
        account_index: u32,
        activity_id: [u8; 32],
        st_hash: [u8; 32],
    ) -> Result<(), DispatchRefused>;
}

/// A refusal from a [`ShieldedDispatch`] hook.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct DispatchRefused {
    /// Why the hook refused.
    pub reason: String,
}

impl DispatchRefused {
    /// A refusal for `reason`.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Which operation a dispatched spend is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedDispatchKind {
    /// A shielded transfer.
    Transfer,
    /// An unshield to a platform address.
    Unshield,
    /// A withdrawal to a Core address.
    Withdraw,
    /// A top-up of `identity_id` from the pool.
    IdentityTopUp { identity_id: [u8; 32] },
    /// The creation of `identity_id` from the pool. The id is derived from
    /// the transition's [`published_nullifiers`](ShieldedDispatchPayload::published_nullifiers).
    IdentityCreate { identity_id: [u8; 32] },
}

/// One of the wallet's own notes a dispatched spend consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchedNote {
    pub nullifier: [u8; 32],
    pub cmx: [u8; 32],
    pub value: u64,
    pub position: u64,
}

/// Everything a [`ShieldedDispatch::dispatch`] call registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedDispatchPayload {
    pub kind: ShieldedDispatchKind,
    pub wallet_id: WalletId,
    pub account_index: u32,
    /// The spend's activity entry id, which keys its redrive record.
    pub activity_id: [u8; 32],
    /// The hash of [`Self::st_bytes`], which keys its disposition.
    pub st_hash: [u8; 32],
    /// The signed transition exactly as it will be broadcast.
    pub st_bytes: Vec<u8>,
    /// The commitment-tree anchor the spend was built against.
    pub anchor: [u8; 32],
    /// The wallet's own notes the spend consumes: exactly the nullifiers its
    /// redrive record reserves. Padding actions are not among them.
    pub selected_notes: Vec<DispatchedNote>,
    /// The nullifier of every action of the transition, in action order,
    /// padding included. A one-note spend is padded to two actions, so this
    /// can hold nullifiers that match no note of the wallet.
    pub published_nullifiers: Vec<[u8; 32]>,
}

/// The hook a coordinator holds, with the transitions in flight under it.
pub(crate) struct DispatchContext {
    pub(crate) hook: Arc<dyn ShieldedDispatch>,
    pub(crate) in_flight: InFlight,
}

impl DispatchContext {
    pub(crate) fn new(hook: Arc<dyn ShieldedDispatch>) -> Self {
        Self {
            hook,
            in_flight: InFlight::default(),
        }
    }
}

/// The `st_hash` of every transition a first send or a rebroadcast holds,
/// from its arming to the send's return. A sync pass skips a record held
/// here.
///
/// Its lock is a leaf: never held across an await or while taking another
/// lock.
#[derive(Clone, Default)]
pub(crate) struct InFlight(Arc<Mutex<HashSet<[u8; 32]>>>);

impl InFlight {
    /// Hold `st_hash` until the returned guard drops, also on an unwind.
    /// `None` when it is already held.
    pub(crate) fn claim(&self, st_hash: [u8; 32]) -> Option<InFlightGuard> {
        self.lock().insert(st_hash).then(|| InFlightGuard {
            set: self.clone(),
            st_hash,
        })
    }

    pub(crate) fn contains(&self, st_hash: &[u8; 32]) -> bool {
        self.lock().contains(st_hash)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<[u8; 32]>> {
        // Every holder only inserts or removes one key, so a poisoned set is
        // still consistent.
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Releases its `st_hash` from [`InFlight`] when dropped.
pub(crate) struct InFlightGuard {
    set: InFlight,
    st_hash: [u8; 32],
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.set.lock().remove(&self.st_hash);
    }
}
