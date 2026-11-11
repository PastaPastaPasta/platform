//! Asset lock lifecycle management.
//!
//! Tracks asset lock transactions from build through finality (IS/CL) and
//! Platform consumption. Shared across sub-wallets via `Arc<AssetLockManager>`.

use dashcore::Transaction;
use dpp::consensus::basic::BasicError;
use dpp::consensus::ConsensusError;
use dpp::identity::state_transition::asset_lock_proof::validate_asset_lock_transaction_structure::validate_asset_lock_transaction_structure;

use crate::error::PlatformWalletError;

mod build;
pub mod lock_notify_handler;
pub mod manager;
pub mod orchestration;
pub(crate) mod sync;
pub mod tracked;

pub use build::AssetLockBuildAmount;
pub use lock_notify_handler::LockNotifyHandler;
pub use orchestration::AssetLockFunding;

/// The refusal an asset-lock transaction over the input cap draws, or
/// `None` when it fits.
///
/// The cap (`max_asset_lock_transaction_inputs`, 100 since v3) is judged by
/// DPP's own structure validator for the transaction
/// (`validate_asset_lock_transaction_structure`, the same check Platform
/// consensus runs on submission), and only its too-many-inputs verdict is
/// projected onto the wallet's error. The wallet owns no second definition of
/// the bound. Dash Core's relay policy refuses the same bound
/// (`assetlocktx-too-many-inputs`) and peers drop such a lock silently, so a
/// funded build asks before the lock is tracked or sent (`build.rs`). The
/// build-only `build_asset_lock_transaction*` does not ask: it hands the
/// transaction back unsent. `credit_output_index` is the lock's credit
/// output.
///
/// Any other verdict of that validator is not this question and is left to
/// the submission layer. A validator the platform version does not know is
/// logged and read as no verdict, so the caller proceeds as if the lock
/// fits; every released version table selects a known validator.
pub(crate) fn input_cap_violation(
    transaction: &Transaction,
    credit_output_index: u32,
    platform_version: &dpp::version::PlatformVersion,
) -> Option<PlatformWalletError> {
    let result = match validate_asset_lock_transaction_structure(
        transaction,
        credit_output_index,
        platform_version,
    ) {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(
                %error,
                "asset lock input cap: DPP's structure validator is unavailable for this \
                 platform version; no verdict"
            );
            return None;
        }
    };
    result.errors.iter().find_map(|error| match error {
        ConsensusError::BasicError(BasicError::IdentityAssetLockTransactionTooManyInputsError(
            too_many,
        )) => Some(PlatformWalletError::AssetLockTooManyInputs {
            count: usize::from(too_many.actual_inputs()),
            max: usize::from(too_many.max_inputs()),
        }),
        _ => None,
    })
}
