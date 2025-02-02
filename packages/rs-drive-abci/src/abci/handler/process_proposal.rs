use crate::abci::app::{PlatformApplication, TransactionalApplication};
use crate::abci::AbciError;
use crate::error::Error;
use crate::execution::types::block_execution_context::v0::{
    BlockExecutionContextV0Getters, BlockExecutionContextV0MutableGetters,
};
use crate::execution::types::block_state_info::v0::{
    BlockStateInfoV0Getters, BlockStateInfoV0Setters,
};
use crate::platform_types::block_execution_outcome;
use crate::platform_types::state_transitions_processing_result::StateTransitionExecutionResult;
use crate::rpc::core::CoreRPCLike;
use dpp::version::PlatformVersion;
use dpp::version::TryIntoPlatformVersioned;
use tenderdash_abci::proto::abci as proto;
use tenderdash_abci::proto::abci::tx_record::TxAction;

pub fn process_proposal<'a, A, C>(
    app: &A,
    request: proto::RequestProcessProposal,
) -> Result<proto::ResponseProcessProposal, Error>
where
    A: PlatformApplication<C> + TransactionalApplication<'a>,
    C: CoreRPCLike,
{
    let timer = crate::metrics::abci_request_duration("process_proposal");

    let mut block_execution_context_guard = app.platform().block_execution_context.write().unwrap();

    let mut drop_block_execution_context = false;
    if let Some(block_execution_context) = block_execution_context_guard.as_mut() {
        // We are already in a block, or in init chain.
        // This only makes sense if we were the proposer unless we are at a future round
        if block_execution_context.block_state_info().round() != (request.round as u32) {
            // We were not the proposer, and we should process something new
            drop_block_execution_context = true;
        } else if let Some(current_block_hash) =
            block_execution_context.block_state_info().block_hash()
        {
            // There is also the possibility that this block already came in, but tenderdash crashed
            // Now tenderdash is sending it again
            if let Some(proposal_info) = block_execution_context.proposer_results() {
                tracing::debug!(
                    method = "process_proposal",
                    ?proposal_info, // TODO: It might be too big for debug
                    "we knew block hash, block execution context already had a proposer result",
                );
                // We were the proposer as well, so we have the result in cache
                return Ok(proto::ResponseProcessProposal {
                    status: proto::response_process_proposal::ProposalStatus::Accept.into(),
                    app_hash: proposal_info.app_hash.clone(),
                    tx_results: proposal_info.tx_results.clone(),
                    consensus_param_updates: proposal_info.consensus_param_updates.clone(),
                    validator_set_update: proposal_info.validator_set_update.clone(),
                });
            }

            if current_block_hash.as_slice() == request.hash {
                // We were not the proposer, just drop the execution context
                tracing::warn!(
                        method = "process_proposal",
                        ?request, // Shumkov, lklimek: this structure might be very big and we already logged it such as all other ABCI requests and responses
                        "block execution context already existed, but we are running it again for same height {}/round {}",
                        request.height,
                        request.round,
                    );
                drop_block_execution_context = true;
            } else {
                // We are getting a different block hash for a block of the same round
                // This is a terrible issue
                return Err(Error::Abci(AbciError::BadRequest(
                    "received a process proposal request twice with different hash".to_string(),
                )))?;
            }
        } else {
            let Some(proposal_info) = block_execution_context.proposer_results() else {
                return Err(Error::Abci(AbciError::BadRequest(
                    "received a process proposal request twice".to_string(),
                )))?;
            };

            let expected_transactions = proposal_info
                .tx_records
                .iter()
                .filter_map(|record| {
                    if record.action == TxAction::Removed as i32
                        || record.action == TxAction::Delayed as i32
                    {
                        None
                    } else {
                        Some(&record.tx)
                    }
                })
                .collect::<Vec<_>>();

            // While it is true that the length could be same, seeing how this is such a rare situation
            // It does not seem worth to deal with situations where the length is the same but the transactions have changed
            if expected_transactions.len() == request.txs.len()
                && proposal_info.core_chain_lock_update == request.core_chain_lock_update
            {
                let (app_hash, tx_results, consensus_param_updates, validator_set_update) = {
                    tracing::debug!(
                            method = "process_proposal",
                            "we didn't know block hash (we were most likely proposer), block execution context already had a proposer result {:?}",
                            proposal_info,
                        );

                    // Cloning all required properties from proposal_info and then dropping it
                    let app_hash = proposal_info.app_hash.clone();
                    let tx_results = proposal_info.tx_results.clone();
                    let consensus_param_updates = proposal_info.consensus_param_updates.clone();
                    let validator_set_update = proposal_info.validator_set_update.clone();
                    (
                        app_hash,
                        tx_results,
                        consensus_param_updates,
                        validator_set_update,
                    )
                };

                // We need to set the block hash
                block_execution_context
                    .block_state_info_mut()
                    .set_block_hash(Some(request.hash.clone().try_into().map_err(|_| {
                        Error::Abci(AbciError::BadRequestDataSize(
                            "block hash is not 32 bytes in process proposal".to_string(),
                        ))
                    })?));
                return Ok(proto::ResponseProcessProposal {
                    status: proto::response_process_proposal::ProposalStatus::Accept.into(),
                    app_hash,
                    tx_results,
                    consensus_param_updates,
                    validator_set_update,
                });
            } else {
                tracing::warn!(
                            method = "process_proposal",
                            "we didn't know block hash (we were most likely proposer), block execution context already had a proposer result {:?}, but we are requesting a different amount of transactions, dropping the cache",
                            proposal_info,
                        );

                drop_block_execution_context = true;
            };
        }
    }

    if drop_block_execution_context {
        *block_execution_context_guard = None;
    }
    drop(block_execution_context_guard);

    // Get transaction
    let transaction_guard = if request.height == app.platform().config.abci.genesis_height as i64 {
        // special logic on init chain
        let transaction = app.transaction().read().unwrap();
        if transaction.is_none() {
            return Err(Error::Abci(AbciError::BadRequest("received a process proposal request for the genesis height before an init chain request".to_string())))?;
        }
        if request.round > 0 {
            transaction.as_ref().map(|tx| tx.rollback_to_savepoint());
        }
        transaction
    } else {
        app.start_transaction();
        app.transaction().read().unwrap()
    };
    let transaction = transaction_guard.as_ref().unwrap();

    // Running the proposal executes all the state transitions for the block
    let run_result =
        app.platform()
            .run_block_proposal((&request).try_into()?, false, transaction)?;

    if !run_result.is_valid() {
        // This was an error running this proposal, tell tenderdash that the block isn't valid
        let response = proto::ResponseProcessProposal {
            status: proto::response_process_proposal::ProposalStatus::Reject.into(),
            app_hash: [0; 32].to_vec(), // we must send 32 bytes
            ..Default::default()
        };

        tracing::warn!(
            errors = ?run_result.errors,
            "Rejected invalid proposal for height: {}, round: {}",
            request.height,
            request.round,
        );

        Ok(response)
    } else {
        let block_execution_outcome::v0::BlockExecutionOutcome {
            app_hash,
            state_transitions_result: state_transition_results,
            validator_set_update,
            protocol_version,
        } = run_result.into_data().map_err(Error::Protocol)?;

        let platform_version = PlatformVersion::get(protocol_version)
            .expect("must be set in run block proposer from existing platform version");

        let invalid_tx_count = state_transition_results.invalid_paid_count();
        let valid_tx_count = state_transition_results.valid_count();

        let tx_results = state_transition_results
            .into_execution_results()
            .into_iter()
            // To prevent spam attacks we add to the block state transitions covered with fees only
            .filter(|execution_result| {
                matches!(
                    execution_result,
                    StateTransitionExecutionResult::SuccessfulExecution(..)
                        | StateTransitionExecutionResult::PaidConsensusError(..)
                )
            })
            .map(|execution_result| execution_result.try_into_platform_versioned(platform_version))
            .collect::<Result<_, _>>()?;

        let response = proto::ResponseProcessProposal {
            app_hash: app_hash.to_vec(),
            tx_results,
            // TODO: Must be reject if results are different
            status: proto::response_process_proposal::ProposalStatus::Accept.into(),
            validator_set_update,
            // TODO: Implement consensus param updates
            consensus_param_updates: None,
        };

        let elapsed_time_ms = timer.elapsed().as_millis();

        tracing::info!(
            invalid_tx_count,
            valid_tx_count,
            elapsed_time_ms,
            "Processed proposal with {} transactions for height: {}, round: {} in {} ms",
            valid_tx_count + invalid_tx_count,
            request.height,
            request.round,
            elapsed_time_ms,
        );

        Ok(response)
    }
}
