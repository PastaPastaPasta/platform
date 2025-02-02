use crate::error::query::QueryError;
use crate::error::Error;
use crate::platform_types::platform::Platform;
use crate::query::QueryValidationResult;
use crate::rpc::core::DefaultCoreRPC;
use crate::utils::spawn_blocking_task_with_name_if_supported;
use async_trait::async_trait;
use dapi_grpc::platform::v0::platform_server::Platform as PlatformService;
use dapi_grpc::platform::v0::{
    BroadcastStateTransitionRequest, BroadcastStateTransitionResponse, GetConsensusParamsRequest,
    GetConsensusParamsResponse, GetDataContractHistoryRequest, GetDataContractHistoryResponse,
    GetDataContractRequest, GetDataContractResponse, GetDataContractsRequest,
    GetDataContractsResponse, GetDocumentsRequest, GetDocumentsResponse, GetEpochsInfoRequest,
    GetEpochsInfoResponse, GetIdentitiesByPublicKeyHashesRequest,
    GetIdentitiesByPublicKeyHashesResponse, GetIdentitiesRequest, GetIdentitiesResponse,
    GetIdentityBalanceAndRevisionRequest, GetIdentityBalanceAndRevisionResponse,
    GetIdentityBalanceRequest, GetIdentityBalanceResponse, GetIdentityByPublicKeyHashRequest,
    GetIdentityByPublicKeyHashResponse, GetIdentityContractNonceRequest,
    GetIdentityContractNonceResponse, GetIdentityKeysRequest, GetIdentityKeysResponse,
    GetIdentityNonceRequest, GetIdentityNonceResponse, GetIdentityRequest, GetIdentityResponse,
    GetProofsRequest, GetProofsResponse, GetProtocolVersionUpgradeStateRequest,
    GetProtocolVersionUpgradeStateResponse, GetProtocolVersionUpgradeVoteStatusRequest,
    GetProtocolVersionUpgradeVoteStatusResponse, WaitForStateTransitionResultRequest,
    WaitForStateTransitionResultResponse,
};
use dapi_grpc::tonic::{Request, Response, Status};
use dpp::version::PlatformVersion;
use dpp::version::PlatformVersionCurrentVersion;
use std::sync::Arc;
use tracing::Instrument;

/// Service to handle platform queries
pub struct QueryService {
    platform: Arc<Platform<DefaultCoreRPC>>,
}

type QueryMethod<RQ, RS> =
    fn(&Platform<DefaultCoreRPC>, RQ, &PlatformVersion) -> Result<QueryValidationResult<RS>, Error>;

impl QueryService {
    /// Creates new QueryService
    pub fn new(platform: Arc<Platform<DefaultCoreRPC>>) -> Self {
        Self { platform }
    }

    async fn handle_blocking_query<RQ, RS>(
        &self,
        request: Request<RQ>,
        query_method: QueryMethod<RQ, RS>,
        endpoint_name: &str,
    ) -> Result<Response<RS>, Status>
    where
        RS: Clone + Send + 'static,
        RQ: Send + 'static,
    {
        let platform = Arc::clone(&self.platform);

        spawn_blocking_task_with_name_if_supported("query", move || {
            let Some(platform_version) = PlatformVersion::get_maybe_current() else {
                return Err(Status::unavailable("platform is not initialized"));
            };

            let mut result = query_method(&platform, request.into_inner(), platform_version)
                .map_err(error_into_status)?;

            if result.is_valid() {
                let response = result
                    .into_data()
                    .map_err(|error| error_into_status(error.into()))?;

                Ok(Response::new(response))
            } else {
                let error = result.errors.swap_remove(0);

                Err(query_error_into_status(error))
            }
        })?
        .instrument(tracing::trace_span!("query", endpoint_name))
        .await
        .map_err(|error| Status::internal(format!("join error: {}", error)))?
    }
}

fn respond_with_unimplemented<RS>(name: &str) -> Result<Response<RS>, Status> {
    tracing::error!("{} endpoint is called but it's not supported", name);

    Err(Status::unimplemented("the endpoint is not supported"))
}

#[async_trait]
impl PlatformService for QueryService {
    async fn broadcast_state_transition(
        &self,
        _request: Request<BroadcastStateTransitionRequest>,
    ) -> Result<Response<BroadcastStateTransitionResponse>, Status> {
        respond_with_unimplemented("broadcast_state_transition")
    }

    async fn get_identity(
        &self,
        request: Request<GetIdentityRequest>,
    ) -> Result<Response<GetIdentityResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_identity,
            "get_identity",
        )
        .await
    }

    async fn get_identities(
        &self,
        request: Request<GetIdentitiesRequest>,
    ) -> Result<Response<GetIdentitiesResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_identities,
            "get_identities",
        )
        .await
    }

    async fn get_identity_keys(
        &self,
        request: Request<GetIdentityKeysRequest>,
    ) -> Result<Response<GetIdentityKeysResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_keys,
            "get_identity_keys",
        )
        .await
    }

    async fn get_identity_nonce(
        &self,
        request: Request<GetIdentityNonceRequest>,
    ) -> Result<Response<GetIdentityNonceResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_identity_nonce,
            "get_identity_nonce",
        )
        .await
    }

    async fn get_identity_contract_nonce(
        &self,
        request: Request<GetIdentityContractNonceRequest>,
    ) -> Result<Response<GetIdentityContractNonceResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_identity_contract_nonce,
            "get_identity_contract_nonce",
        )
        .await
    }

    async fn get_identity_balance(
        &self,
        request: Request<GetIdentityBalanceRequest>,
    ) -> Result<Response<GetIdentityBalanceResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_balance,
            "get_identity_balance",
        )
        .await
    }

    async fn get_identity_balance_and_revision(
        &self,
        request: Request<GetIdentityBalanceAndRevisionRequest>,
    ) -> Result<Response<GetIdentityBalanceAndRevisionResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_balance_and_revision,
            "get_identity_balance_and_revision",
        )
        .await
    }

    async fn get_proofs(
        &self,
        request: Request<GetProofsRequest>,
    ) -> Result<Response<GetProofsResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_proofs,
            "get_proofs",
        )
        .await
    }

    async fn get_data_contract(
        &self,
        request: Request<GetDataContractRequest>,
    ) -> Result<Response<GetDataContractResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_data_contract,
            "get_data_contract",
        )
        .await
    }

    async fn get_data_contract_history(
        &self,
        request: Request<GetDataContractHistoryRequest>,
    ) -> Result<Response<GetDataContractHistoryResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_data_contract_history,
            "get_data_contract_history",
        )
        .await
    }

    async fn get_data_contracts(
        &self,
        request: Request<GetDataContractsRequest>,
    ) -> Result<Response<GetDataContractsResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_data_contracts,
            "get_data_contracts",
        )
        .await
    }

    async fn get_documents(
        &self,
        request: Request<GetDocumentsRequest>,
    ) -> Result<Response<GetDocumentsResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_documents,
            "get_documents",
        )
        .await
    }

    async fn get_identities_by_public_key_hashes(
        &self,
        request: Request<GetIdentitiesByPublicKeyHashesRequest>,
    ) -> Result<Response<GetIdentitiesByPublicKeyHashesResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_identities_by_public_key_hashes,
            "get_identities_by_public_key_hashes",
        )
        .await
    }

    async fn get_identity_by_public_key_hash(
        &self,
        request: Request<GetIdentityByPublicKeyHashRequest>,
    ) -> Result<Response<GetIdentityByPublicKeyHashResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_identity_by_public_key_hash,
            "get_identity_by_public_key_hash",
        )
        .await
    }

    async fn wait_for_state_transition_result(
        &self,
        _request: Request<WaitForStateTransitionResultRequest>,
    ) -> Result<Response<WaitForStateTransitionResultResponse>, Status> {
        respond_with_unimplemented("wait_for_state_transition_result")
    }

    async fn get_consensus_params(
        &self,
        _request: Request<GetConsensusParamsRequest>,
    ) -> Result<Response<GetConsensusParamsResponse>, Status> {
        respond_with_unimplemented("get_consensus_params")
    }

    async fn get_protocol_version_upgrade_state(
        &self,
        request: Request<GetProtocolVersionUpgradeStateRequest>,
    ) -> Result<Response<GetProtocolVersionUpgradeStateResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_version_upgrade_state,
            "get_protocol_version_upgrade_state",
        )
        .await
    }

    async fn get_protocol_version_upgrade_vote_status(
        &self,
        request: Request<GetProtocolVersionUpgradeVoteStatusRequest>,
    ) -> Result<Response<GetProtocolVersionUpgradeVoteStatusResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_version_upgrade_vote_status,
            "get_protocol_version_upgrade_vote_status",
        )
        .await
    }

    async fn get_epochs_info(
        &self,
        request: Request<GetEpochsInfoRequest>,
    ) -> Result<Response<GetEpochsInfoResponse>, Status> {
        self.handle_blocking_query(
            request,
            Platform::<DefaultCoreRPC>::query_epoch_infos,
            "get_epochs_info",
        )
        .await
    }
}

fn query_error_into_status(error: QueryError) -> Status {
    match error {
        QueryError::NotFound(message) => Status::not_found(message),
        QueryError::InvalidArgument(message) => Status::invalid_argument(message),
        QueryError::Query(error) => Status::invalid_argument(error.to_string()),
        _ => {
            tracing::error!("unexpected query error: {:?}", error);

            Status::unknown(error.to_string())
        }
    }
}

fn error_into_status(error: Error) -> Status {
    Status::internal(format!("query: {}", error))
}
