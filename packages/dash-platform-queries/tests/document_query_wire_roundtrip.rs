//! Round-trip tests for the wire codec of [`DocumentQuery`]:
//! `DocumentQuery` → [`GetDocumentsRequest`] →
//! [`DocumentQuery::try_from_request`] must reproduce the original
//! query exactly, on both the V0 (CBOR clause) and V1 (typed proto
//! clause) wire encodings — this is what lets an embedder verify a
//! proved response against nothing but the request bytes it sent.

use std::sync::Arc;

use dapi_grpc::platform::v0::get_documents_request::get_documents_request_v0::Start;
use dapi_grpc::platform::v0::get_documents_request::{GetDocumentsRequestV0, Version};
use dapi_grpc::platform::v0::GetDocumentsRequest;
use dash_platform_queries::documents::document_query::DocumentQuery;
use dash_platform_queries::Error;
use dpp::data_contract::accessors::v0::DataContractV0Getters;
use dpp::platform_value::Value;
use dpp::prelude::DataContract;
use dpp::tests::fixtures::get_data_contract_fixture;
use dpp::version::PlatformVersion;
use drive::query::{DriveDocumentQuery, OrderClause, SelectProjection, WhereClause, WhereOperator};

fn test_contract() -> Arc<DataContract> {
    let platform_version = PlatformVersion::latest();
    Arc::new(
        get_data_contract_fixture(None, 0, platform_version.protocol_version).data_contract_owned(),
    )
}

/// A protocol version whose `drive_abci.query.document_query`
/// feature-version is `0` — encodes onto the V0 (CBOR-clause) wire.
fn v0_platform_version() -> &'static PlatformVersion {
    let version = PlatformVersion::get(1).expect("protocol version 1 exists");
    assert_eq!(
        version
            .drive_abci
            .query
            .document_query
            .default_current_version,
        0,
        "protocol version 1 should encode the V0 documents wire"
    );
    version
}

/// The latest protocol version — encodes onto the V1 (typed proto
/// clause) wire.
fn v1_platform_version() -> &'static PlatformVersion {
    let version = PlatformVersion::latest();
    assert_eq!(
        version
            .drive_abci
            .query
            .document_query
            .default_current_version,
        1,
        "latest protocol version should encode the V1 documents wire"
    );
    version
}

fn roundtrip(query: &DocumentQuery, platform_version: &PlatformVersion) -> DocumentQuery {
    let contract = Arc::clone(&query.data_contract);
    let request = query
        .clone()
        .try_into_request_for_version(platform_version)
        .expect("query should encode onto the wire");
    DocumentQuery::try_from_request(request, contract)
        .expect("wire request should decode back into a query")
}

#[test]
fn v1_roundtrip_documents_query_full_surface() {
    let contract = test_contract();
    let mut query = DocumentQuery::new(Arc::clone(&contract), "niceDocument")
        .expect("document type exists")
        .with_where(WhereClause {
            field: "firstName".to_string(),
            operator: WhereOperator::Equal,
            value: Value::Text("Alice".to_string()),
        })
        .with_where(WhereClause {
            field: "age".to_string(),
            operator: WhereOperator::In,
            value: Value::Array(vec![Value::U64(21), Value::U64(42)]),
        })
        .with_where(WhereClause {
            field: "balance".to_string(),
            operator: WhereOperator::GreaterThan,
            value: Value::I64(-5),
        })
        .with_order_by(OrderClause {
            field: "firstName".to_string(),
            ascending: true,
        })
        .with_order_by(OrderClause {
            field: "age".to_string(),
            ascending: false,
        })
        .with_limit(42)
        .with_offset(7);
    query.start = Some(Start::StartAt(vec![1u8; 32]));

    assert_eq!(roundtrip(&query, v1_platform_version()), query);
}

#[test]
fn v1_roundtrip_start_after() {
    let contract = test_contract();
    let mut query = DocumentQuery::new(contract, "niceDocument").expect("document type exists");
    query.start = Some(Start::StartAfter(vec![2u8; 32]));

    assert_eq!(roundtrip(&query, v1_platform_version()), query);
}

#[test]
fn v1_roundtrip_grouped_count() {
    let contract = test_contract();
    let query = DocumentQuery::new(contract, "niceDocument")
        .expect("document type exists")
        .with_select(SelectProjection::count_star())
        .with_group_by("age")
        .with_where(WhereClause {
            field: "age".to_string(),
            operator: WhereOperator::GreaterThanOrEquals,
            value: Value::U64(18),
        })
        .with_limit(5);

    assert_eq!(roundtrip(&query, v1_platform_version()), query);
}

#[test]
fn v0_roundtrip_documents_query() {
    let contract = test_contract();
    let mut query = DocumentQuery::new(Arc::clone(&contract), "niceDocument")
        .expect("document type exists")
        .with_where(WhereClause {
            field: "firstName".to_string(),
            operator: WhereOperator::Equal,
            value: Value::Text("Alice".to_string()),
        })
        .with_where(WhereClause {
            field: "age".to_string(),
            operator: WhereOperator::In,
            value: Value::Array(vec![Value::U64(21), Value::U64(42)]),
        })
        .with_where(WhereClause {
            field: "balance".to_string(),
            operator: WhereOperator::GreaterThan,
            value: Value::I64(-5),
        })
        .with_order_by(OrderClause {
            field: "firstName".to_string(),
            ascending: true,
        })
        .with_order_by(OrderClause {
            field: "age".to_string(),
            ascending: false,
        })
        .with_limit(10);
    query.start = Some(Start::StartAfter(vec![3u8; 32]));

    let request = query
        .clone()
        .try_into_request_for_version(v0_platform_version())
        .expect("query should encode onto the V0 wire");
    assert!(
        matches!(request.version, Some(Version::V0(_))),
        "protocol version 1 must produce the V0 wire shape"
    );
    let decoded = DocumentQuery::try_from_request(request, contract)
        .expect("V0 wire request should decode back into a query");
    assert_eq!(decoded, query);
}

#[test]
fn v0_rejects_malformed_where_cbor() {
    let contract = test_contract();
    let request = GetDocumentsRequest {
        version: Some(Version::V0(GetDocumentsRequestV0 {
            data_contract_id: contract.id().to_vec(),
            document_type: "niceDocument".to_string(),
            r#where: vec![0x9F], // truncated CBOR array
            order_by: vec![],
            limit: 0,
            prove: true,
            start: None,
        })),
    };

    let error = DocumentQuery::try_from_request(request, contract)
        .expect_err("truncated where CBOR must be rejected");
    assert!(
        error.to_string().contains("unable to decode 'where' query"),
        "unexpected error: {error}"
    );
}

#[test]
fn v1_rejects_unknown_where_operator() {
    let contract = test_contract();
    let query = DocumentQuery::new(Arc::clone(&contract), "niceDocument")
        .expect("document type exists")
        .with_where(WhereClause {
            field: "firstName".to_string(),
            operator: WhereOperator::Equal,
            value: Value::Text("Alice".to_string()),
        });
    let mut request = query
        .try_into_request_for_version(v1_platform_version())
        .expect("query should encode onto the wire");
    let Some(Version::V1(request_v1)) = &mut request.version else {
        panic!("expected the V1 wire shape");
    };
    request_v1.where_clauses[0].operator = 99;

    let error = DocumentQuery::try_from_request(request, contract)
        .expect_err("unknown operator discriminant must be rejected");
    assert!(
        error
            .to_string()
            .contains("unknown WhereOperator discriminant: 99"),
        "unexpected error: {error}"
    );
}

#[test]
fn v1_rejects_explicit_zero_limit() {
    let contract = test_contract();
    let query =
        DocumentQuery::new(Arc::clone(&contract), "niceDocument").expect("document type exists");
    let mut request = query
        .try_into_request_for_version(v1_platform_version())
        .expect("query should encode onto the wire");
    let Some(Version::V1(request_v1)) = &mut request.version else {
        panic!("expected the V1 wire shape");
    };
    request_v1.limit = Some(0);

    let error = DocumentQuery::try_from_request(request, contract)
        .expect_err("explicit zero limit must be rejected, mirroring the server");
    assert!(
        error.to_string().contains("limit = 0"),
        "unexpected error: {error}"
    );
}

#[test]
fn v1_rejects_multi_projection_select() {
    let contract = test_contract();
    let query =
        DocumentQuery::new(Arc::clone(&contract), "niceDocument").expect("document type exists");
    let mut request = query
        .try_into_request_for_version(v1_platform_version())
        .expect("query should encode onto the wire");
    let Some(Version::V1(request_v1)) = &mut request.version else {
        panic!("expected the V1 wire shape");
    };
    let extra_select = request_v1.selects[0].clone();
    request_v1.selects.push(extra_select);

    let error = DocumentQuery::try_from_request(request, contract)
        .expect_err("multi-projection SELECT must be rejected");
    assert!(
        error.to_string().contains("multi-projection SELECT"),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_contract_mismatch() {
    let contract = test_contract();
    let query =
        DocumentQuery::new(Arc::clone(&contract), "niceDocument").expect("document type exists");
    let mut request = query
        .try_into_request_for_version(v1_platform_version())
        .expect("query should encode onto the wire");
    let Some(Version::V1(request_v1)) = &mut request.version else {
        panic!("expected the V1 wire shape");
    };
    request_v1.data_contract_id = vec![9u8; 32];

    let error = DocumentQuery::try_from_request(request, contract)
        .expect_err("mismatched contract id must be rejected");
    assert!(
        matches!(error, Error::Protocol(_)),
        "unexpected error: {error}"
    );
    assert!(
        error.to_string().contains("targets data contract"),
        "unexpected error: {error}"
    );
}

/// A `u32` wire limit above `u16::MAX` must be refused, not wrapped.
///
/// `DriveDocumentQuery`'s limit is a `u16`; the server rejects anything
/// larger with `InvalidLimit` and so never proves such a query. An `as`
/// cast would silently turn a request for 65537 documents into a
/// 1-document query, and a proof for *that* query would then verify —
/// binding the proof to something the caller never asked for.
#[test]
fn limit_above_u16_max_is_rejected_not_truncated() {
    let contract = test_contract();
    let query = DocumentQuery::new(contract, "niceDocument")
        .expect("document type exists")
        .with_limit(u16::MAX as u32 + 2);

    let error = DriveDocumentQuery::try_from(&query)
        .expect_err("a limit above u16::MAX must not be silently truncated");
    assert!(
        error.to_string().contains("65537"),
        "unexpected error: {error}"
    );
}

/// Request-shape checks in [`verify_documents_response`].
///
/// Every field asserted here is dropped by the `DocumentQuery` →
/// `DriveDocumentQuery` lowering, so without an explicit rejection an
/// untrusted transport could pair a request the real server would have
/// refused with a genuine proof for the narrower query it lowers to.
///
/// The provider panics on every call, which also pins *when* the
/// rejection happens: before any proof machinery runs.
mod verify_binds_the_whole_request {
    use super::*;
    use dapi_grpc::platform::v0::GetDocumentsResponse;
    use dash_context_provider::{ContextProvider, ContextProviderError};
    use dash_platform_queries::documents::document_query::verify_documents_response;
    use dpp::dashcore::Network;
    use dpp::data_contract::associated_token::token_configuration::TokenConfiguration;
    use dpp::prelude::{CoreBlockHeight, Identifier};
    use drive::query::{
        HavingAggregate, HavingAggregateFunction, HavingClause, HavingOperator, HavingRightOperand,
    };

    /// Fails the test if proof verification is reached at all.
    struct NeverCalledProvider;

    impl ContextProvider for NeverCalledProvider {
        fn get_data_contract(
            &self,
            _id: &Identifier,
            _platform_version: &PlatformVersion,
        ) -> Result<Option<Arc<DataContract>>, ContextProviderError> {
            panic!("request must be rejected before proof verification starts")
        }

        fn get_token_configuration(
            &self,
            _token_id: &Identifier,
        ) -> Result<Option<TokenConfiguration>, ContextProviderError> {
            panic!("request must be rejected before proof verification starts")
        }

        fn get_quorum_public_key(
            &self,
            _quorum_type: u32,
            _quorum_hash: [u8; 32],
            _core_chain_locked_height: u32,
        ) -> Result<[u8; 48], ContextProviderError> {
            panic!("request must be rejected before proof verification starts")
        }

        fn get_platform_activation_height(&self) -> Result<CoreBlockHeight, ContextProviderError> {
            panic!("request must be rejected before proof verification starts")
        }
    }

    /// Encode `query` onto the V1 wire, let `mutate` reshape the request
    /// the way a hostile transport could, and return the rejection.
    fn verify_error(
        query: DocumentQuery,
        mutate: impl FnOnce(&mut GetDocumentsRequest),
    ) -> drive_proof_verifier::Error {
        let contract = Arc::clone(&query.data_contract);
        let mut request = query
            .try_into_request_for_version(v1_platform_version())
            .expect("query should encode onto the wire");
        mutate(&mut request);

        verify_documents_response(
            request,
            contract,
            GetDocumentsResponse::default(),
            Network::Testnet,
            PlatformVersion::latest(),
            &NeverCalledProvider,
        )
        .expect_err("the reshaped request must be rejected")
    }

    fn documents_query() -> DocumentQuery {
        DocumentQuery::new(test_contract(), "niceDocument").expect("document type exists")
    }

    /// The server refuses GROUP BY under SELECT DOCUMENTS
    /// (`validate_and_route`), so no proved document response can
    /// belong to such a request.
    #[test]
    fn rejects_group_by() {
        let error = verify_error(documents_query().with_group_by("age"), |_| {});
        assert!(
            error.to_string().contains("GROUP BY"),
            "unexpected error: {error}"
        );
    }

    /// The server refuses a non-empty HAVING for any non-aggregate
    /// SELECT (`validate_and_route`).
    #[test]
    fn rejects_having() {
        let query = documents_query().with_having(vec![HavingClause {
            aggregate: HavingAggregate {
                function: HavingAggregateFunction::Count,
                field: String::new(),
            },
            operator: HavingOperator::GreaterThan,
            right: HavingRightOperand::Value(Value::U64(0)),
        }]);
        let error = verify_error(query, |_| {});
        assert!(
            error.to_string().contains("HAVING"),
            "unexpected error: {error}"
        );
    }

    /// The server accepts OFFSET only on the ranked surface
    /// (`reject_offset_off_the_ranked_path`); a document fetch never
    /// routes there.
    #[test]
    fn rejects_offset() {
        let error = verify_error(documents_query().with_offset(7), |_| {});
        assert!(
            error.to_string().contains("OFFSET"),
            "unexpected error: {error}"
        );
    }

    /// `prove: false` makes an honest server answer without a proof, so
    /// a proved response cannot belong to such a request.
    #[test]
    fn rejects_unproved_request() {
        let error = verify_error(documents_query(), |request| {
            let Some(Version::V1(v1)) = &mut request.version else {
                panic!("expected the V1 wire shape");
            };
            v1.prove = false;
        });
        assert!(
            error.to_string().contains("prove=false"),
            "unexpected error: {error}"
        );
    }

    /// An aggregate projection is proved with a different proof shape;
    /// the pre-existing guard stays alongside the new ones.
    #[test]
    fn rejects_aggregate_projection() {
        let error = verify_error(
            documents_query().with_select(SelectProjection::count_star()),
            |_| {},
        );
        assert!(
            error.to_string().contains("plain document fetches"),
            "unexpected error: {error}"
        );
    }
}
