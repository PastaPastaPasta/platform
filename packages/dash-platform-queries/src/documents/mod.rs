pub(crate) mod aggregate_limit;
pub(crate) mod average_proof_helpers;
pub(crate) mod count_proof_helpers;
pub mod document_average;
pub mod document_count;
pub mod document_having_entries;
pub mod document_history_query;
pub mod document_query;
pub mod document_ranked_entries;
pub mod document_split_averages;
pub mod document_split_counts;
pub mod document_split_sums;
pub mod document_sum;
pub(crate) mod having_proof_helpers;
/// Shared wire-proto → drive-type decoders for `getDocuments`,
/// used by both rs-drive-abci (server request decode) and
/// [`document_query::DocumentQuery::try_from_request`] (client
/// verification) so the two directions cannot drift.
pub mod proto_conversions;
pub(crate) mod ranked_proof_helpers;
pub(crate) mod sum_proof_helpers;
