//! Browser streaming transport shares wasm-streams 0.5 with the DAPI client.
//! Enabling reqwest 0.12's stream feature on WASM would link a second, incompatible
//! wasm-streams version with duplicate wasm-bindgen exports.
use super::verified::{ProofRequest, PROOF_REQUEST_TIMEOUT_MS};
use dash_context_provider::ContextProviderError;
use dash_core_proof::MAX_WITNESS;
use futures_util::{
    future::{select, Either},
    pin_mut, StreamExt,
};
use wasm_bindgen::{JsCast, JsValue};

fn error(value: impl std::fmt::Debug) -> ContextProviderError {
    ContextProviderError::InvalidQuorum(format!("Proof HTTP request failed: {value:?}"))
}
struct AbortOnDrop(web_sys::AbortController);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn download(
    source: &str,
    payload: &ProofRequest,
) -> Result<Vec<u8>, ContextProviderError> {
    let abort = AbortOnDrop(web_sys::AbortController::new().map_err(error)?);
    let options = web_sys::RequestInit::new();
    options.set_method("POST");
    options.set_signal(Some(&abort.0.signal()));
    options.set_body(&JsValue::from_str(
        &serde_json::to_string(payload).map_err(error)?,
    ));
    let request = web_sys::Request::new_with_str_and_init(
        &format!("{}/proofs", source.trim_end_matches('/')),
        &options,
    )
    .map_err(error)?;
    request
        .headers()
        .set("content-type", "application/json")
        .map_err(error)?;
    // Fetch is available on both Window and WorkerGlobalScope. Reflect also
    // supports browser test hosts without inventing an unsafe Send implementation.
    let global = js_sys::global();
    let fetch: js_sys::Function = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(error)?
        .dyn_into()
        .map_err(error)?;
    let promise: js_sys::Promise = fetch
        .call1(&global, &request)
        .map_err(error)?
        .dyn_into()
        .map_err(error)?;
    let receive = async {
        let response: web_sys::Response = wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(error)?
            .dyn_into()
            .map_err(error)?;
        if !response.ok() {
            return Err(error(response.status()));
        }
        if response
            .headers()
            .get("content-length")
            .map_err(error)?
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|size| size > MAX_WITNESS)
        {
            return Err(error("Proof response too large"));
        }
        let body = response
            .body()
            .ok_or_else(|| error("Missing proof response body"))?;
        let mut stream = wasm_streams::ReadableStream::from_raw(body).into_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk: js_sys::Uint8Array = chunk.map_err(error)?.dyn_into().map_err(error)?;
            let length = chunk.length() as usize;
            if length > MAX_WITNESS - bytes.len() {
                return Err(error("Proof response too large"));
            }
            let start = bytes.len();
            bytes.resize(start + length, 0);
            chunk.copy_to(&mut bytes[start..]);
        }
        Ok(bytes)
    };
    let deadline = gloo_timers::future::TimeoutFuture::new(PROOF_REQUEST_TIMEOUT_MS);
    pin_mut!(receive, deadline);
    match select(receive, deadline).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => Err(error("Proof request timed out")),
    }
}
