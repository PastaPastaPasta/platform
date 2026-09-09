//! Core certificate proofs authenticate keys before Platform proof verification.
//! HTTP sources supply evidence only; checkpoints are fixed by the application.
use crate::TrustedHttpContextProvider;
use dash_context_provider::{ContextProvider, ContextProviderError};
#[cfg(not(target_arch = "wasm32"))]
use dash_core_proof::MAX_WITNESS;
use dash_core_proof::{
    bootstrap::{self, RecordKind},
    parse_commitment, State,
};
use dpp::{
    dashcore::Network,
    data_contract::TokenConfiguration,
    prelude::{CoreBlockHeight, DataContract, Identifier},
    version::PlatformVersion,
};
use futures_util::{stream, StreamExt};
use lru::LruCache;
use serde::Serialize;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

// Core may need tens of seconds to construct a cold, year-long proof. Allow
// the relay's 60-second generation deadline plus HTTP delivery time.
pub(super) const PROOF_REQUEST_TIMEOUT_MS: u32 = 65_000;

#[derive(Clone)]
pub struct VerifiedHttpContextProvider {
    network: Network,
    anchor: State,
    sources: Arc<Vec<String>>,
    #[cfg(not(target_arch = "wasm32"))]
    client: reqwest::Client,
    cache: Arc<Mutex<Cache>>,
    contracts: TrustedHttpContextProvider,
}
struct Cache {
    keys: LruCache<(u32, [u8; 32]), ([u8; 48], u32)>,
    latest: State,
    endpoints: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofRequest {
    pub checkpoint: String,
    pub height: u32,
    pub quorum_hash: String,
    pub llmq_type: u32,
    pub node_count: u8,
}
fn error(message: impl ToString) -> ContextProviderError {
    ContextProviderError::InvalidQuorum(message.to_string())
}
fn rpc_hash(bytes: &[u8; 32]) -> String {
    hex::encode(bytes.iter().rev().copied().collect::<Vec<_>>())
}

impl VerifiedHttpContextProvider {
    pub fn new(
        network: Network,
        sources: Vec<String>,
        capacity: NonZeroUsize,
    ) -> Result<Self, ContextProviderError> {
        let json =
            match network {
                Network::Mainnet => include_str!("../checkpoints/mainnet.json"),
                Network::Testnet => include_str!("../checkpoints/testnet.json"),
                _ => return Err(ContextProviderError::Config(
                    "No release checkpoint for this network; supply an explicit context provider"
                        .into(),
                )),
            };
        let anchor = serde_json::from_str(json).map_err(error)?;
        Self::with_checkpoint(network, anchor, sources, capacity)
    }

    /// A custom snapshot is application trust configuration, never relay metadata.
    pub fn with_checkpoint(
        network: Network,
        anchor: State,
        mut sources: Vec<String>,
        capacity: NonZeroUsize,
    ) -> Result<Self, ContextProviderError> {
        anchor.validate().map_err(error)?;
        if !matches!(
            (network, anchor.network),
            (Network::Mainnet, 0) | (Network::Testnet, 1)
        ) {
            return Err(ContextProviderError::Config(
                "Checkpoint network mismatch".into(),
            ));
        }
        if sources.is_empty() {
            sources.push(crate::get_quorum_base_url(network, None).map_err(error)?);
            for seed in dash_network_seeds::evo_seeds(network).into_iter().take(8) {
                if let Some(port) = seed.platform_http_port {
                    sources.push(format!(
                        "https://{}",
                        std::net::SocketAddr::new(seed.address.ip(), port)
                    ));
                }
            }
        }
        if sources.len() > 16 {
            return Err(ContextProviderError::Config(
                "At most 16 proof sources".into(),
            ));
        }
        for source in &sources {
            let url = url::Url::parse(source).map_err(error)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(ContextProviderError::Config(
                    "Invalid proof source URL".into(),
                ));
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let client = reqwest::Client::new();
        // This object is used only for local contract/token caches and system
        // contracts. Its HTTP quorum methods are never called by verified mode.
        let contracts = TrustedHttpContextProvider::new(network, None, capacity).map_err(error)?;
        Ok(Self {
            network,
            anchor: anchor.clone(),
            sources: Arc::new(sources),
            #[cfg(not(target_arch = "wasm32"))]
            client,
            cache: Arc::new(Mutex::new(Cache {
                keys: LruCache::new(capacity),
                latest: anchor,
                endpoints: Vec::new(),
            })),
            contracts,
        })
    }

    pub fn verified_state(&self) -> Result<State, ContextProviderError> {
        Ok(self.cache.lock().map_err(error)?.latest.clone())
    }
    pub fn verified_endpoints(&self) -> Result<Vec<String>, ContextProviderError> {
        Ok(self.cache.lock().map_err(error)?.endpoints.clone())
    }
    pub fn add_known_contract(&self, contract: DataContract) {
        self.contracts.add_known_contract(contract);
    }
    pub fn add_known_token_configuration(&self, id: Identifier, config: TokenConfiguration) {
        self.contracts.add_known_token_configuration(id, config);
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn download(
        &self,
        source: &str,
        request: &ProofRequest,
    ) -> Result<Vec<u8>, ContextProviderError> {
        let response = self
            .client
            .post(format!("{}/proofs", source.trim_end_matches('/')))
            .timeout(Duration::from_millis(PROOF_REQUEST_TIMEOUT_MS.into()))
            .json(request)
            .send()
            .await
            .map_err(error)?;
        if !response.status().is_success() {
            return Err(error(format!(
                "Proof source returned {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_WITNESS as u64)
        {
            return Err(error("Proof response too large"));
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(error)?;
            if chunk.len() > MAX_WITNESS - bytes.len() {
                return Err(error("Proof response too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    #[cfg(target_arch = "wasm32")]
    async fn download(
        &self,
        source: &str,
        request: &ProofRequest,
    ) -> Result<Vec<u8>, ContextProviderError> {
        crate::verified_http::download(source, request).await
    }

    /// Network I/O runs here, outside synchronous Platform verification.
    /// `hash` uses Platform/ContextProvider byte order (Core RPC display order).
    /// Erasing this large future keeps every generic SDK query from embedding it.
    pub fn ensure_quorum(
        &self,
        kind: u32,
        hash: [u8; 32],
        minimum: u32,
    ) -> futures_util::future::BoxFuture<'_, Result<(), ContextProviderError>> {
        let future = self.ensure_quorum_inner(kind, hash, minimum);
        // Browser fetch objects belong to their originating JS thread. The SDK's
        // shared async traits require Send; this wrapper checks thread affinity
        // on every poll and drop instead of permitting cross-thread JS access.
        #[cfg(target_arch = "wasm32")]
        {
            Box::pin(send_wrapper::SendWrapper::new(future))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Box::pin(future)
        }
    }

    async fn ensure_quorum_inner(
        &self,
        kind: u32,
        hash: [u8; 32],
        minimum: u32,
    ) -> Result<(), ContextProviderError> {
        if self.get_quorum_public_key(kind, hash, minimum).is_ok() {
            return Ok(());
        }
        let expected = if self.network == Network::Mainnet {
            4
        } else {
            6
        };
        if kind != expected {
            return Err(error("Unexpected Platform quorum type"));
        }
        let latest = self.verified_state()?;
        let mut anchors = vec![latest.clone()];
        if latest != self.anchor {
            anchors.push(self.anchor.clone());
        }
        let mut last = error("No proof sources available");
        for anchor in anchors {
            let request = ProofRequest {
                checkpoint: rpc_hash(&anchor.block_hash),
                height: minimum.max(anchor.height + 1),
                quorum_hash: hex::encode(hash),
                llmq_type: kind,
                node_count: 4,
            };
            let mut sources = self.sources.as_ref().clone();
            for endpoint in self.verified_endpoints()? {
                if sources.len() < 16 && !sources.contains(&endpoint) {
                    sources.push(endpoint);
                }
            }
            let mut downloads = stream::iter(sources.into_iter().map(|source| {
                let request = request.clone();
                async move { self.download(&source, &request).await }
            }))
            .buffer_unordered(3);
            while let Some(result) = downloads.next().await {
                match result.and_then(|bytes| self.accept(&bytes, &anchor, minimum, kind, hash)) {
                    Ok(()) => return Ok(()),
                    Err(e) => last = e,
                }
            }
        }
        Err(last)
    }

    fn accept(
        &self,
        bytes: &[u8],
        anchor: &State,
        minimum: u32,
        kind: u32,
        hash: [u8; 32],
    ) -> Result<(), ContextProviderError> {
        let verified = bootstrap::verify(bytes, anchor, minimum).map_err(error)?;
        let mut key = None;
        let mut endpoints = Vec::new();
        for record in verified.records() {
            match record.kind {
                RecordKind::Quorum => {
                    let commitment = parse_commitment(record.leaf).map_err(error)?;
                    // Commitment serialization uses Core's internal hash order;
                    // ContextProvider and Tenderdash use RPC display order.
                    let mut quorum_hash = commitment.quorum_hash;
                    quorum_hash.reverse();
                    if commitment.kind as u32 == kind
                        && quorum_hash == hash
                        && key.replace(commitment.public_key).is_some()
                    {
                        return Err(error("Duplicate quorum opening"));
                    }
                }
                RecordKind::Masternode => endpoints.extend(decode_endpoints(record.leaf)?),
            }
        }
        let key =
            key.ok_or_else(|| error("Requested quorum missing from authenticated records"))?;
        // Publish only after every record and the requested identity are checked.
        let mut cache = self.cache.lock().map_err(error)?;
        cache.keys.put((kind, hash), (key, verified.state().height));
        if verified.state().height >= cache.latest.height {
            cache.latest = verified.state().clone();
            endpoints.sort();
            endpoints.dedup();
            cache.endpoints = endpoints;
        }
        Ok(())
    }
}

fn decode_endpoints(leaf: &[u8]) -> Result<Vec<String>, ContextProviderError> {
    use dpp::dashcore::sml::masternode_list_entry::net_info::{
        Bip155Network, NetInfoEntry, NetInfoPurpose,
    };
    use dpp::dashcore::{
        consensus::{deserialize, serialize},
        sml::masternode_list_entry::{EntryMasternodeType, MasternodeListEntry, MasternodeNetInfo},
    };
    // The SML hash preimage excludes its version. Accept only an unambiguous,
    // canonical supported decoding; the relay does not get to pick a version.
    let mut decoded = None;
    for version in [2u16, 3] {
        let mut wire = version.to_le_bytes().to_vec();
        wire.extend(leaf);
        if let Ok(entry) = deserialize::<MasternodeListEntry>(&wire) {
            if serialize(&entry) != wire {
                continue;
            }
            if decoded.replace(entry).is_some() {
                return Err(error("Ambiguous masternode serialization"));
            }
        }
    }
    let entry = decoded.ok_or_else(|| error("Unsupported masternode serialization"))?;
    let EntryMasternodeType::HighPerformance {
        platform_http_port, ..
    } = entry.mn_type
    else {
        return Err(error("Record is not an EvoNode"));
    };
    if !entry.is_valid || entry.confirmed_hash.is_none() {
        return Err(error("Ineligible EvoNode record"));
    }
    let mut urls = Vec::new();
    match entry.service_address {
        MasternodeNetInfo::Legacy(address) => {
            if platform_http_port != 0 {
                urls.push(format!(
                    "https://{}",
                    std::net::SocketAddr::new(address.ip(), platform_http_port)
                ));
            }
        }
        MasternodeNetInfo::Extended(info) => {
            for (purpose, entries) in info.purposes {
                if purpose != NetInfoPurpose::PlatformHttps {
                    continue;
                }
                for endpoint in entries {
                    let (host, port) = match endpoint {
                        NetInfoEntry::Service {
                            network: Bip155Network::Ipv4,
                            addr,
                            port,
                        } if addr.len() == 4 => (
                            std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string(),
                            port,
                        ),
                        NetInfoEntry::Service {
                            network: Bip155Network::Ipv6,
                            addr,
                            port,
                        } if addr.len() == 16 => (
                            format!(
                                "[{}]",
                                std::net::Ipv6Addr::from(
                                    <[u8; 16]>::try_from(addr)
                                        .map_err(|_| error("Invalid IPv6 address"))?
                                )
                            ),
                            port,
                        ),
                        NetInfoEntry::Domain { host, port } => (host, port),
                        _ => continue,
                    };
                    if port == 0 {
                        continue;
                    }
                    let mut url = url::Url::parse("https://localhost").map_err(error)?;
                    url.set_host(Some(&host)).map_err(error)?;
                    url.set_port(Some(port))
                        .map_err(|_| error("Invalid endpoint port"))?;
                    urls.push(url.to_string());
                }
            }
        }
    }
    if urls.is_empty() {
        return Err(error("EvoNode has no supported HTTPS endpoint"));
    }
    Ok(urls)
}

impl ContextProvider for VerifiedHttpContextProvider {
    fn get_quorum_public_key(
        &self,
        kind: u32,
        hash: [u8; 32],
        height: u32,
    ) -> Result<[u8; 48], ContextProviderError> {
        if let Some((key, certified)) = self.cache.lock().map_err(error)?.keys.get(&(kind, hash)) {
            if *certified >= height {
                return Ok(*key);
            }
        }
        Err(ContextProviderError::QuorumNotCached {
            quorum_type: kind,
            quorum_hash: hash,
            core_chain_locked_height: height,
        })
    }
    fn get_data_contract(
        &self,
        id: &Identifier,
        version: &PlatformVersion,
    ) -> Result<Option<Arc<DataContract>>, ContextProviderError> {
        self.contracts.get_data_contract(id, version)
    }
    fn register_data_contract(&self, contract: Arc<DataContract>) {
        self.contracts.register_data_contract(contract);
    }
    fn get_token_configuration(
        &self,
        id: &Identifier,
    ) -> Result<Option<TokenConfiguration>, ContextProviderError> {
        self.contracts.get_token_configuration(id)
    }
    fn get_platform_activation_height(&self) -> Result<CoreBlockHeight, ContextProviderError> {
        self.contracts.get_platform_activation_height()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    const ENVELOPE: &[u8] = include_bytes!("../../rs-core-proof/tests/data/bootstrap.bin");
    fn provider() -> VerifiedHttpContextProvider {
        VerifiedHttpContextProvider::new(
            Network::Testnet,
            vec!["http://127.0.0.1:1".into()],
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap()
    }
    fn relay(body: Vec<u8>, declared_size: Option<usize>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = std::io::BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /proofs "));
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            assert!(length <= 1024);
            let mut request = vec![0; length];
            reader.read_exact(&mut request).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request["llmqType"], 6);
            if body == ENVELOPE {
                assert_eq!(
                    request["quorumHash"],
                    "000000a65e119b239f71212edd1c15cc111d349f69ed4138d3b9c49fec2a14f8"
                );
                assert_eq!(
                    request["checkpoint"],
                    "000000a99c2dac4616bca1f27301f1f99684a96102c97ef1d645569c529b55b7"
                );
            }
            let header = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", declared_size.unwrap_or(body.len()));
            socket.write_all(header.as_bytes()).unwrap();
            let _ = socket.write_all(&body);
        });
        (url, server)
    }

    #[tokio::test]
    async fn should_fetch_evidence_and_fail_over_without_trusted_key_requests() {
        let (bad, bad_server) = relay(vec![0; 100], None);
        let (good, good_server) = relay(ENVELOPE.to_vec(), None);
        let provider = VerifiedHttpContextProvider::new(
            Network::Testnet,
            vec![bad, good],
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        let record = bootstrap::verify(ENVELOPE, &provider.anchor, 0).unwrap();
        let commitment = parse_commitment(record.records()[0].leaf).unwrap();
        let platform_hash =
            hex::decode("000000a65e119b239f71212edd1c15cc111d349f69ed4138d3b9c49fec2a14f8")
                .unwrap()
                .try_into()
                .unwrap();
        provider
            .ensure_quorum(6, platform_hash, record.state().height)
            .await
            .unwrap();
        bad_server.join().unwrap();
        good_server.join().unwrap();
        // Both HTTP servers are gone: this must use the authenticated cache.
        provider
            .ensure_quorum(6, platform_hash, record.state().height)
            .await
            .unwrap();
        assert_eq!(
            provider.get_quorum_public_key(6, platform_hash, 0).unwrap(),
            commitment.public_key
        );
    }

    #[tokio::test]
    async fn should_reject_oversize_http_response_without_advancing_state() {
        let (url, server) = relay(Vec::new(), Some(MAX_WITNESS + 1));
        let provider = VerifiedHttpContextProvider::new(
            Network::Testnet,
            vec![url],
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        assert!(provider.ensure_quorum(6, [1; 32], 0).await.is_err());
        assert_eq!(provider.verified_state().unwrap(), provider.anchor);
        assert!(provider.verified_endpoints().unwrap().is_empty());
        server.join().unwrap();
    }

    #[test]
    fn should_publish_only_complete_authenticated_expected_records() {
        let provider = provider();
        let verified = bootstrap::verify(ENVELOPE, &provider.anchor, 0).unwrap();
        let commitment = parse_commitment(verified.records()[0].leaf).unwrap();
        let platform_hash =
            hex::decode("000000a65e119b239f71212edd1c15cc111d349f69ed4138d3b9c49fec2a14f8")
                .unwrap()
                .try_into()
                .unwrap();
        let anchor = provider.verified_state().unwrap();
        let mut corrupt = ENVELOPE.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(provider
            .accept(&corrupt, &anchor, 0, 6, platform_hash)
            .is_err());
        assert_eq!(provider.verified_state().unwrap(), anchor);
        assert!(provider.verified_endpoints().unwrap().is_empty());
        assert!(provider.accept(ENVELOPE, &anchor, 0, 6, [1; 32]).is_err());
        assert!(provider.get_quorum_public_key(6, platform_hash, 0).is_err());
        provider
            .accept(ENVELOPE, &anchor, 0, 6, platform_hash)
            .unwrap();
        assert_eq!(
            provider
                .get_quorum_public_key(6, platform_hash, verified.state().height)
                .unwrap(),
            commitment.public_key
        );
        assert!(provider
            .get_quorum_public_key(6, platform_hash, verified.state().height + 1)
            .is_err());
        assert!(!provider.verified_endpoints().unwrap().is_empty());
    }
    #[test]
    fn should_bind_release_checkpoint_to_network() {
        let provider = provider();
        assert!(VerifiedHttpContextProvider::with_checkpoint(
            Network::Mainnet,
            provider.anchor,
            vec![],
            NonZeroUsize::new(8).unwrap()
        )
        .is_err());
        assert!(VerifiedHttpContextProvider::new(
            Network::Regtest,
            vec![],
            NonZeroUsize::new(8).unwrap()
        )
        .is_err());
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod snapshot_provenance_tests {
    use super::*;
    #[test]
    fn should_match_mainnet_release_snapshot_to_authenticated_coinbase() {
        use dash_core_proof::{coinbase_roots, header_hash, sha256d, MerklePath};
        let evidence: serde_json::Value = serde_json::from_str(include_str!(
            "../../rs-core-proof/tests/data/mainnet-anchor.json"
        ))
        .unwrap();
        let header: Vec<u8> = serde_json::from_value(evidence["header"].clone()).unwrap();
        let header: [u8; 80] = header.try_into().unwrap();
        let coinbase: Vec<u8> = serde_json::from_value(evidence["coinbase"].clone()).unwrap();
        let path: MerklePath = serde_json::from_value(evidence["path"].clone()).unwrap();
        let provider = VerifiedHttpContextProvider::new(
            Network::Mainnet,
            vec!["http://127.0.0.1:1".into()],
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(header_hash(&header), provider.anchor.block_hash);
        assert_eq!(
            rpc_hash(&provider.anchor.block_hash),
            evidence["block_hash"]
        );
        path.verify(sha256d(&coinbase), header[36..68].try_into().unwrap())
            .unwrap();
        let roots = coinbase_roots(&coinbase, provider.anchor.height).unwrap();
        assert_eq!(
            roots,
            (provider.anchor.masternode_root, provider.anchor.quorum_root)
        );
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod browser_tests {
    use super::*;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;
    struct FetchGuard(JsValue);
    impl Drop for FetchGuard {
        fn drop(&mut self) {
            js_sys::Reflect::set(&js_sys::global(), &JsValue::from_str("fetch"), &self.0).unwrap();
        }
    }
    fn mock_fetch(body: &str) -> FetchGuard {
        let global = js_sys::global();
        let key = JsValue::from_str("fetch");
        let guard = FetchGuard(js_sys::Reflect::get(&global, &key).unwrap());
        let replacement = js_sys::Function::new_with_args("request", body);
        js_sys::Reflect::set(&global, &key, replacement.as_ref()).unwrap();
        guard
    }
    #[wasm_bindgen_test]
    async fn verifies_streamed_evidence_and_rejects_unbounded_browser_body() {
        let envelope = include_bytes!("../../rs-core-proof/tests/data/bootstrap.bin");
        let provider = VerifiedHttpContextProvider::new(
            Network::Testnet,
            vec!["https://relay.example".into()],
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        let verified = bootstrap::verify(envelope, &provider.anchor, 0).unwrap();
        let commitment = parse_commitment(verified.records()[0].leaf).unwrap();
        let platform_hash =
            hex::decode("000000a65e119b239f71212edd1c15cc111d349f69ed4138d3b9c49fec2a14f8")
                .unwrap()
                .try_into()
                .unwrap();
        let valid = format!("if (request.method !== 'POST' || !request.url.endsWith('/proofs')) throw Error('unexpected trusted request'); return Promise.resolve(new Response(new Uint8Array({}), {{status:200}}));", serde_json::to_string(envelope.as_slice()).unwrap());
        let guard = mock_fetch(&valid);
        provider
            .ensure_quorum(6, platform_hash, verified.state().height)
            .await
            .unwrap();
        assert_eq!(
            provider.get_quorum_public_key(6, platform_hash, 0).unwrap(),
            commitment.public_key
        );
        drop(guard);
        let fresh = VerifiedHttpContextProvider::new(
            Network::Testnet,
            vec!["https://relay.example".into()],
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        // No Content-Length: the streaming cap must enforce the decoded bound.
        let _guard = mock_fetch("return Promise.resolve(new Response(new ReadableStream({start(c) { c.enqueue(new Uint8Array(1048577)); c.close(); }}))); ");
        assert!(fresh.ensure_quorum(6, platform_hash, 0).await.is_err());
        assert_eq!(fresh.verified_state().unwrap(), fresh.anchor);
    }
}
