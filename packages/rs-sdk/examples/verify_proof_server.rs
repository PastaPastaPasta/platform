//! Exercise a running Core proof relay through the SDK, without trusted quorum HTTP lookups.
use clap::{Parser, Subcommand};
use dash_context_provider::ContextProvider;
use dash_sdk::{platform::fetch_current_no_parameters::FetchCurrent, SdkBuilder};
use dpp::{block::extended_epoch_info::ExtendedEpochInfo, dashcore::Network};
use rs_sdk_trusted_context_provider::VerifiedHttpContextProvider;
use std::{num::NonZeroUsize, path::PathBuf, time::Instant};

#[derive(Parser)]
struct Args {
    #[arg(long, value_parser = ["mainnet", "testnet"])]
    network: String,
    /// Base URL of the running quorum server (or a test proxy in front of it).
    #[arg(long)]
    source: String,
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Fetch and verify a Core bootstrap, comparing its key to independent test evidence.
    Quorum {
        #[arg(long)]
        quorum_hash: String,
        #[arg(long)]
        height: u32,
        #[arg(long)]
        expected_key: String,
        /// Optional independently prepared checkpoint JSON, for historical range tests.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Require rejection containing this text and no published key/state/endpoints.
        #[arg(long)]
        expect_error: Option<String>,
    },
    /// Fetch a live Platform epoch with the default verified SDK context provider.
    Platform {
        /// Optional DAPI URL; otherwise use the SDK's network seeds.
        #[arg(long)]
        address: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let network = if args.network == "mainnet" {
        Network::Mainnet
    } else {
        Network::Testnet
    };
    let start = Instant::now();
    match args.mode {
        Mode::Quorum {
            quorum_hash,
            height,
            expected_key,
            checkpoint,
            expect_error,
        } => {
            let capacity = NonZeroUsize::new(100).unwrap();
            let sources = vec![args.source];
            let provider = if let Some(path) = checkpoint {
                VerifiedHttpContextProvider::with_checkpoint(
                    network,
                    serde_json::from_slice(&std::fs::read(path)?)?,
                    sources,
                    capacity,
                )?
            } else {
                VerifiedHttpContextProvider::new(network, sources, capacity)?
            };
            let hash: [u8; 32] = hex::decode(&quorum_hash)?
                .try_into()
                .map_err(|_| "quorum hash must be 32 bytes")?;
            let kind = if network == Network::Mainnet { 4 } else { 6 };
            let before = provider.verified_state()?;
            assert!(provider.get_quorum_public_key(kind, hash, height).is_err());
            let result = provider.ensure_quorum(kind, hash, height).await;
            if let Some(expected) = expect_error {
                let error = result
                    .expect_err("invalid evidence was accepted")
                    .to_string();
                assert!(error.contains(&expected), "unexpected failure: {error}");
                assert_eq!(provider.verified_state()?, before);
                assert!(provider.verified_endpoints()?.is_empty());
                assert!(provider.get_quorum_public_key(kind, hash, height).is_err());
                println!(
                    "{}",
                    serde_json::json!({"rejected": error, "state_unchanged": true})
                );
            } else {
                result?;
                let key = provider.get_quorum_public_key(kind, hash, height)?;
                assert_eq!(hex::encode(key), expected_key.to_lowercase());
                let endpoints = provider.verified_endpoints()?;
                assert!(!endpoints.is_empty());
                println!(
                    "{}",
                    serde_json::json!({
                        "verified": true, "seconds": start.elapsed().as_secs_f64(),
                        "state": provider.verified_state()?, "quorum_hash": quorum_hash,
                        "public_key": hex::encode(key), "endpoints": endpoints,
                    })
                );
            }
        }
        Mode::Platform { address } => {
            let builder = if let Some(address) = address {
                SdkBuilder::new(address.parse()?).with_network(network)
            } else if network == Network::Mainnet {
                SdkBuilder::new_mainnet()
            } else {
                SdkBuilder::new_testnet()
            };
            // Do not install a custom/trusted provider or disable proof/freshness checks.
            let sdk = builder.with_proof_sources(vec![args.source]).build()?;
            let (epoch, metadata, proof) =
                ExtendedEpochInfo::fetch_current_with_metadata_and_proof(&sdk).await?;
            println!(
                "{}",
                serde_json::json!({
                    "verified": true, "seconds": start.elapsed().as_secs_f64(),
                    "epoch": format!("{epoch:?}"), "metadata": format!("{metadata:?}"),
                    "platform_proof_bytes": proof.grovedb_proof.len(),
                    "quorum_hash": hex::encode(proof.quorum_hash),
                })
            );
        }
    }
    Ok(())
}
