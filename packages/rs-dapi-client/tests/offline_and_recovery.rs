//! Regression coverage for local-offline handling and all-banned recovery.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{FakeResponse, ScriptedRequest};
use dapi_grpc::tonic::{Code, Status};
use rs_dapi_client::transport::TransportError;
use rs_dapi_client::{
    Address, AddressList, DapiClient, DapiClientError, DapiRequestExecutor, RequestSettings,
};

fn offline_error() -> TransportError {
    let mut status = Status::unavailable("connect failed");
    status.set_source(Arc::new(std::io::Error::new(
        std::io::ErrorKind::NetworkUnreachable,
        "offline",
    )));
    TransportError::Grpc(status)
}

fn fully_banned_address_list() -> AddressList {
    let mut address_list = AddressList::new();
    for uri in ["http://127.0.0.1:10101", "http://127.0.0.1:10102"] {
        let address: Address = uri.parse().expect("valid address");
        address_list.add(address.clone());
        address_list.ban_for(
            &address,
            Duration::from_secs(600),
            Some("pre-existing ban".into()),
        );
    }
    address_list
}

#[tokio::test]
async fn offline_failures_do_not_ban_live_addresses() {
    let settings = RequestSettings {
        retries: Some(2),
        ..Default::default()
    };
    let request = ScriptedRequest::new(|_uri| Err(offline_error()));
    let address_list: AddressList = "http://127.0.0.1:10103,http://127.0.0.1:10104"
        .parse()
        .expect("valid address list");
    let client = DapiClient::new(address_list, settings);

    let error = client
        .execute(request.clone(), settings)
        .await
        .expect_err("offline request should fail after exhausting its retry budget");

    assert_eq!(request.hit_uris.lock().unwrap().len(), 3);
    assert_eq!(client.get_live_addresses().len(), 2);
    match error.inner {
        DapiClientError::Transport(TransportError::Grpc(status)) => {
            assert_eq!(status.code(), Code::Unavailable)
        }
        other => panic!("expected raw Transport(Grpc(Unavailable)), got: {other:?}"),
    }
}

#[tokio::test]
async fn all_banned_list_recovers_after_successful_probe() {
    let request = ScriptedRequest::new(|_uri| Ok(FakeResponse));
    let client = DapiClient::new(fully_banned_address_list(), RequestSettings::default());

    let response = client
        .execute(request.clone(), RequestSettings::default())
        .await
        .expect("one banned address should be probed successfully");

    assert_eq!(request.hit_uris.lock().unwrap().len(), 1);
    assert_eq!(response.retries, 0);
    assert!(
        !client.address_list().is_banned(&response.address),
        "successful recovery probe should unban the selected address"
    );
}

#[tokio::test]
async fn failed_remote_probe_returns_exhausted_error_after_one_hit() {
    let request =
        ScriptedRequest::new(|_uri| Err(TransportError::Grpc(Status::unavailable("node down"))));
    let client = DapiClient::new(fully_banned_address_list(), RequestSettings::default());

    let error = client
        .execute(request.clone(), RequestSettings::default())
        .await
        .expect_err("failed recovery probe should leave the list exhausted");

    let hit_uris = request.hit_uris.lock().unwrap();
    assert_eq!(hit_uris.len(), 1);
    let probed = Address::try_from(hit_uris[0].clone()).expect("valid probed address");
    assert!(client.address_list().is_banned(&probed));
    match error.inner {
        DapiClientError::NoAvailableAddressesToRetry(transport_error) => {
            let TransportError::Grpc(status) = *transport_error;
            assert_eq!(status.code(), Code::Unavailable);
        }
        other => panic!("expected NoAvailableAddressesToRetry, got: {other:?}"),
    }
}

#[tokio::test]
async fn failed_offline_probe_does_not_rebase_existing_ban() {
    let request = ScriptedRequest::new(|_uri| Err(offline_error()));
    let client = DapiClient::new(fully_banned_address_list(), RequestSettings::default());
    let before = client.address_list().ban_info();

    let error = client
        .execute(request.clone(), RequestSettings::default())
        .await
        .expect_err("offline recovery probe should leave the list exhausted");

    let hit_uris = request.hit_uris.lock().unwrap();
    assert_eq!(hit_uris.len(), 1);
    let probed_uri = hit_uris[0].to_string();
    let before_probe = before
        .iter()
        .find(|info| info.uri == probed_uri)
        .expect("probed address existed before execution");
    let after = client.address_list().ban_info();
    let after_probe = after
        .iter()
        .find(|info| info.uri == probed_uri)
        .expect("probed address still exists after execution");

    assert_eq!(after_probe.banned_until, before_probe.banned_until);
    assert_eq!(after_probe.ban_count, before_probe.ban_count);
    assert_eq!(after_probe.reason, before_probe.reason);
    match error.inner {
        DapiClientError::NoAvailableAddressesToRetry(transport_error) => {
            let TransportError::Grpc(status) = *transport_error;
            assert_eq!(status.code(), Code::Unavailable);
        }
        other => panic!("expected NoAvailableAddressesToRetry, got: {other:?}"),
    }
}
