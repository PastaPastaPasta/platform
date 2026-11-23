//! A `PlatformWallet` handle can outlive its wallet's registration in the
//! shared `WalletManager` (the wallet is closed while a caller still holds the
//! handle). Every state guard and every entry point that reads through one
//! must then fail with `WalletNotFound` rather than panic.

use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use tokio::task::block_in_place;

use crate::error::PlatformWalletError;
use crate::test_support::funded_platform_wallet;
use crate::wallet::platform_wallet::PlatformWallet;
use crate::wallet::provider_key_at_index::ProviderKeyKind;

async fn close(wallet: &PlatformWallet) {
    wallet
        .wallet_manager()
        .write()
        .await
        .remove_wallet(&wallet.wallet_id())
        .expect("wallet was registered");
}

#[track_caller]
fn assert_wallet_not_found<T>(wallet: &PlatformWallet, result: Result<T, PlatformWalletError>) {
    match result {
        Err(PlatformWalletError::WalletNotFound(id)) => {
            assert_eq!(id, hex::encode(wallet.wallet_id()))
        }
        Err(other) => panic!("expected WalletNotFound, got {other:?}"),
        Ok(_) => panic!("expected WalletNotFound, got Ok"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn derive_provider_key_at_index_after_close_is_wallet_not_found() {
    let wallet = funded_platform_wallet().await;
    for (kind, include_private) in [
        (ProviderKeyKind::Owner, false),
        (ProviderKeyKind::Voting, true),
        (ProviderKeyKind::Operator, false),
        (ProviderKeyKind::PlatformNode, false),
    ] {
        block_in_place(|| wallet.derive_provider_key_at_index(kind, 0, None, include_private))
            .expect("derives while registered");
    }

    close(&wallet).await;

    for (kind, include_private) in [
        (ProviderKeyKind::Owner, false),
        (ProviderKeyKind::Voting, true),
        (ProviderKeyKind::Operator, false),
        (ProviderKeyKind::PlatformNode, false),
    ] {
        let result =
            block_in_place(|| wallet.derive_provider_key_at_index(kind, 0, None, include_private));
        assert_wallet_not_found(&wallet, result);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn derive_core_address_private_key_after_close_is_wallet_not_found() {
    let wallet = funded_platform_wallet().await;
    let address = wallet
        .wallet_manager()
        .read()
        .await
        .get_wallet_info(&wallet.wallet_id())
        .expect("wallet registered")
        .core_wallet
        .monitored_addresses()
        .first()
        .expect("wallet tracks an address")
        .to_string();
    block_in_place(|| wallet.derive_core_address_private_key(&address, None))
        .expect("derives while registered");

    close(&wallet).await;

    let result = block_in_place(|| wallet.derive_core_address_private_key(&address, None));
    assert_wallet_not_found(&wallet, result);
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_constructors_after_close_are_wallet_not_found() {
    let wallet = funded_platform_wallet().await;
    wallet.checked_state().await.expect("registered");
    wallet.checked_state_mut().await.expect("registered");
    block_in_place(|| wallet.state_blocking().map(|_| ())).expect("registered");
    block_in_place(|| wallet.state_mut_blocking().map(|_| ())).expect("registered");
    assert!(wallet.try_state().expect("registered").is_some());
    assert!(wallet.try_state_mut().expect("registered").is_some());

    close(&wallet).await;

    assert_wallet_not_found(&wallet, wallet.checked_state().await);
    assert_wallet_not_found(&wallet, wallet.checked_state_mut().await);
    assert_wallet_not_found(
        &wallet,
        block_in_place(|| wallet.state_blocking().map(|_| ())),
    );
    assert_wallet_not_found(
        &wallet,
        block_in_place(|| wallet.state_mut_blocking().map(|_| ())),
    );
    assert_wallet_not_found(&wallet, wallet.try_state());
    assert_wallet_not_found(&wallet, wallet.try_state_mut());
}

#[tokio::test]
async fn try_state_under_contention_is_none_not_an_error() {
    let wallet = funded_platform_wallet().await;
    let _writer = wallet.wallet_manager().write().await;
    assert!(wallet.try_state().expect("registered").is_none());
    assert!(wallet.try_state_mut().expect("registered").is_none());
}

#[tokio::test]
#[should_panic(expected = "use checked_state")]
async fn infallible_state_after_close_panics_at_construction() {
    let wallet = funded_platform_wallet().await;
    close(&wallet).await;
    let _ = wallet.state().await;
}

#[tokio::test]
#[should_panic(expected = "use checked_state_mut")]
async fn infallible_state_mut_after_close_panics_at_construction() {
    let wallet = funded_platform_wallet().await;
    close(&wallet).await;
    let _ = wallet.state_mut().await;
}
