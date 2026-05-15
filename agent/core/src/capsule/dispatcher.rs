//! CIT-AGENT-9c-1-rpc — eth_call dispatcher trait + concrete
//! implementation backed by `citrate-wallet-core::RpcClient`.
//!
//! The host fn for `citrate:chain/eth-call` calls into this trait
//! when the canned-queue fixture is empty AND a dispatcher is
//! configured on the `HostCtx`. The trait is sync; the production
//! impl wraps the async `RpcClient` via `tokio::task::block_in_place`
//! + `Handle::block_on`. Same pattern as CIT-AGENT-7b's
//! `AnchorReconciliationCheck`.
//!
//! Why sync trait + internal block_in_place rather than async?
//! `wasmtime::component::Linker::instance(...).func_wrap` is the
//! synchronous host-fn registration path; switching to
//! `func_wrap_async` would require also switching the engine to
//! `async_support = true` and the instantiate calls to
//! `instantiate_async`, cascading through Capsule::instantiate +
//! every test that uses it. Keeping the sync surface + blocking
//! internally is the smaller, more auditable change.

use crate::capsule::wasm::Address;
use citrate_wallet_core::chain::RpcClient;
use std::sync::Arc;

/// A pluggable dispatcher for the `citrate:chain/eth-call` host
/// function. The host fn calls `eth_call(to, data)` when the
/// in-memory canned-queue test fixture is empty + a dispatcher is
/// present in the HostCtx.
///
/// Implementations MUST be `Send + Sync` so the `Linker::func_wrap`
/// closure can capture a clone of the trait object.
pub trait EthCallDispatcher: Send + Sync {
    /// Read-only chain call. Implementations dispatch to the
    /// underlying chain endpoint and return the raw return bytes
    /// on success, or a forensically-useful error string on
    /// failure. The host fn surfaces the error to the capsule
    /// through the WIT `result<list<u8>, string>` return type.
    fn eth_call(&self, to: &Address, data: &[u8]) -> Result<Vec<u8>, String>;
}

/// Production `EthCallDispatcher` backed by an async
/// `citrate-wallet-core::RpcClient`. The dispatcher bridges the
/// sync host-fn surface to the async RPC client via
/// `tokio::task::block_in_place` + the current runtime's
/// `Handle::block_on`.
///
/// REQUIREMENT: the host fn call must occur on a thread inside a
/// multi-threaded tokio runtime. The agent harness's main loop
/// satisfies this; the doctor CLI uses `spawn_blocking` for the
/// same reason; tests use `#[tokio::test(flavor = "multi_thread")]`.
pub struct RpcEthCallDispatcher {
    client: Arc<RpcClient>,
}

impl RpcEthCallDispatcher {
    pub fn new(client: Arc<RpcClient>) -> Self {
        Self { client }
    }

    pub fn from_url(rpc_url: impl AsRef<str>) -> Self {
        Self {
            client: Arc::new(RpcClient::new(rpc_url.as_ref())),
        }
    }
}

impl EthCallDispatcher for RpcEthCallDispatcher {
    fn eth_call(&self, to: &Address, data: &[u8]) -> Result<Vec<u8>, String> {
        let to_hex = format!("0x{}", hex::encode(to));
        let data_vec = data.to_vec();
        let client = self.client.clone();
        // block_in_place yields to the tokio scheduler so other
        // tasks can run while we await the RPC. Requires a
        // multi-threaded runtime context.
        tokio::task::block_in_place(move || {
            let handle = tokio::runtime::Handle::current();
            handle
                .block_on(async move { client.eth_call(&to_hex, &data_vec).await })
                .map_err(|e| format!("eth_call RPC: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test dispatcher that records every call + returns a fixed
    /// response. Used by 9c-1-rpc's integration test to prove the
    /// trait-based path works without standing up an RPC server.
    pub struct MockDispatcher {
        pub calls: Mutex<Vec<(Address, Vec<u8>)>>,
        pub response: Vec<u8>,
    }

    impl MockDispatcher {
        pub fn new(response: Vec<u8>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                response,
            }
        }
    }

    impl EthCallDispatcher for MockDispatcher {
        fn eth_call(&self, to: &Address, data: &[u8]) -> Result<Vec<u8>, String> {
            self.calls
                .lock()
                .expect("dispatcher mutex not poisoned")
                .push((*to, data.to_vec()));
            Ok(self.response.clone())
        }
    }

    #[test]
    fn mock_dispatcher_records_and_returns() {
        let mock = MockDispatcher::new(vec![1, 2, 3]);
        let to = [0xabu8; 20];
        let result = mock.eth_call(&to, &[0xde, 0xad]).unwrap();
        assert_eq!(result, vec![1, 2, 3]);
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, to);
        assert_eq!(calls[0].1, vec![0xde, 0xad]);
    }
}
