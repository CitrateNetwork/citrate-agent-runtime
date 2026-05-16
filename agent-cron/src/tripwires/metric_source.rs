//! BFR-INT-poam-B / WP-1 — `MetricSource` + `ChainQuery` traits.
//!
//! Abstractions for the two data sources every tripwire job needs:
//!
//! - `MetricSource` — scalar values from Prometheus or process
//!   internals.
//! - `ChainQuery` — recent block + event-log queries against a
//!   JSON-RPC endpoint.
//!
//! Production impls use HTTP (reqwest); tests use in-memory
//! `MockMetricSource` / `MockChainQuery` so the 9 job tests don't
//! need a running Prometheus or RPC.

use async_trait::async_trait;

/// Async source of scalar metric values.
#[async_trait]
pub trait MetricSource: Send + Sync {
    /// Read a single scalar metric. Returns `None` if the metric
    /// doesn't exist (treat as "no breach"). Returns
    /// `Some(Err(reason))` on transport / parse failure.
    async fn read_scalar(&self, name: &str) -> Option<Result<f64, String>>;
}

/// One on-chain event log entry — the minimum shape every chain-
/// correlation tripwire needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEvent {
    /// `0x`-prefixed hex of the contract that emitted the event.
    pub contract_addr: String,
    /// Event signature topic0 — `keccak256(EventName(arg1,...))`.
    pub topic0: [u8; 32],
    /// Additional indexed topic args. Empty for events with no
    /// indexed params.
    pub indexed_topics: Vec<[u8; 32]>,
    /// Unindexed data bytes (concatenated).
    pub data: Vec<u8>,
    /// Block number this event was emitted in.
    pub block_number: u64,
}

/// Async chain-state query surface.
#[async_trait]
pub trait ChainQuery: Send + Sync {
    /// Current block height.
    async fn block_number(&self) -> Result<u64, String>;

    /// Fetch event logs for a contract within a block range,
    /// optionally filtered by topic0. Caller is responsible for
    /// keeping ranges bounded; production impl should cap the
    /// range at ~10k blocks per call.
    async fn get_logs(
        &self,
        contract_addr: &str,
        from_block: u64,
        to_block: u64,
        topic0: Option<[u8; 32]>,
    ) -> Result<Vec<ChainEvent>, String>;
}

// ── Production HTTP-backed impls ─────────────────────────────────

/// `MetricSource` backed by a Prometheus HTTP API endpoint.
/// Queries `/api/v1/query?query=<name>` and parses the first
/// vector sample's value.
pub struct PrometheusHttpSource {
    base_url: String,
    client: reqwest::Client,
}

impl PrometheusHttpSource {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
        }
    }
}

#[async_trait]
impl MetricSource for PrometheusHttpSource {
    async fn read_scalar(&self, name: &str) -> Option<Result<f64, String>> {
        let url = format!(
            "{}/api/v1/query?query={}",
            self.base_url.trim_end_matches('/'),
            urlencode(name),
        );
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return Some(Err(format!("prom request: {e}"))),
        };
        if !resp.status().is_success() {
            return Some(Err(format!("prom status: {}", resp.status())));
        }
        let json: serde_json::Value = match resp.json().await {
            Ok(j) => j,
            Err(e) => return Some(Err(format!("prom parse: {e}"))),
        };
        // result is an array; we want first sample's value at [1]
        let result = json
            .pointer("/data/result/0/value/1")
            .and_then(|v| v.as_str())?;
        match result.parse::<f64>() {
            Ok(f) => Some(Ok(f)),
            Err(e) => Some(Err(format!("prom value parse: {e}"))),
        }
    }
}

fn urlencode(s: &str) -> String {
    // Minimal percent-encoding for Prometheus query names. The
    // values we query are alphanumeric + underscore + braces +
    // quotes for label selectors; encode the small set that
    // matters for HTTP transport.
    s.chars()
        .flat_map(|c| match c {
            ' ' => "%20".chars().collect::<Vec<_>>(),
            '"' => "%22".chars().collect::<Vec<_>>(),
            '{' => "%7B".chars().collect::<Vec<_>>(),
            '}' => "%7D".chars().collect::<Vec<_>>(),
            '=' => "%3D".chars().collect::<Vec<_>>(),
            ',' => "%2C".chars().collect::<Vec<_>>(),
            c => vec![c],
        })
        .collect()
}

/// `ChainQuery` backed by a JSON-RPC endpoint via `eth_blockNumber`
/// and `eth_getLogs`.
pub struct EthLogsSource {
    rpc_url: String,
    client: reqwest::Client,
}

impl EthLogsSource {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }
}

#[async_trait]
impl ChainQuery for EthLogsSource {
    async fn block_number(&self) -> Result<u64, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        });
        let resp: serde_json::Value = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("blockNumber send: {e}"))?
            .json()
            .await
            .map_err(|e| format!("blockNumber parse: {e}"))?;
        let hex = resp
            .pointer("/result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "blockNumber: missing result".to_string())?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map_err(|e| format!("blockNumber hex: {e}"))
    }

    async fn get_logs(
        &self,
        contract_addr: &str,
        from_block: u64,
        to_block: u64,
        topic0: Option<[u8; 32]>,
    ) -> Result<Vec<ChainEvent>, String> {
        let mut params = serde_json::json!({
            "address": contract_addr,
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock":   format!("0x{:x}", to_block),
        });
        if let Some(t0) = topic0 {
            params["topics"] =
                serde_json::json!([format!("0x{}", hex::encode(t0))]);
        }
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [params],
            "id": 1
        });
        let resp: serde_json::Value = self
            .client
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("getLogs send: {e}"))?
            .json()
            .await
            .map_err(|e| format!("getLogs parse: {e}"))?;
        let result = resp
            .pointer("/result")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "getLogs: missing result".to_string())?;
        let mut out = Vec::with_capacity(result.len());
        for entry in result {
            let addr = entry
                .get("address")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let topics: Vec<String> = entry
                .get("topics")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let topic0 = topics
                .first()
                .and_then(|s| parse_bytes32(s).ok())
                .unwrap_or([0u8; 32]);
            let indexed_topics: Vec<[u8; 32]> = topics
                .iter()
                .skip(1)
                .filter_map(|s| parse_bytes32(s).ok())
                .collect();
            let data_hex = entry
                .get("data")
                .and_then(|v| v.as_str())
                .unwrap_or("0x");
            let data = hex::decode(data_hex.trim_start_matches("0x"))
                .unwrap_or_default();
            let block_hex = entry
                .get("blockNumber")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0");
            let block_number = u64::from_str_radix(
                block_hex.trim_start_matches("0x"),
                16,
            )
            .unwrap_or(0);
            out.push(ChainEvent {
                contract_addr: addr,
                topic0,
                indexed_topics,
                data,
                block_number,
            });
        }
        Ok(out)
    }
}

fn parse_bytes32(hex_in: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_in.trim_start_matches("0x"))
        .map_err(|e| format!("hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("bytes32 len {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ── Test impls ───────────────────────────────────────────────────

#[cfg(test)]
pub struct MockMetricSource {
    pub values: std::collections::HashMap<String, Result<f64, String>>,
}

#[cfg(test)]
impl MockMetricSource {
    pub fn new() -> Self {
        Self {
            values: std::collections::HashMap::new(),
        }
    }

    pub fn with(mut self, name: &str, value: f64) -> Self {
        self.values.insert(name.to_string(), Ok(value));
        self
    }

    pub fn with_err(mut self, name: &str, err: &str) -> Self {
        self.values
            .insert(name.to_string(), Err(err.to_string()));
        self
    }
}

#[cfg(test)]
#[async_trait]
impl MetricSource for MockMetricSource {
    async fn read_scalar(&self, name: &str) -> Option<Result<f64, String>> {
        self.values.get(name).cloned()
    }
}

#[cfg(test)]
pub struct MockChainQuery {
    pub block: u64,
    pub events: Vec<ChainEvent>,
}

#[cfg(test)]
impl MockChainQuery {
    pub fn new(block: u64) -> Self {
        Self {
            block,
            events: Vec::new(),
        }
    }

    pub fn with_events(mut self, events: Vec<ChainEvent>) -> Self {
        self.events = events;
        self
    }
}

#[cfg(test)]
#[async_trait]
impl ChainQuery for MockChainQuery {
    async fn block_number(&self) -> Result<u64, String> {
        Ok(self.block)
    }

    async fn get_logs(
        &self,
        contract_addr: &str,
        from_block: u64,
        to_block: u64,
        topic0: Option<[u8; 32]>,
    ) -> Result<Vec<ChainEvent>, String> {
        Ok(self
            .events
            .iter()
            .filter(|e| {
                e.contract_addr.eq_ignore_ascii_case(contract_addr)
                    && e.block_number >= from_block
                    && e.block_number <= to_block
                    && topic0.map_or(true, |t| e.topic0 == t)
            })
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_metric_returns_set_values() {
        let m = MockMetricSource::new()
            .with("metric_a", 0.5)
            .with("metric_b", 100.0);
        assert_eq!(
            m.read_scalar("metric_a").await,
            Some(Ok(0.5))
        );
        assert_eq!(
            m.read_scalar("metric_b").await,
            Some(Ok(100.0))
        );
        assert_eq!(m.read_scalar("missing").await, None);
    }

    #[tokio::test]
    async fn mock_metric_propagates_errors() {
        let m = MockMetricSource::new().with_err("broken", "rpc down");
        match m.read_scalar("broken").await {
            Some(Err(s)) => assert!(s.contains("rpc down")),
            other => panic!("expected Some(Err), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn mock_chain_filters_by_address() {
        let events = vec![
            ChainEvent {
                contract_addr: "0xaa".to_string(),
                topic0: [1u8; 32],
                indexed_topics: vec![],
                data: vec![],
                block_number: 100,
            },
            ChainEvent {
                contract_addr: "0xbb".to_string(),
                topic0: [1u8; 32],
                indexed_topics: vec![],
                data: vec![],
                block_number: 100,
            },
        ];
        let q = MockChainQuery::new(110).with_events(events);
        let logs = q.get_logs("0xaa", 50, 110, None).await.expect("logs");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].contract_addr, "0xaa");
    }

    #[tokio::test]
    async fn mock_chain_filters_by_block_range_and_topic() {
        let t0 = [0xabu8; 32];
        let events = vec![
            ChainEvent {
                contract_addr: "0xaa".to_string(),
                topic0: t0,
                indexed_topics: vec![],
                data: vec![],
                block_number: 50,
            },
            ChainEvent {
                contract_addr: "0xaa".to_string(),
                topic0: t0,
                indexed_topics: vec![],
                data: vec![],
                block_number: 200, // out of range
            },
            ChainEvent {
                contract_addr: "0xaa".to_string(),
                topic0: [0u8; 32], // wrong topic
                indexed_topics: vec![],
                data: vec![],
                block_number: 100,
            },
        ];
        let q = MockChainQuery::new(150).with_events(events);
        let logs = q
            .get_logs("0xaa", 40, 150, Some(t0))
            .await
            .expect("logs");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].block_number, 50);
    }

    #[tokio::test]
    async fn mock_chain_block_number() {
        let q = MockChainQuery::new(12345);
        assert_eq!(q.block_number().await.unwrap(), 12345);
    }

    #[test]
    fn urlencode_handles_label_selector() {
        let q = r#"foo{label="bar"}"#;
        let out = urlencode(q);
        assert!(out.contains("%7B"));
        assert!(out.contains("%7D"));
        assert!(out.contains("%22"));
    }
}
