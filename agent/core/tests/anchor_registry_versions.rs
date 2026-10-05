//! HUP-S7.1: `AnchorRegistryClient::is_anchored_by_self` against the real `AnchorRegistry`
//! bytecode of both versions on a local anvil (never 40204).
//!
//! - the deployed version (one record per root; a second committer of the same root reverts with
//!   `AlreadyAnchored`; no `isAnchoredBy`);
//! - the next version from the HUP registry redeploy (one record per `(committer, root)`,
//!   `isAnchoredBy`).
//!
//! Two keys derived at run time anchor the same value, the first one first. On both versions the
//! first key's anchor is confirmed. The second key's anchor is confirmed only on the next version:
//! on the deployed version its transaction reverted, and `isAnchored(root)` (true for anyone's
//! anchor) must not make it look confirmed. A third key that never sent anything is never
//! confirmed, and a value nobody anchored is false for everyone.
//!
//! Opt-in (`--ignored`); `scripts/anvil-anchor-registry-versions.sh` builds both contract versions
//! from citrate-chain and sets `CITRATE_ANCHOR_REGISTRY_LEGACY` / `CITRATE_ANCHOR_REGISTRY_NEXT`
//! to the forge artifact JSON of each.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use citrate_agent_core::audit::record::AnchorKind;
use citrate_agent_core::chain::AnchorRegistryClient;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

const CHAIN_ID: u64 = 31337;

struct Anvil {
    child: Child,
    url: String,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind a free port");
    l.local_addr().expect("local addr").port()
}

/// Minimal JSON-RPC over HTTP/1.1 (std only), for the test's own anvil.
fn rpc(url: &str, method: &str, params: Value) -> Value {
    let host = url.trim_start_matches("http://");
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let mut s = TcpStream::connect(host).expect("connect to anvil");
    write!(
        s,
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("write request");
    let mut raw = String::new();
    s.read_to_string(&mut raw).expect("read response");
    let json_start = raw.find("\r\n\r\n").map(|i| i + 4).expect("http body");
    let v: Value = serde_json::from_str(&raw[json_start..]).expect("json body");
    if let Some(e) = v.get("error") {
        panic!("{method} failed: {e}");
    }
    v["result"].clone()
}

fn start_anvil() -> Anvil {
    let port = free_port();
    let child = Command::new("anvil")
        .args([
            "--port",
            &port.to_string(),
            "--host",
            "127.0.0.1",
            "--chain-id",
            &CHAIN_ID.to_string(),
            "--block-base-fee-per-gas",
            "0",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil is installed (Foundry)");
    let url = format!("http://127.0.0.1:{port}");
    let anvil = Anvil { child, url };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(anvil.url.trim_start_matches("http://")).is_ok() {
            let client = rpc(&anvil.url, "web3_clientVersion", json!([]));
            assert!(
                client.as_str().is_some_and(|c| c.starts_with("anvil/")),
                "not our anvil: {client}"
            );
            return anvil;
        }
        assert!(Instant::now() < deadline, "anvil did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn artifact_bytecode(path: &str) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let v: Value = serde_json::from_str(&text).expect("forge artifact json");
    let code = v["bytecode"]["object"]
        .as_str()
        .expect("artifact has bytecode.object");
    assert!(code.len() > 2, "empty bytecode in {path}");
    code.to_string()
}

/// Wait for a receipt (anvil mines each transaction on arrival, but answers the send first).
fn wait_receipt(url: &str, tx: &Value) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let rc = rpc(url, "eth_getTransactionReceipt", json!([tx]));
        if !rc.is_null() {
            return rc;
        }
        assert!(Instant::now() < deadline, "no receipt for {tx}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn deploy(url: &str, bytecode: &str) -> String {
    let from = rpc(url, "eth_accounts", json!([]))[0].clone();
    let tx = rpc(
        url,
        "eth_sendTransaction",
        json!([{"from": from, "data": bytecode, "gas": "0x2dc6c0"}]),
    );
    let rc = wait_receipt(url, &tx);
    assert_eq!(rc["status"], "0x1", "deploy failed: {rc}");
    rc["contractAddress"]
        .as_str()
        .expect("contract address")
        .to_string()
}

fn client(label: &str, url: &str, registry: &str) -> AnchorRegistryClient {
    // Throwaway keys derived at run time; funded on this anvil only.
    let key = hex::encode(Keccak256::digest(label.as_bytes()));
    let c = AnchorRegistryClient::from_hex_key(&key, url, registry, CHAIN_ID)
        .unwrap_or_else(|| panic!("derived key {label} is not a valid scalar"));
    rpc(
        url,
        "anvil_setBalance",
        json!([c.from_address(), "0x56BC75E2D63100000"]),
    );
    c
}

fn receipt_status(url: &str, tx: &str) -> String {
    let rc = wait_receipt(url, &json!(tx));
    rc["status"].as_str().unwrap_or("none").to_string()
}

async fn rehearse(version: &str, artifact: &str) {
    let next = version == "next";
    let anvil = start_anvil();
    let url = anvil.url.clone();
    let registry = deploy(&url, &artifact_bytecode(artifact));

    let first = client("anchor-versions-first", &url, &registry);
    let second = client("anchor-versions-second", &url, &registry);
    let bystander = client("anchor-versions-bystander", &url, &registry);
    let root: [u8; 32] = Keccak256::digest(b"anchor-versions-day").into();
    let unanchored: [u8; 32] = Keccak256::digest(b"anchor-versions-other-day").into();

    // Nothing anchored yet.
    assert!(!first.is_anchored_by_self(root).await.expect("read"));

    let tx1 = first
        .anchor(AnchorKind::NightlyMerkle, root)
        .await
        .expect("send first");
    assert_eq!(receipt_status(&url, &tx1), "0x1", "{version}: first anchor");
    let tx2 = second
        .anchor(AnchorKind::NightlyMerkle, root)
        .await
        .expect("send second");
    // The deployed version refuses a second committer of the same root (AlreadyAnchored).
    let want = if next { "0x1" } else { "0x0" };
    assert_eq!(receipt_status(&url, &tx2), want, "{version}: second anchor");

    // isAnchored is true for everyone once anyone anchored the value.
    assert!(second.is_anchored(root).await.expect("read"));
    assert!(bystander.is_anchored(root).await.expect("read"));

    assert!(
        first.is_anchored_by_self(root).await.expect("read"),
        "{version}: the first committer's anchor is confirmed"
    );
    assert_eq!(
        second.is_anchored_by_self(root).await.expect("read"),
        next,
        "{version}: the second committer is confirmed only where its transaction landed"
    );
    assert!(
        !bystander.is_anchored_by_self(root).await.expect("read"),
        "{version}: a key that sent nothing is never confirmed"
    );
    assert!(!first.is_anchored_by_self(unanchored).await.expect("read"));
    // By address, without a key: the same answers.
    assert!(first
        .is_anchored_by(second.from_address(), root)
        .await
        .map(|v| v == next)
        .expect("read"));
    eprintln!("anchor registry {version}: PASS ({registry})");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs anvil and the AnchorRegistry artifacts: run scripts/anvil-anchor-registry-versions.sh"]
async fn own_anchor_check_on_both_registry_versions() {
    let legacy = std::env::var("CITRATE_ANCHOR_REGISTRY_LEGACY").ok();
    let next = std::env::var("CITRATE_ANCHOR_REGISTRY_NEXT").ok();
    assert!(
        legacy.is_some() && next.is_some(),
        "set CITRATE_ANCHOR_REGISTRY_LEGACY and CITRATE_ANCHOR_REGISTRY_NEXT (scripts/anvil-anchor-registry-versions.sh)"
    );
    if let Some(p) = legacy {
        rehearse("legacy", &p).await;
    }
    if let Some(p) = next {
        rehearse("next", &p).await;
    }
}
