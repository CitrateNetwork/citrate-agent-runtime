//! BFR-INT-poam-B / WP-6 — `citrate-tripwire-daemon` binary.
//!
//! Schedules the 9 FedRAMP tripwire jobs. Each runs on its own
//! configured interval (60s for critical, 300s for high/medium,
//! 3600s for slow-moving like cert expiry). SIGTERM stops cleanly.
//!
//! Configuration via env vars:
//!
//! - `CITRATE_TRIPWIRE_PROM_URL` — Prometheus base URL.
//!   Default `http://127.0.0.1:9090`.
//! - `CITRATE_TRIPWIRE_RPC_URL` — JSON-RPC base URL.
//!   Default `https://rpc.citrate.ai`.
//! - `DEPLOYER_PRIVATE_KEY` — secp256k1 hex key for the recorder
//!   that fires tripwires. **REQUIRED** — daemon exits if unset.
//! - `CITRATE_TRIPWIRE_REGISTRY` — TripwireRegistry contract addr.
//!   Default `0x7efc1eb17beff413e1af7fb3bb541e895c307300`.
//! - `CITRATE_TRIPWIRE_SCOPE` — bytes32-hex scope under which to
//!   fire. Default = `keccak256("boeing-root")`.
//! - `CITRATE_TRIPWIRE_TENANT` — TenantHierarchy address.
//! - `CITRATE_TRIPWIRE_ROLE_ESCALATION` — RoleEscalation address.
//! - `CITRATE_TRIPWIRE_MULTISIG` — MultiSigEnvelope address.

use std::sync::Arc;
use std::time::Duration;

use citrate_agent_cron::tripwires::evaluator::{HysteresisGate, JobOutcome};
use citrate_agent_cron::tripwires::jobs::{
    run_trip_ac_001, run_trip_ac_002, run_trip_au_001, run_trip_au_002,
    run_trip_au_003, run_trip_cm_001, run_trip_ia_001, run_trip_sc_001,
    run_trip_si_001,
};
use citrate_agent_cron::tripwires::metric_source::{
    EthLogsSource, PrometheusHttpSource,
};
use citrate_recorder::audit::recorder::RecorderClient;
use sha3::{Digest, Keccak256};
use tokio::sync::Mutex;
use tracing::{info, warn};

const DEFAULT_REGISTRY: &str = "0x7efc1eb17beff413e1af7fb3bb541e895c307300";
const DEFAULT_PROM: &str = "http://127.0.0.1:9090";
const DEFAULT_RPC: &str = "https://rpc.citrate.ai";

fn keccak(s: &str) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(s.as_bytes());
    let d = h.finalize();
    let mut o = [0u8; 32];
    o.copy_from_slice(&d);
    o
}

fn parse_bytes32_hex(s: &str) -> Result<[u8; 32], String> {
    let h = s.trim_start_matches("0x");
    let b = hex::decode(h).map_err(|e| format!("hex: {e}"))?;
    if b.len() != 32 {
        return Err(format!("len {}", b.len()));
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&b);
    Ok(o)
}

/// Bundle of deps every job task captures.
#[derive(Clone)]
struct JobDeps {
    metrics: Arc<PrometheusHttpSource>,
    chain: Arc<EthLogsSource>,
    recorder: Arc<RecorderClient>,
    registry: String,
    scope: [u8; 32],
}

fn log_outcome(name: &str, outcome: JobOutcome) {
    match outcome {
        JobOutcome::NoBreach => {}
        JobOutcome::Fired(tx) => info!("{name}: FIRED — {tx}"),
        JobOutcome::Failed(reason) => warn!("{name}: failed — {reason}"),
        // AR-B-010: a missing metric is a monitoring BLIND SPOT — surface
        // it loudly rather than treating it as a clean pass.
        JobOutcome::MetricUnavailable(reason) => {
            warn!("{name}: DETECTION DISABLED — metric unavailable: {reason}")
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("citrate-tripwire-daemon starting (BFR-INT-poam-B)");

    let prom_url = std::env::var("CITRATE_TRIPWIRE_PROM_URL")
        .unwrap_or_else(|_| DEFAULT_PROM.to_string());
    let rpc_url = std::env::var("CITRATE_TRIPWIRE_RPC_URL")
        .unwrap_or_else(|_| DEFAULT_RPC.to_string());
    let registry = std::env::var("CITRATE_TRIPWIRE_REGISTRY")
        .unwrap_or_else(|_| DEFAULT_REGISTRY.to_string());
    let scope = std::env::var("CITRATE_TRIPWIRE_SCOPE")
        .map(|s| parse_bytes32_hex(&s).expect("CITRATE_TRIPWIRE_SCOPE bytes32"))
        .unwrap_or_else(|_| keccak("boeing-root"));

    let recorder = Arc::new(
        RecorderClient::from_env(&rpc_url)
            .ok_or("DEPLOYER_PRIVATE_KEY missing — daemon needs a recorder to fire on chain")?,
    );
    info!(
        "recorder loaded — firing as {} against TripwireRegistry {}",
        recorder.from_address(),
        registry
    );

    let metrics = Arc::new(PrometheusHttpSource::new(prom_url.clone()));
    let chain = Arc::new(EthLogsSource::new(rpc_url.clone()));
    info!("prometheus {} | rpc {}", prom_url, rpc_url);

    let deps = JobDeps {
        metrics,
        chain,
        recorder,
        registry,
        scope,
    };

    // Per-job gates. Each lives in its own Arc<Mutex> so the task
    // can mutate state across ticks.
    let g_au_001 = Arc::new(Mutex::new(HysteresisGate::new(
        0.80, 0.70, Duration::from_secs(3600),
    )));
    let g_au_002 = Arc::new(Mutex::new(HysteresisGate::new(
        1000.0, 800.0, Duration::from_secs(1800),
    )));
    let g_sc_001 = Arc::new(Mutex::new(HysteresisGate::new(
        0.0, -5.0, Duration::from_secs(86400),
    )));
    let g_ac_001 = Arc::new(Mutex::new(HysteresisGate::new(
        14_400.0, 12_000.0, Duration::from_secs(3600),
    )));
    let g_cm_001 = Arc::new(Mutex::new(HysteresisGate::new(
        0.5, 0.0, Duration::from_secs(900),
    )));
    let g_ia_001 = Arc::new(Mutex::new(HysteresisGate::new(
        0.5, 0.0, Duration::from_secs(900),
    )));
    let g_ac_002 = Arc::new(Mutex::new(HysteresisGate::new(
        0.5, 0.0, Duration::from_secs(60),
    )));
    let g_au_003 = Arc::new(Mutex::new(HysteresisGate::new(
        0.01, 0.005, Duration::from_secs(60),
    )));
    let g_si_001 = Arc::new(Mutex::new(HysteresisGate::new(
        0.5, 0.0, Duration::from_secs(60),
    )));

    let tenant_addr = std::env::var("CITRATE_TRIPWIRE_TENANT")
        .unwrap_or_else(|_| "0x3FF095445b382075971fD5D3e05FD8bB3FF8006C".to_string());
    let role_esc_addr = std::env::var("CITRATE_TRIPWIRE_ROLE_ESCALATION")
        .unwrap_or_else(|_| "0x3130B9494Dc9c9253078176917cF4CDdcEf48337".to_string());
    let multisig_addr = std::env::var("CITRATE_TRIPWIRE_MULTISIG")
        .unwrap_or_else(|_| "0x05825775315f3d074db9F948713D05059e12a8Fd".to_string());

    let grant_topic = keccak("ElevationGranted(bytes32,bytes32,bytes32)");
    let revoke_topic = keccak("ElevationRevoked(bytes32)");
    let elevation_topic = keccak(
        "RequestElevation(bytes32,bytes32,bytes32,uint32,bytes32,bytes,string)",
    );
    let status_change_topic = keccak("NodeStatusChanged(bytes32,uint8)");
    let invalid_caller_topic = keccak("InvalidCaller(address)");

    // TRIP-AU-001 — RocksDB capacity.
    {
        let deps = deps.clone();
        let gate = g_au_001.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_au_001(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                )
                .await;
                drop(g);
                log_outcome("TRIP-AU-001", outcome);
            }
        });
    }

    // TRIP-AU-002 — Audit log shipper backlog.
    {
        let deps = deps.clone();
        let gate = g_au_002.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_au_002(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                )
                .await;
                drop(g);
                log_outcome("TRIP-AU-002", outcome);
            }
        });
    }

    // TRIP-SC-001 — TLS cert expiry.
    {
        let deps = deps.clone();
        let gate = g_sc_001.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(3600));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_sc_001(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                )
                .await;
                drop(g);
                log_outcome("TRIP-SC-001", outcome);
            }
        });
    }

    // TRIP-AC-001 — Role escalation > 4h.
    {
        let deps = deps.clone();
        let gate = g_ac_001.clone();
        let role = role_esc_addr.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_ac_001(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                    &role,
                    grant_topic,
                    revoke_topic,
                )
                .await;
                drop(g);
                log_outcome("TRIP-AC-001", outcome);
            }
        });
    }

    // TRIP-CM-001 — Multi-sig method bypassed.
    {
        let deps = deps.clone();
        let gate = g_cm_001.clone();
        let ms = multisig_addr.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_cm_001(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                    &ms,
                    invalid_caller_topic,
                )
                .await;
                drop(g);
                log_outcome("TRIP-CM-001", outcome);
            }
        });
    }

    // TRIP-IA-001 — Elevation without auth_mode.
    {
        let deps = deps.clone();
        let gate = g_ia_001.clone();
        let role = role_esc_addr.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(300));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_ia_001(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                    &role,
                    elevation_topic,
                )
                .await;
                drop(g);
                log_outcome("TRIP-IA-001", outcome);
            }
        });
    }

    // TRIP-AC-002 — FN status change without revoke.
    {
        let deps = deps.clone();
        let gate = g_ac_002.clone();
        let tenant = tenant_addr.clone();
        let role = role_esc_addr.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_ac_002(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                    &tenant,
                    &role,
                    status_change_topic,
                    revoke_topic,
                )
                .await;
                drop(g);
                log_outcome("TRIP-AC-002", outcome);
            }
        });
    }

    // TRIP-AU-003 — IPFS pin failure rate.
    {
        let deps = deps.clone();
        let gate = g_au_003.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_au_003(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                )
                .await;
                drop(g);
                log_outcome("TRIP-AU-003", outcome);
            }
        });
    }

    // TRIP-SI-001 — Release manifest hash mismatch.
    {
        let deps = deps.clone();
        let gate = g_si_001.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let mut g = gate.lock().await;
                let outcome = run_trip_si_001(
                    deps.metrics.as_ref(),
                    deps.chain.as_ref(),
                    deps.recorder.as_ref(),
                    &deps.registry,
                    deps.scope,
                    &mut *g,
                )
                .await;
                drop(g);
                log_outcome("TRIP-SI-001", outcome);
            }
        });
    }

    info!("9 tripwire jobs scheduled. Daemon ready. Waiting for SIGTERM...");

    tokio::signal::ctrl_c().await?;
    info!("SIGTERM received — daemon shutting down");
    Ok(())
}
