//! BFR-INT-poam-B / WP-3+4+5 — the 9 tripwire job implementations.
//!
//! Each `run_*` function takes the shared deps (metric source,
//! chain query, recorder, scope, gate) + returns a `JobOutcome`.
//! Wiring (cron schedule, daemon orchestration) lives in
//! `bin/tripwire_daemon.rs`.
//!
//! All 9 jobs follow the same shape:
//! 1. Compute the metric (Prometheus / chain log scan).
//! 2. Evaluate via the `HysteresisGate`.
//! 3. If gate says fire: derive `firing_id`, call
//!    `RecorderClient::fire_tripwire`, return `Fired(tx_hash)`.

use citrate_recorder::audit::recorder::{
    compute_firing_id, compute_tripwire_id, RecorderClient,
};
use tracing::{info, warn};

use super::evaluator::{HysteresisGate, JobOutcome};
use super::metric_source::{ChainQuery, MetricSource};

/// Shared call to fire a tripwire on chain. Centralised so the 9
/// jobs don't each re-derive the firing_id + handle the tx path.
///
/// BFR-INT-verification-poll: after broadcast, polls
/// `eth_getTransactionReceipt` until the TX is mined. Receipts
/// with `status == false` (reverted) surface as
/// `JobOutcome::Failed` rather than the previous false-positive
/// `Fired` — the broadcast succeeded but the on-chain action
/// didn't.
async fn fire(
    recorder: &RecorderClient,
    registry_addr: &str,
    canonical_id: &str,
    scope: [u8; 32],
    severity: u8,
    evidence_cid: [u8; 32],
    block_number: u64,
) -> JobOutcome {
    let tripwire_id = compute_tripwire_id(canonical_id);
    let firing_id = compute_firing_id(tripwire_id, scope, block_number);

    // Broadcast first; if that fails (RPC down, nonce issue), no
    // need to poll.
    let tx_hash = match recorder
        .fire_tripwire(
            registry_addr,
            firing_id,
            tripwire_id,
            scope,
            severity,
            evidence_cid,
        )
        .await
    {
        Ok(tx) => tx,
        Err(e) => {
            warn!("tripwire {canonical_id} broadcast failed: {e}");
            return JobOutcome::Failed(format!("fire_tripwire broadcast: {e}"));
        }
    };

    // Wait for receipt. 60s covers ~30 blocks of headroom.
    match recorder
        .wait_for_receipt(&tx_hash, std::time::Duration::from_secs(60))
        .await
    {
        Ok(receipt) if receipt.status => {
            info!(
                "tripwire {canonical_id} fired (severity {severity}) — tx {} mined at block {} (gas {})",
                receipt.tx_hash, receipt.block_number, receipt.gas_used
            );
            JobOutcome::Fired(receipt.tx_hash)
        }
        Ok(receipt) => {
            warn!(
                "tripwire {canonical_id} REVERTED on chain — tx {} (gas {})",
                receipt.tx_hash, receipt.gas_used
            );
            JobOutcome::Failed(format!(
                "tx reverted (gas_used {}): {}",
                receipt.gas_used, receipt.tx_hash
            ))
        }
        Err(e) => {
            warn!("tripwire {canonical_id} wait_for_receipt failed: {e}");
            JobOutcome::Failed(format!("wait_for_receipt: {e}"))
        }
    }
}

// ── WP-3 — Simple metric tripwires ───────────────────────────────

/// `TRIP-AU-001` — RocksDB hot tier > 80% capacity. Medium severity.
pub async fn run_trip_au_001(
    metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
) -> JobOutcome {
    let m = match metrics
        .read_scalar(r#"rocksdb_size_bytes / rocksdb_capacity_bytes"#)
        .await
    {
        Some(Ok(v)) => v,
        Some(Err(e)) => return JobOutcome::Failed(format!("metric: {e}")),
        None => return JobOutcome::NoBreach, // metric not yet emitted
    };
    if !gate.evaluate(m) {
        return JobOutcome::NoBreach;
    }
    let block = chain.block_number().await.unwrap_or(0);
    fire(
        recorder,
        registry_addr,
        "TRIP-AU-001",
        scope,
        1, // Medium
        [0u8; 32],
        block,
    )
    .await
}

/// `TRIP-AU-002` — Audit log shipper backlog > 1000 events. High.
pub async fn run_trip_au_002(
    metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
) -> JobOutcome {
    let m = match metrics.read_scalar("audit_log_shipper_backlog_count").await {
        Some(Ok(v)) => v,
        Some(Err(e)) => return JobOutcome::Failed(format!("metric: {e}")),
        None => return JobOutcome::NoBreach,
    };
    if !gate.evaluate(m) {
        return JobOutcome::NoBreach;
    }
    let block = chain.block_number().await.unwrap_or(0);
    fire(
        recorder,
        registry_addr,
        "TRIP-AU-002",
        scope,
        2, // High
        [0u8; 32],
        block,
    )
    .await
}

/// `TRIP-SC-001` — TLS cert expiry < 30 days. Medium.
///
/// `metrics` reads `tls_cert_days_until_expiry` (note: lower
/// values mean expiry is closer — we fire when this DROPS BELOW
/// 30, not above; we negate by treating "30 - value" as the
/// metric the gate evaluates).
pub async fn run_trip_sc_001(
    metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
) -> JobOutcome {
    let days = match metrics.read_scalar("tls_cert_days_until_expiry").await {
        Some(Ok(v)) => v,
        Some(Err(e)) => return JobOutcome::Failed(format!("metric: {e}")),
        None => return JobOutcome::NoBreach,
    };
    // Gate threshold is days_remaining: < 30 = fire. We flip the
    // sign — gate fires when (30 - days) > 0, with hysteresis
    // configured by the daemon to use 30 as the high threshold and
    // (e.g.) 35 as the re-arm point.
    let inverted = 30.0 - days;
    if !gate.evaluate(inverted) {
        return JobOutcome::NoBreach;
    }
    let block = chain.block_number().await.unwrap_or(0);
    fire(
        recorder,
        registry_addr,
        "TRIP-SC-001",
        scope,
        1, // Medium
        [0u8; 32],
        block,
    )
    .await
}

// ── WP-4 — Chain-correlation tripwires ──────────────────────────

/// `TRIP-AC-001` — Any account elevated > 4h continuous. High.
///
/// Scans RoleEscalation events; if any active grant exceeds 4h
/// (4 * 3600 seconds, but we use block-rate as a proxy: assume
/// ~1 block/sec, so > 14400 blocks since grant).
pub async fn run_trip_ac_001(
    _metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
    role_escalation_addr: &str,
    grant_topic0: [u8; 32],
    revoke_topic0: [u8; 32],
) -> JobOutcome {
    let now = match chain.block_number().await {
        Ok(b) => b,
        Err(e) => return JobOutcome::Failed(format!("blockNumber: {e}")),
    };
    // Scan the last 24h of grants (~86400 blocks at 1s/block).
    let from_block = now.saturating_sub(86_400);
    let grants = match chain
        .get_logs(role_escalation_addr, from_block, now, Some(grant_topic0))
        .await
    {
        Ok(v) => v,
        Err(e) => return JobOutcome::Failed(format!("getLogs grants: {e}")),
    };
    let revokes = match chain
        .get_logs(role_escalation_addr, from_block, now, Some(revoke_topic0))
        .await
    {
        Ok(v) => v,
        Err(e) => return JobOutcome::Failed(format!("getLogs revokes: {e}")),
    };

    // Build a set of revoked grant_ids (assume topic1 = grant id).
    use std::collections::HashSet;
    let revoked: HashSet<[u8; 32]> = revokes
        .into_iter()
        .filter_map(|e| e.indexed_topics.first().copied())
        .collect();

    // Find oldest still-active grant.
    let oldest_active = grants
        .into_iter()
        .filter(|g| {
            g.indexed_topics
                .first()
                .map(|id| !revoked.contains(id))
                .unwrap_or(true)
        })
        .map(|g| g.block_number)
        .min();

    let age_blocks = match oldest_active {
        Some(b) => now.saturating_sub(b) as f64,
        None => 0.0,
    };

    if !gate.evaluate(age_blocks) {
        return JobOutcome::NoBreach;
    }
    fire(
        recorder,
        registry_addr,
        "TRIP-AC-001",
        scope,
        2, // High
        [0u8; 32],
        now,
    )
    .await
}

/// `TRIP-CM-001` — Multi-sig method called by non-multi-sig
/// account. High.
///
/// Scans MultiSigEnvelope event log for "DirectCall" or
/// "InvalidCaller" events. A fire indicates someone bypassed the
/// multi-sig enforcement path.
pub async fn run_trip_cm_001(
    _metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
    multisig_addr: &str,
    invalid_caller_topic0: [u8; 32],
) -> JobOutcome {
    let now = match chain.block_number().await {
        Ok(b) => b,
        Err(e) => return JobOutcome::Failed(format!("blockNumber: {e}")),
    };
    // Scan the last poll window (~5 min = 300 blocks at 1s/block).
    let from_block = now.saturating_sub(300);
    let logs = match chain
        .get_logs(multisig_addr, from_block, now, Some(invalid_caller_topic0))
        .await
    {
        Ok(v) => v,
        Err(e) => return JobOutcome::Failed(format!("getLogs: {e}")),
    };
    let count = logs.len() as f64;
    if !gate.evaluate(count) {
        return JobOutcome::NoBreach;
    }
    fire(
        recorder,
        registry_addr,
        "TRIP-CM-001",
        scope,
        2, // High
        [0u8; 32],
        now,
    )
    .await
}

/// `TRIP-IA-001` — `requestElevation` called without `auth_mode`.
/// Medium.
///
/// Scans RoleEscalation events; counts `requestElevation` calls
/// whose `auth_mode` arg is empty (encoded as empty string in
/// data bytes).
pub async fn run_trip_ia_001(
    _metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
    role_escalation_addr: &str,
    elevation_topic0: [u8; 32],
) -> JobOutcome {
    let now = match chain.block_number().await {
        Ok(b) => b,
        Err(e) => return JobOutcome::Failed(format!("blockNumber: {e}")),
    };
    let from_block = now.saturating_sub(300);
    let logs = match chain
        .get_logs(role_escalation_addr, from_block, now, Some(elevation_topic0))
        .await
    {
        Ok(v) => v,
        Err(e) => return JobOutcome::Failed(format!("getLogs: {e}")),
    };
    // Heuristic: data must contain the auth_mode string header.
    // If the data section is shorter than 64 bytes (one offset +
    // one length slot), the auth_mode is missing.
    let missing = logs
        .iter()
        .filter(|e| e.data.len() < 64 || e.data.iter().all(|&b| b == 0))
        .count() as f64;
    if !gate.evaluate(missing) {
        return JobOutcome::NoBreach;
    }
    fire(
        recorder,
        registry_addr,
        "TRIP-IA-001",
        scope,
        1, // Medium
        [0u8; 32],
        now,
    )
    .await
}

// ── WP-5 — Critical-severity tripwires ──────────────────────────

/// `TRIP-AC-002` — FN status change → no auto-revoke within 5s.
/// Critical.
///
/// Correlates TenantHierarchy status-change events with
/// RoleEscalation revoke events. If a status change isn't followed
/// by a revoke within 5 blocks (~5s), fires.
pub async fn run_trip_ac_002(
    _metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
    tenant_hierarchy_addr: &str,
    role_escalation_addr: &str,
    status_change_topic0: [u8; 32],
    revoke_topic0: [u8; 32],
) -> JobOutcome {
    let now = match chain.block_number().await {
        Ok(b) => b,
        Err(e) => return JobOutcome::Failed(format!("blockNumber: {e}")),
    };
    let from_block = now.saturating_sub(300);
    let status_changes = match chain
        .get_logs(
            tenant_hierarchy_addr,
            from_block,
            now,
            Some(status_change_topic0),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => return JobOutcome::Failed(format!("getLogs status: {e}")),
    };
    let revokes = match chain
        .get_logs(role_escalation_addr, from_block, now, Some(revoke_topic0))
        .await
    {
        Ok(v) => v,
        Err(e) => return JobOutcome::Failed(format!("getLogs revoke: {e}")),
    };

    // For each status change at block N, look for any revoke in
    // [N, N+5]. Count unresolved.
    let unresolved = status_changes
        .iter()
        .filter(|sc| {
            let window_end = sc.block_number + 5;
            !revokes.iter().any(|r| {
                r.block_number >= sc.block_number && r.block_number <= window_end
            })
        })
        .count() as f64;

    if !gate.evaluate(unresolved) {
        return JobOutcome::NoBreach;
    }
    fire(
        recorder,
        registry_addr,
        "TRIP-AC-002",
        scope,
        3, // Critical
        [0u8; 32],
        now,
    )
    .await
}

/// `TRIP-AU-003` — IPFS pin failure rate > 1%/hr. Critical.
pub async fn run_trip_au_003(
    metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
) -> JobOutcome {
    let attempts = match metrics
        .read_scalar("ipfs_pin_attempts_total")
        .await
    {
        Some(Ok(v)) => v,
        Some(Err(e)) => return JobOutcome::Failed(format!("attempts: {e}")),
        None => return JobOutcome::NoBreach,
    };
    let failures = match metrics
        .read_scalar("ipfs_pin_failures_total")
        .await
    {
        Some(Ok(v)) => v,
        Some(Err(e)) => return JobOutcome::Failed(format!("failures: {e}")),
        None => return JobOutcome::NoBreach,
    };
    if attempts < 1.0 {
        return JobOutcome::NoBreach; // not enough data
    }
    let rate = failures / attempts;
    if !gate.evaluate(rate) {
        return JobOutcome::NoBreach;
    }
    let block = chain.block_number().await.unwrap_or(0);
    fire(
        recorder,
        registry_addr,
        "TRIP-AU-003",
        scope,
        3, // Critical
        [0u8; 32],
        block,
    )
    .await
}

/// `TRIP-SI-001` — Release manifest hash mismatch on deploy.
/// Critical.
///
/// Reads `release_manifest_hash_mismatch_count` from the
/// release-package build/deploy pipeline. Fires if > 0.
pub async fn run_trip_si_001(
    metrics: &dyn MetricSource,
    chain: &dyn ChainQuery,
    recorder: &RecorderClient,
    registry_addr: &str,
    scope: [u8; 32],
    gate: &mut HysteresisGate,
) -> JobOutcome {
    let count = match metrics
        .read_scalar("release_manifest_hash_mismatch_count")
        .await
    {
        Some(Ok(v)) => v,
        Some(Err(e)) => return JobOutcome::Failed(format!("metric: {e}")),
        None => return JobOutcome::NoBreach,
    };
    if !gate.evaluate(count) {
        return JobOutcome::NoBreach;
    }
    let block = chain.block_number().await.unwrap_or(0);
    fire(
        recorder,
        registry_addr,
        "TRIP-SI-001",
        scope,
        3, // Critical
        [0u8; 32],
        block,
    )
    .await
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::metric_source::{ChainEvent, MockChainQuery, MockMetricSource};
    use super::*;
    use std::time::Duration;

    fn test_recorder() -> RecorderClient {
        // Use a deterministic key + a known RPC URL. The chain
        // calls won't succeed without a real chain, but the
        // RecorderClient construction is what we need + we never
        // call .send_tx in unit tests.
        RecorderClient::from_hex_key(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "http://127.0.0.1:0", // unreachable on purpose
        )
        .expect("test recorder")
    }

    const REG: &str = "0x7efc1eb17beff413e1af7fb3bb541e895c307300";
    const SCOPE: [u8; 32] = [0xeeu8; 32];

    // ── Simple metric tests ──

    #[tokio::test]
    async fn trip_au_001_no_breach_below_threshold() {
        let metrics = MockMetricSource::new()
            .with("rocksdb_size_bytes / rocksdb_capacity_bytes", 0.5);
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(0.80, 0.70, Duration::from_secs(0));
        let outcome = run_trip_au_001(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }

    #[tokio::test]
    async fn trip_au_001_attempts_fire_when_above_threshold() {
        let metrics = MockMetricSource::new()
            .with("rocksdb_size_bytes / rocksdb_capacity_bytes", 0.95);
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(0.80, 0.70, Duration::from_secs(0));
        let outcome = run_trip_au_001(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        // The fire call will fail (unreachable RPC) but we should
        // see Failed, NOT NoBreach — confirming the gate fired.
        match outcome {
            JobOutcome::Failed(_) => {}
            other => panic!("expected Failed (RPC unreachable), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn trip_au_001_metric_missing_is_no_breach() {
        let metrics = MockMetricSource::new(); // no metric
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(0.80, 0.70, Duration::from_secs(0));
        let outcome = run_trip_au_001(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }

    #[tokio::test]
    async fn trip_au_002_fires_at_backlog_threshold() {
        let metrics = MockMetricSource::new()
            .with("audit_log_shipper_backlog_count", 1500.0);
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(1000.0, 800.0, Duration::from_secs(0));
        let outcome = run_trip_au_002(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert!(matches!(outcome, JobOutcome::Failed(_))); // RPC unreachable
    }

    #[tokio::test]
    async fn trip_sc_001_fires_when_expiry_imminent() {
        let metrics = MockMetricSource::new()
            .with("tls_cert_days_until_expiry", 7.0); // 7 days — bad
        let chain = MockChainQuery::new(100);
        // Gate threshold: (30 - days) > 0 fires. With days=7,
        // inverted=23 > 0 high_threshold. Set gate at 0 high.
        let mut gate = HysteresisGate::new(0.0, -5.0, Duration::from_secs(0));
        let outcome = run_trip_sc_001(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert!(matches!(outcome, JobOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn trip_sc_001_no_breach_when_cert_fresh() {
        let metrics = MockMetricSource::new()
            .with("tls_cert_days_until_expiry", 90.0);
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(0.0, -5.0, Duration::from_secs(0));
        let outcome = run_trip_sc_001(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }

    // ── Chain-correlation tests ──

    #[tokio::test]
    async fn trip_ac_001_no_active_grants_no_breach() {
        let metrics = MockMetricSource::new();
        let chain = MockChainQuery::new(100_000);
        let mut gate = HysteresisGate::new(14_400.0, 12_000.0, Duration::from_secs(0));
        let outcome = run_trip_ac_001(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
            "0x3130B9494Dc9c9253078176917cF4CDdcEf48337",
            [0xa1u8; 32],
            [0xa2u8; 32],
        )
        .await;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }

    #[tokio::test]
    async fn trip_ac_001_fires_on_old_grant() {
        let role_escalation = "0x3130B9494Dc9c9253078176917cF4CDdcEf48337";
        let grant_t0 = [0xa1u8; 32];
        let revoke_t0 = [0xa2u8; 32];
        let now = 100_000;
        // Grant at block N - 20_000 > 14_400 threshold.
        let events = vec![ChainEvent {
            contract_addr: role_escalation.to_string(),
            topic0: grant_t0,
            indexed_topics: vec![[0xbb; 32]],
            data: vec![],
            block_number: now - 20_000,
        }];
        let chain = MockChainQuery::new(now).with_events(events);
        let mut gate = HysteresisGate::new(14_400.0, 12_000.0, Duration::from_secs(0));
        let outcome = run_trip_ac_001(
            &MockMetricSource::new(),
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
            role_escalation,
            grant_t0,
            revoke_t0,
        )
        .await;
        assert!(matches!(outcome, JobOutcome::Failed(_))); // RPC unreachable
    }

    #[tokio::test]
    async fn trip_ac_001_revoked_grant_is_not_counted() {
        let role_escalation = "0x3130B9494Dc9c9253078176917cF4CDdcEf48337";
        let grant_t0 = [0xa1u8; 32];
        let revoke_t0 = [0xa2u8; 32];
        let now = 100_000;
        let grant_id = [0xbb; 32];
        let events = vec![
            ChainEvent {
                contract_addr: role_escalation.to_string(),
                topic0: grant_t0,
                indexed_topics: vec![grant_id],
                data: vec![],
                block_number: now - 20_000,
            },
            ChainEvent {
                contract_addr: role_escalation.to_string(),
                topic0: revoke_t0,
                indexed_topics: vec![grant_id],
                data: vec![],
                block_number: now - 15_000,
            },
        ];
        let chain = MockChainQuery::new(now).with_events(events);
        let mut gate = HysteresisGate::new(14_400.0, 12_000.0, Duration::from_secs(0));
        let outcome = run_trip_ac_001(
            &MockMetricSource::new(),
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
            role_escalation,
            grant_t0,
            revoke_t0,
        )
        .await;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }

    #[tokio::test]
    async fn trip_cm_001_invalid_callers_counted() {
        let multisig = "0x05825775315f3d074db9F948713D05059e12a8Fd";
        let t0 = [0xc1u8; 32];
        let now = 100;
        let events = vec![
            ChainEvent {
                contract_addr: multisig.to_string(),
                topic0: t0,
                indexed_topics: vec![],
                data: vec![],
                block_number: now - 10,
            },
            ChainEvent {
                contract_addr: multisig.to_string(),
                topic0: t0,
                indexed_topics: vec![],
                data: vec![],
                block_number: now - 5,
            },
        ];
        let chain = MockChainQuery::new(now).with_events(events);
        let mut gate = HysteresisGate::new(0.5, 0.0, Duration::from_secs(0));
        let outcome = run_trip_cm_001(
            &MockMetricSource::new(),
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
            multisig,
            t0,
        )
        .await;
        assert!(matches!(outcome, JobOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn trip_ia_001_short_data_counted_as_missing_auth_mode() {
        let role_escalation = "0x3130B9494Dc9c9253078176917cF4CDdcEf48337";
        let t0 = [0xd1u8; 32];
        let now = 100;
        let events = vec![ChainEvent {
            contract_addr: role_escalation.to_string(),
            topic0: t0,
            indexed_topics: vec![],
            data: vec![0u8; 32], // shorter than 64 = missing auth_mode
            block_number: now - 10,
        }];
        let chain = MockChainQuery::new(now).with_events(events);
        let mut gate = HysteresisGate::new(0.5, 0.0, Duration::from_secs(0));
        let outcome = run_trip_ia_001(
            &MockMetricSource::new(),
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
            role_escalation,
            t0,
        )
        .await;
        assert!(matches!(outcome, JobOutcome::Failed(_)));
    }

    // ── Critical-severity tests ──

    #[tokio::test]
    async fn trip_ac_002_unresolved_status_change_fires() {
        let tenant = "0x3FF095445b382075971fD5D3e05FD8bB3FF8006C";
        let role_escalation = "0x3130B9494Dc9c9253078176917cF4CDdcEf48337";
        let status_t0 = [0xe1u8; 32];
        let revoke_t0 = [0xe2u8; 32];
        let now = 100;
        let events = vec![ChainEvent {
            contract_addr: tenant.to_string(),
            topic0: status_t0,
            indexed_topics: vec![],
            data: vec![],
            block_number: now - 50,
            // No revoke within 5 blocks of this — unresolved.
        }];
        let chain = MockChainQuery::new(now).with_events(events);
        let mut gate = HysteresisGate::new(0.5, 0.0, Duration::from_secs(0));
        let outcome = run_trip_ac_002(
            &MockMetricSource::new(),
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
            tenant,
            role_escalation,
            status_t0,
            revoke_t0,
        )
        .await;
        assert!(matches!(outcome, JobOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn trip_ac_002_resolved_status_change_no_breach() {
        let tenant = "0x3FF095445b382075971fD5D3e05FD8bB3FF8006C";
        let role_escalation = "0x3130B9494Dc9c9253078176917cF4CDdcEf48337";
        let status_t0 = [0xe1u8; 32];
        let revoke_t0 = [0xe2u8; 32];
        let now = 100;
        let events = vec![
            ChainEvent {
                contract_addr: tenant.to_string(),
                topic0: status_t0,
                indexed_topics: vec![],
                data: vec![],
                block_number: now - 50,
            },
            ChainEvent {
                contract_addr: role_escalation.to_string(),
                topic0: revoke_t0,
                indexed_topics: vec![],
                data: vec![],
                block_number: now - 47, // within 5 blocks of status change
            },
        ];
        let chain = MockChainQuery::new(now).with_events(events);
        let mut gate = HysteresisGate::new(0.5, 0.0, Duration::from_secs(0));
        let outcome = run_trip_ac_002(
            &MockMetricSource::new(),
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
            tenant,
            role_escalation,
            status_t0,
            revoke_t0,
        )
        .await;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }

    #[tokio::test]
    async fn trip_au_003_ipfs_failure_rate() {
        let metrics = MockMetricSource::new()
            .with("ipfs_pin_attempts_total", 1000.0)
            .with("ipfs_pin_failures_total", 50.0); // 5%
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(0.01, 0.005, Duration::from_secs(0));
        let outcome = run_trip_au_003(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert!(matches!(outcome, JobOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn trip_au_003_no_attempts_no_breach() {
        let metrics = MockMetricSource::new()
            .with("ipfs_pin_attempts_total", 0.0)
            .with("ipfs_pin_failures_total", 0.0);
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(0.01, 0.005, Duration::from_secs(0));
        let outcome = run_trip_au_003(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }

    #[tokio::test]
    async fn trip_si_001_fires_on_any_mismatch() {
        let metrics = MockMetricSource::new()
            .with("release_manifest_hash_mismatch_count", 1.0);
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(0.5, 0.0, Duration::from_secs(0));
        let outcome = run_trip_si_001(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert!(matches!(outcome, JobOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn trip_si_001_zero_mismatches_no_breach() {
        let metrics = MockMetricSource::new()
            .with("release_manifest_hash_mismatch_count", 0.0);
        let chain = MockChainQuery::new(100);
        let mut gate = HysteresisGate::new(0.5, 0.0, Duration::from_secs(0));
        let outcome = run_trip_si_001(
            &metrics,
            &chain,
            &test_recorder(),
            REG,
            SCOPE,
            &mut gate,
        )
        .await;
        assert_eq!(outcome, JobOutcome::NoBreach);
    }
}
