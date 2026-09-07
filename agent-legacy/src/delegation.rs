//! Approval delegation — the approval manager and capability enforcement layer.
//! NOTE: This is approval-based delegation, NOT cryptographically signed delegation.
//! Cryptographic signing of capability grants is a future enhancement.
//!
//! Every tool invocation from an external runtime must pass through this layer.
//! Approvals are keyed by request_id, have timeouts, and auto-deny on expiry.
//!
//! Architecture per auditor:
//! - PendingApprovalStore keyed by approval_request_id
//! - Each pending item owns a oneshot::Sender<bool>
//! - UI callbacks resolve by request ID
//! - Timeout, cancel-on-tab-close, and e-stop all clear pending requests
//! - Deny by default on dropped sender or timeout

use crate::canonical::ApprovalRequest;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use tokio_util::sync::CancellationToken;

/// A pending approval waiting for user decision.
struct PendingItem {
    request: ApprovalRequest,
    sender: oneshot::Sender<bool>,
    /// Token that cancels the spawned timeout task when the approval
    /// resolves early. Without it, every long-timeout approval leaks
    /// a sleeping task until the timeout elapses.
    /// RM-B1 / WP-E5.5 (audit AGT-09).
    cancel: CancellationToken,
}

/// AR-B-020: hard ceiling on a caller-supplied `timeout_seconds`. The value
/// came verbatim from the request, so `u64::MAX` produced an approval that
/// never auto-denies and a resident timeout task that never exits. Clamp it to
/// a sane maximum (1 hour) so every pending approval eventually resolves.
const MAX_TIMEOUT_SECS: u64 = 3600;

/// The approval manager — holds pending requests and resolves them.
pub struct PendingApprovalStore {
    pending: Arc<RwLock<HashMap<String, PendingItem>>>,
}

impl PendingApprovalStore {
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Submit an approval request. Returns a receiver that will get
    /// true (approved) or false (denied) when the user decides.
    /// Auto-denies after timeout_seconds if no decision is made.
    pub async fn submit(&self, request: ApprovalRequest) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let request_id = request.request_id.clone();
        // AR-B-020: clamp the caller-supplied timeout so an approval can never
        // be made to never expire.
        let timeout_secs = request.timeout_seconds.min(MAX_TIMEOUT_SECS);
        let cancel = CancellationToken::new();
        let cancel_for_timeout = cancel.clone();

        {
            let mut pending = self.pending.write().await;
            // AR-B-020: a duplicate request_id must NOT overwrite the existing
            // pending item — the old code dropped the original awaiter's sender
            // (it got RecvError, read as deny) while the displaced item's
            // timeout task survived and later auto-denied the REPLACEMENT. Refuse
            // the collision: deny the new request immediately (fail-closed) and
            // leave the in-flight approval untouched.
            if pending.contains_key(&request_id) {
                let _ = tx.send(false);
                return rx;
            }
            pending.insert(
                request_id.clone(),
                PendingItem {
                    request,
                    sender: tx,
                    cancel,
                },
            );
        }

        // RM-B1 / WP-E5.5 (audit AGT-09): the timeout task races
        // against an early-resolution cancel. With 10K long-timeout
        // approvals resolved quickly, we used to leak 10K sleeping
        // tasks; post-fix `select!` exits as soon as resolve fires.
        let store = self.pending.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)) => {
                    let mut pending = store.write().await;
                    if let Some(item) = pending.remove(&request_id) {
                        tracing::info!("Approval timeout: auto-denying {}", request_id);
                        let _ = item.sender.send(false);
                    }
                }
                _ = cancel_for_timeout.cancelled() => {
                    // Resolved early; just exit. The resolve()
                    // path already sent the decision to the
                    // receiver and removed the item.
                }
            }
        });

        rx
    }

    /// Resolve a pending approval by request ID.
    /// Returns true if the request was found and resolved.
    ///
    /// SECURITY (AR-B-020 follow-up): this call carries no approver identity, so
    /// any caller with a pending id can resolve it. Callers MUST gate this
    /// behind their own authenticated approver surface; binding an approver
    /// identity into the store is a tracked follow-up (needs an identity model
    /// the legacy crate does not yet have).
    pub async fn resolve(&self, request_id: &str, approved: bool) -> bool {
        let mut pending = self.pending.write().await;
        if let Some(item) = pending.remove(request_id) {
            tracing::info!(
                "Approval resolved: {} → {} (tool: {})",
                request_id,
                if approved { "approved" } else { "denied" },
                item.request.tool_name,
            );
            // Cancel the timeout task before notifying — preserving
            // ordering so the timeout can never racefully send
            // `false` after a successful resolve.
            item.cancel.cancel();
            let _ = item.sender.send(approved);
            true
        } else {
            false
        }
    }

    /// Get all pending requests (for UI display).
    pub async fn list_pending(&self) -> Vec<ApprovalRequest> {
        self.pending
            .read()
            .await
            .values()
            .map(|item| item.request.clone())
            .collect()
    }

    /// Cancel all pending requests (e-stop or session end).
    /// All pending approvals auto-deny.
    pub async fn cancel_all(&self) -> usize {
        let mut pending = self.pending.write().await;
        let count = pending.len();
        for (id, item) in pending.drain() {
            tracing::info!(
                "Approval cancelled: {} (tool: {})",
                id,
                item.request.tool_name
            );
            // RM-B1 / WP-E5.5 (audit AGT-09): cancel the timeout
            // task on bulk cancel too, so e-stop doesn't leak
            // tasks-in-flight.
            item.cancel.cancel();
            let _ = item.sender.send(false);
        }
        count
    }

    /// Number of pending approvals.
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }
}

impl Default for PendingApprovalStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request(id: &str, tool: &str) -> ApprovalRequest {
        ApprovalRequest {
            request_id: id.to_string(),
            session_id: "sess-1".to_string(),
            tool_name: tool.to_string(),
            params: serde_json::json!({}),
            risk_level: "high".to_string(),
            created_at: "2026-03-31T10:00:00Z".to_string(),
            timeout_seconds: 30,
            resolved: None,
            resolved_at: None,
        }
    }

    #[tokio::test]
    async fn test_submit_and_resolve_approved() {
        let store = PendingApprovalStore::new();
        let rx = store.submit(test_request("req-1", "send_tx")).await;
        assert_eq!(store.pending_count().await, 1);
        store.resolve("req-1", true).await;
        assert!(rx.await.expect("received"));
        assert_eq!(store.pending_count().await, 0);
    }

    #[tokio::test]
    async fn duplicate_request_id_does_not_hijack_the_in_flight_approval() {
        // AR-B-020: a second submit with the same id must NOT overwrite the
        // first (which dropped the original awaiter's sender). The original
        // stays pending and resolvable; the duplicate is denied immediately.
        let store = PendingApprovalStore::new();
        let rx1 = store.submit(test_request("dup", "send_tx")).await;
        let rx2 = store.submit(test_request("dup", "deploy_contract")).await;
        // The duplicate is denied right away.
        assert!(!rx2.await.expect("dup received"), "duplicate must be denied");
        // The original is still pending and still resolvable to Approved.
        assert_eq!(store.pending_count().await, 1);
        assert!(store.resolve("dup", true).await);
        assert!(rx1.await.expect("orig received"), "original must survive");
    }

    #[tokio::test]
    async fn timeout_seconds_is_clamped() {
        // AR-B-020: an unbounded caller timeout is clamped so the approval
        // cannot be made to never expire.
        let store = PendingApprovalStore::new();
        let mut req = test_request("clamp", "send_tx");
        req.timeout_seconds = u64::MAX;
        let _rx = store.submit(req).await;
        // The item is pending; we only assert it was accepted (the clamp is
        // applied to the spawned timeout, which we don't wait out here).
        assert_eq!(store.pending_count().await, 1);
    }

    #[tokio::test]
    async fn test_submit_and_resolve_denied() {
        let store = PendingApprovalStore::new();
        let rx = store.submit(test_request("req-2", "deploy_contract")).await;
        store.resolve("req-2", false).await;
        assert!(!rx.await.expect("received"));
    }

    #[tokio::test]
    async fn test_cancel_all_denies() {
        let store = PendingApprovalStore::new();
        let rx1 = store.submit(test_request("req-3", "send_tx")).await;
        let rx2 = store.submit(test_request("req-4", "deploy_contract")).await;
        assert_eq!(store.pending_count().await, 2);
        let cancelled = store.cancel_all().await;
        assert_eq!(cancelled, 2);
        assert!(!rx1.await.expect("received"));
        assert!(!rx2.await.expect("received"));
    }

    #[tokio::test]
    async fn test_resolve_nonexistent() {
        let store = PendingApprovalStore::new();
        let resolved = store.resolve("nonexistent", true).await;
        assert!(!resolved);
    }

    #[tokio::test]
    async fn test_list_pending() {
        let store = PendingApprovalStore::new();
        let _rx = store.submit(test_request("req-5", "check_balance")).await;
        let pending = store.list_pending().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_name, "check_balance");
    }

    /// RM-B1 / WP-E5.5 (audit AGT-09): timeout tasks must not
    /// outlive resolved approvals. Submit 200 long-timeout
    /// approvals, resolve all of them quickly, and verify the
    /// store empties immediately rather than holding entries
    /// until the 600-second timeout elapses.
    #[tokio::test]
    async fn test_agt09_no_task_leak_on_early_resolve() {
        let store = PendingApprovalStore::new();
        let n = 200;
        let mut receivers = Vec::with_capacity(n);
        for i in 0..n {
            let mut req = test_request(&format!("req-leak-{}", i), "send_tx");
            req.timeout_seconds = 600; // long enough to leak if not cancelled
            receivers.push(store.submit(req).await);
        }
        assert_eq!(store.pending_count().await, n);

        // Resolve all of them quickly.
        for i in 0..n {
            store.resolve(&format!("req-leak-{}", i), true).await;
        }
        // All receivers must yield true immediately.
        for rx in receivers {
            assert!(rx.await.expect("rx delivered"));
        }
        // And the store is empty — not waiting on background timeouts.
        assert_eq!(store.pending_count().await, 0);

        // The timeout tasks themselves are cancelled tokens; they
        // observe the cancel and exit. We can't observe their join
        // handle here (the spawn is fire-and-forget), but yielding
        // a few times lets them run through the cancel branch.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn test_timeout_auto_denies() {
        let store = PendingApprovalStore::new();
        let mut req = test_request("req-6", "send_tx");
        req.timeout_seconds = 1; // 1 second timeout
        let rx = store.submit(req).await;
        // Wait for timeout
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(!rx.await.expect("received"));
        assert_eq!(store.pending_count().await, 0);
    }
}
