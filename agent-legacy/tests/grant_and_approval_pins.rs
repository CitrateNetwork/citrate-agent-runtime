//! Pins on the grant check (`McpServer::check_grant`), the grant signature
//! pre-image, and the pending-approval store, through their public entry
//! points.

use std::sync::Arc;
use std::time::Duration;

use citrate_agent_legacy::canonical::{ApprovalRequest, CapabilityGrant, PolicyProfile};
use citrate_agent_legacy::delegation::PendingApprovalStore;
use citrate_agent_legacy::mcp_server::McpServer;
use citrate_agent_legacy::tool::ToolRegistry;
use ed25519_dalek::{Signer, SigningKey};

fn signed_grant(key: &SigningKey, issuer: &str, revoked: bool) -> CapabilityGrant {
    let mut grant = CapabilityGrant {
        id: "pin-grant".to_string(),
        issuer: issuer.to_string(),
        recipient: "pin-runtime".to_string(),
        allowed_tools: vec!["check_balance".to_string()],
        max_value_per_tx: None,
        allowed_paths: vec![],
        expires_at: "2099-01-01T00:00:00Z".to_string(),
        policy: PolicyProfile::ReadOnly,
        revoked,
        connected_since: 0,
        issuer_pubkey: key.verifying_key().to_bytes().to_vec(),
        signature: Vec::new(),
    };
    grant.signature = key.sign(&grant.signing_preimage()).to_bytes().to_vec();
    grant
}

/// `check_grant` re-checks the issuer trust anchor at use time, not only at
/// insert. A grant stored while the server was permissive (validly
/// self-signed, issuer not enrolled) must stop authorizing once strict mode
/// is on.
#[tokio::test]
async fn check_grant_rejects_an_untrusted_issuer_once_strict() {
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let mut server = McpServer::new_insecure_unsigned_grants(Arc::new(ToolRegistry::new()));
    server
        .try_add_grant(signed_grant(&key, "0xself", false))
        .await
        .expect("permissive server stores a validly self-signed grant");
    server
        .check_grant("pin-grant", "check_balance", None, None)
        .await
        .expect("control: permissive mode authorizes it");

    server.set_require_signed_grants(true);
    let err = server
        .check_grant("pin-grant", "check_balance", None, None)
        .await
        .expect_err("strict mode must not authorize a grant from an unenrolled key");
    assert!(
        err.contains("not trusted"),
        "expected issuer-trust refusal, got: {err}"
    );
}

/// Control for the test above: the same flow with the issuer key enrolled
/// keeps authorizing, so the refusal is the trust anchor and nothing else.
#[tokio::test]
async fn check_grant_accepts_an_enrolled_issuer_when_strict() {
    let key = SigningKey::from_bytes(&[0x43; 32]);
    let mut server = McpServer::new_insecure_unsigned_grants(Arc::new(ToolRegistry::new()))
        .with_trusted_issuer(key.verifying_key().to_bytes(), "0xorg");
    server
        .try_add_grant(signed_grant(&key, "0xorg", false))
        .await
        .expect("store");
    server.set_require_signed_grants(true);
    server
        .check_grant("pin-grant", "check_balance", None, None)
        .await
        .expect("an enrolled issuer still authorizes in strict mode");
}

/// The signature covers the revocation flag: a signature made over a live
/// grant does not verify for the same grant marked revoked (and vice versa).
#[test]
fn grant_signature_binds_the_revoked_flag() {
    let key = SigningKey::from_bytes(&[0x44; 32]);
    let live = signed_grant(&key, "0xorg", false);
    live.verify_signature()
        .expect("control: verifies as signed");
    let mut flipped = live.clone();
    flipped.revoked = true;
    assert!(
        flipped.verify_signature().is_err(),
        "a signature over revoked=false must not verify for revoked=true"
    );
    assert_ne!(live.signing_preimage(), flipped.signing_preimage());
}

fn approval(id: &str, timeout_seconds: u64) -> ApprovalRequest {
    ApprovalRequest {
        request_id: id.to_string(),
        session_id: "pin".to_string(),
        tool_name: "send_tx".to_string(),
        params: serde_json::json!({}),
        risk_level: "high".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        timeout_seconds,
        resolved: None,
        resolved_at: None,
    }
}

/// A caller-supplied timeout cannot keep an approval pending forever: an
/// `u64::MAX` timeout still auto-denies within the store's one-hour ceiling.
#[tokio::test(start_paused = true)]
async fn an_unbounded_approval_timeout_still_auto_denies_within_the_ceiling() {
    let store = PendingApprovalStore::new();
    let rx = store.submit(approval("forever", u64::MAX)).await;
    tokio::time::sleep(Duration::from_secs(3600 + 1)).await;
    let decided = tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .expect("the approval must have resolved by the ceiling");
    assert!(
        !decided.expect("sender kept"),
        "an expired approval is a deny"
    );
    assert_eq!(store.pending_count().await, 0);
}
