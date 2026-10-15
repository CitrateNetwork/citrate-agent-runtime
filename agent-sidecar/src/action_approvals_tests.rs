//! HGW-1 — untrusted-content taint escalates to HIC approval instead of ending the conversation.
//!
//! Owner decision 2026-10-15 (HGW (2)): once a session has read untrusted content, every
//! side-effecting action goes to the member as an approval card that shows what is about to run
//! and why it is gated. An approval releases that one action; the session stays tainted, so the
//! next action asks again. Where nobody can be asked (a session not opened by an HIC-aware app,
//! for example a headless run), the action is declined with a message that says so. Taint still
//! never allows a silent or automatic action.
//!
//! BDD map:
//! - AT-1.1 (three or more consecutive `shell_run`s, file writes after taint):
//!   `after_taint_commands_and_writes_go_to_a_card_and_run_when_approved`.
//! - Per-action, not global: `an_approval_releases_one_action_and_the_next_asks_again`.
//! - Exact subject: `a_decision_must_carry_the_arguments_that_were_shown`.
//! - Headless: `without_an_hic_aware_app_tainted_actions_are_declined_and_say_why`.
//! - Routes: `the_action_routes_need_the_bearer_and_a_known_session`.
//! - Records: `action_decisions_are_recorded_for_the_anchor`.
//! - Explicit clear (HGW-W1, #74): `taint_clear_is_an_explicit_recorded_member_action`.
//! - Ask, don't retry: `a_declined_action_tells_the_model_to_ask_not_retry`.

#![cfg(unix)]

use super::hgw_support::*;
use super::*;
use axum::http::StatusCode;
use citrate_agent_loop::AssistantTurn;

fn reason_of(card: &serde_json::Value) -> String {
    card["hicReason"].as_str().unwrap_or_default().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn after_taint_commands_and_writes_go_to_a_card_and_run_when_approved() {
    let fx = Fx::new("taint-cards");
    let proj = fx.proj();
    let written = proj.join("src/index.js");
    let turns = vec![
        AssistantTurn::tools(vec![shell("c1", &["echo", "one"], &proj)]),
        AssistantTurn::tools(vec![fs_write("c2", &written, "console.log('hi')\n")]),
        AssistantTurn::tools(vec![shell("c3", &["echo", "two"], &proj)]),
        AssistantTurn::tools(vec![shell("c4", &["echo", "three"], &proj)]),
        AssistantTurn::text("Built."),
    ];
    let mgr = Arc::new(manager_with(&fx, turns, Some(shell_open())));
    let id = mgr.create(create_req(fx.rw_doc(), true)).expect("session");
    let s = mgr.get(&id).expect("session");
    let app = app_for(mgr.clone());
    mgr.send(&id, "build it".into(), None).expect("send");
    let answered = member_answers(&app, &s, &id, |_, _| true).await;

    // Every call ran: one untainted command, then three tainted actions, each released by a card.
    for c in ["c1", "c2", "c3", "c4"] {
        assert_eq!(result_of(&s, c).await["status"], "ok", "{c}");
    }
    assert_eq!(
        std::fs::read_to_string(&written).expect("written"),
        "console.log('hi')\n"
    );
    let routes: Vec<&str> = answered.iter().map(|a| a.route).collect();
    assert_eq!(routes, vec!["shell", "actions", "shell", "shell"]);
    // The first command was asked before any taint: no taint reason on its card.
    assert!(
        answered[0].card.get("hicReason").is_none(),
        "{}",
        answered[0].card
    );
    // The write's card shows what will run and why it is gated.
    let w = &answered[1].card;
    assert_eq!(w["tool"], "fs_write");
    assert_eq!(w["hic"], "required");
    assert!(
        w["id"].as_str().unwrap_or_default().starts_with("act-"),
        "{w}"
    );
    assert!(reason_of(w).contains("shell_run"), "{w}");
    assert_eq!(w["taintSources"], serde_json::json!(["shell_run"]));
    assert!(
        w["subject"]
            .as_str()
            .unwrap_or_default()
            .contains("index.js"),
        "the card shows the exact arguments: {w}"
    );
    assert!(
        w["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("fs_write"),
        "{w}"
    );
    // Later commands' cards carry the same reason.
    for a in &answered[2..] {
        assert!(reason_of(&a.card).contains("shell_run"), "{}", a.card);
        assert_eq!(a.card["taintSources"], serde_json::json!(["shell_run"]));
    }
    // No "host cannot ask" decline anywhere in the session.
    assert!(!events(&s).iter().any(|e| e["content"]
        .as_str()
        .unwrap_or_default()
        .contains("no member can be asked")));
    // The session is still tainted: approvals never clear it.
    assert!(s.taint().is_tainted());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_releases_one_action_and_the_next_asks_again() {
    let fx = Fx::new("taint-per-action");
    let proj = fx.proj();
    let a = proj.join("a.txt");
    let b = proj.join("b.txt");
    let turns = vec![
        AssistantTurn::tools(vec![shell("c1", &["echo", "x"], &proj)]),
        AssistantTurn::tools(vec![fs_write("c2", &a, "A")]),
        AssistantTurn::tools(vec![fs_write("c3", &b, "B")]),
        AssistantTurn::text("ok"),
    ];
    let mgr = Arc::new(manager_with(&fx, turns, Some(shell_open())));
    let id = mgr.create(create_req(fx.rw_doc(), true)).expect("session");
    let s = mgr.get(&id).expect("session");
    let app = app_for(mgr.clone());
    mgr.send(&id, "go".into(), None).expect("send");
    let b_shown = b.clone();
    let answered = member_answers(&app, &s, &id, move |route, card| {
        // Nothing is written before the member decides.
        if route == "actions" {
            assert!(!b_shown.exists());
        }
        // Allow the command and the first write; decline the second write.
        !(route == "actions"
            && card["subject"]
                .as_str()
                .unwrap_or_default()
                .contains("b.txt"))
    })
    .await;
    assert_eq!(
        answered.iter().filter(|a| a.route == "actions").count(),
        2,
        "each write asked on its own"
    );
    assert_eq!(std::fs::read_to_string(&a).expect("a"), "A");
    assert!(!b.exists(), "a declined action never runs");
    let r = result_of(&s, "c3").await;
    assert_eq!(r["status"], "denied", "{r}");
    assert!(
        r["content"]
            .as_str()
            .unwrap_or_default()
            .contains("declined"),
        "{r}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_decision_must_carry_the_arguments_that_were_shown() {
    let fx = Fx::new("taint-subject");
    let proj = fx.proj();
    let f = proj.join("f.txt");
    let turns = vec![
        AssistantTurn::tools(vec![shell("c1", &["echo", "x"], &proj)]),
        AssistantTurn::tools(vec![fs_write("c2", &f, "F")]),
        AssistantTurn::text("ok"),
    ];
    let mgr = Arc::new(manager_with(&fx, turns, Some(shell_open())));
    let id = mgr.create(create_req(fx.rw_doc(), true)).expect("session");
    let s = mgr.get(&id).expect("session");
    let app = app_for(mgr.clone());
    mgr.send(&id, "go".into(), None).expect("send");
    // Approve the command, then find the write's card.
    let mut card = serde_json::Value::Null;
    for _ in 0..1500 {
        let (_, sh) = send(&app, "GET", &format!("/sessions/{id}/shell/pending"), None).await;
        if let Some(c) = sh["pending"].as_array().and_then(|a| a.first()).cloned() {
            let (st, _) = send(
                &app,
                "POST",
                &format!("/sessions/{id}/shell/decide"),
                Some(serde_json::json!({"id": c["id"], "allow": true, "argv": c["argv"], "cwd": c["cwd"]})),
            )
            .await;
            assert_eq!(st, StatusCode::OK);
        }
        let (_, ac) = send(
            &app,
            "GET",
            &format!("/sessions/{id}/approvals/pending"),
            None,
        )
        .await;
        if let Some(c) = ac["pending"].as_array().and_then(|a| a.first()).cloned() {
            card = c;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(card.is_object(), "no action card appeared");
    let aid = card["id"].as_str().unwrap_or_default().to_string();
    let url = format!("/sessions/{id}/approvals/{aid}/decide");
    let (st, _) = send(
        &app,
        "POST",
        &url,
        Some(serde_json::json!({"allow": true, "subject": "{\"path\":\"/etc/x\"}"})),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(!f.exists(), "a mismatched decision releases nothing");
    let (st, _) = send(
        &app,
        "POST",
        &format!("/sessions/{id}/approvals/act-999/decide"),
        Some(serde_json::json!({"allow": true, "subject": card["subject"]})),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = send(
        &app,
        "POST",
        &url,
        Some(serde_json::json!({"allow": "yes"})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = send(
        &app,
        "POST",
        &url,
        Some(serde_json::json!({"allow": true, "subject": card["subject"]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    wait_done(&s).await;
    assert_eq!(std::fs::read_to_string(&f).expect("f"), "F");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_hic_aware_app_tainted_actions_are_declined_and_say_why() {
    let fx = Fx::new("taint-headless");
    let proj = fx.proj();
    let f = proj.join("f.txt");
    let turns = vec![
        AssistantTurn::tools(vec![shell("c1", &["echo", "x"], &proj)]),
        AssistantTurn::tools(vec![fs_write("c2", &f, "F")]),
        AssistantTurn::tools(vec![shell("c3", &["echo", "y"], &proj)]),
        AssistantTurn::text("ok"),
    ];
    let mgr = Arc::new(manager_with(&fx, turns, Some(shell_open())));
    let id = mgr.create(create_req(fx.rw_doc(), false)).expect("session");
    let s = mgr.get(&id).expect("session");
    let app = app_for(mgr.clone());
    mgr.send(&id, "go".into(), None).expect("send");
    // The untainted first command still waits for a decision on the shell route, as before.
    let answered = member_answers(&app, &s, &id, |_, _| true).await;
    assert_eq!(
        answered.len(),
        1,
        "only the untainted command was asked: {answered:?}"
    );
    assert_eq!(answered[0].route, "shell");
    for c in ["c2", "c3"] {
        let r = result_of(&s, c).await;
        assert_eq!(r["status"], "denied", "{r}");
        let msg = r["content"].as_str().unwrap_or_default();
        assert!(msg.contains("no member can be asked"), "{msg}");
        assert!(msg.contains("from shell_run"), "{msg}");
    }
    assert!(!f.exists());
    let (st, body) = send(
        &app,
        "GET",
        &format!("/sessions/{id}/approvals/pending"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["pending"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_action_routes_need_the_bearer_and_a_known_session() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    let fx = Fx::new("taint-routes");
    let mgr = Arc::new(manager_with(&fx, vec![], Some(shell_open())));
    let id = mgr.create(create_req(fx.rw_doc(), true)).expect("session");
    let app = app_for(mgr);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sessions/{id}/approvals/pending"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let (st, _) = send(&app, "GET", "/sessions/nope/approvals/pending", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _) = send(
        &app,
        "POST",
        "/sessions/nope/approvals/act-1/decide",
        Some(serde_json::json!({"allow": true, "subject": "{}"})),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// HUP-S2.6: every member decision on an action card lands in the decision log the nightly
/// anchor batches (write-ahead for an allow).
#[tokio::test(flavor = "multi_thread")]
async fn action_decisions_are_recorded_for_the_anchor() {
    use citrate_agent_records::{Decision, DecisionLog, Entry, LogConfig, Outcome};
    let fx = Fx::new("taint-records");
    let records_dir = fx.base.join("records");
    let (log, _) = DecisionLog::open(&records_dir, LogConfig::default()).expect("log");
    let proj = fx.proj();
    let turns = vec![
        AssistantTurn::tools(vec![shell("c1", &["echo", "x"], &proj)]),
        AssistantTurn::tools(vec![fs_write("c2", &proj.join("a.txt"), "A")]),
        AssistantTurn::tools(vec![fs_write("c3", &proj.join("b.txt"), "B")]),
        AssistantTurn::text("ok"),
    ];
    let mgr = Arc::new(manager_with(&fx, turns, Some(shell_open())).with_records(Arc::new(log)));
    let id = mgr.create(create_req(fx.rw_doc(), true)).expect("session");
    let s = mgr.get(&id).expect("session");
    let app = app_for(mgr.clone());
    mgr.send(&id, "go".into(), None).expect("send");
    member_answers(&app, &s, &id, |route, card| {
        !(route == "actions"
            && card["subject"]
                .as_str()
                .unwrap_or_default()
                .contains("b.txt"))
    })
    .await;
    let mut recs = citrate_agent_records::read::page(&records_dir, None, 10_000).expect("records");
    recs.sort_by_key(|r| r.record.seq);
    let decisions: Vec<(u64, Decision, String)> = recs
        .iter()
        .filter_map(|r| match &r.record.entry {
            Entry::Decision(d) if d.kind == "sidecar.tool_call" => {
                Some((r.record.seq, d.decision, d.subject.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(decisions.len(), 2, "{decisions:?}");
    assert_eq!(decisions[0].1, Decision::Approved);
    assert!(decisions[0].2.contains("fs_write"), "{decisions:?}");
    let outcome = recs.iter().find_map(|r| match &r.record.entry {
        Entry::Outcome(o) if o.decision_seq == decisions[0].0 => Some(o.outcome),
        _ => None,
    });
    assert_eq!(outcome, Some(Outcome::Completed));
    assert_eq!(decisions[1].1, Decision::Denied);
}

/// HGW-W1 (#74): a member can clear a session's taint, but only as an explicit, recorded action:
/// not for a scheduled run, not with an empty note, and not when the decision cannot be recorded
/// (write-ahead, fail closed). After a clear, effectful calls run without a card again.
#[tokio::test(flavor = "multi_thread")]
async fn taint_clear_is_an_explicit_recorded_member_action() {
    use citrate_agent_records::{Decision, DecisionLog, Entry, LogConfig};
    let fx = Fx::new("taint-clear");
    let f = fx.proj().join("after-clear.txt");
    // Without a records log, nothing is cleared.
    let mgr = Arc::new(manager_with(&fx, vec![], Some(shell_open())));
    let id = mgr.create(create_req(fx.rw_doc(), true)).expect("session");
    let s = mgr.get(&id).expect("session");
    s.taint().taint("shell_run", "output");
    let app = app_for(mgr.clone());
    let url = format!("/sessions/{id}/taint/clear");
    let (st, _) = send(
        &app,
        "POST",
        &url,
        Some(serde_json::json!({"note": "I read that output"})),
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert!(s.taint().is_tainted());
    // With records: an empty note is refused, a real one clears and is recorded.
    let dir = fx.base.join("records");
    let (log, _) = DecisionLog::open(&dir, LogConfig::default()).expect("log");
    let turns = vec![
        AssistantTurn::tools(vec![fs_write("c1", &f, "F")]),
        AssistantTurn::text("ok"),
    ];
    let mgr = Arc::new(manager_with(&fx, turns, Some(shell_open())).with_records(Arc::new(log)));
    let id = mgr.create(create_req(fx.rw_doc(), true)).expect("session");
    let s = mgr.get(&id).expect("session");
    s.taint().taint("shell_run", "output");
    let app = app_for(mgr.clone());
    let url = format!("/sessions/{id}/taint/clear");
    let (st, _) = send(&app, "POST", &url, Some(serde_json::json!({"note": "  "}))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, body) = send(
        &app,
        "POST",
        &url,
        Some(serde_json::json!({"note": "I read that output"})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["cleared"]["source"], "shell_run");
    assert!(!s.taint().is_tainted());
    let (st, _) = send(
        &app,
        "POST",
        &url,
        Some(serde_json::json!({"note": "again"})),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "nothing to clear");
    // The next write runs without a card.
    mgr.send(&id, "go".into(), None).expect("send");
    wait_done(&s).await;
    assert_eq!(result_of(&s, "c1").await["status"], "ok");
    assert!(f.exists());
    let recs = citrate_agent_records::read::page(&dir, None, 10_000).expect("records");
    assert!(recs.iter().any(|r| matches!(&r.record.entry,
        Entry::Decision(d) if d.kind == "taint.clear" && d.decision == Decision::Approved && d.subject.contains("shell_run"))));
    // A scheduled run's taint is never cleared.
    let mut req = create_req(fx.rw_doc(), true);
    req.unattended = true;
    let id = mgr.create(req).expect("session");
    let (st, _) = send(
        &app,
        "POST",
        &format!("/sessions/{id}/taint/clear"),
        Some(serde_json::json!({"note": "please"})),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(mgr.get(&id).expect("session").taint().is_tainted());
}

/// HGW-W1 (#74 AC3): a declined action tells the model to ask the member, not to retry.
#[tokio::test(flavor = "multi_thread")]
async fn a_declined_action_tells_the_model_to_ask_not_retry() {
    let fx = Fx::new("taint-decline-hint");
    let proj = fx.proj();
    let turns = vec![
        AssistantTurn::tools(vec![shell("c1", &["echo", "x"], &proj)]),
        AssistantTurn::tools(vec![fs_write("c2", &proj.join("a.txt"), "A")]),
        AssistantTurn::tools(vec![shell("c3", &["echo", "y"], &proj)]),
        AssistantTurn::text("ok"),
    ];
    let mgr = Arc::new(manager_with(&fx, turns, Some(shell_open())));
    let id = mgr.create(create_req(fx.rw_doc(), true)).expect("session");
    let s = mgr.get(&id).expect("session");
    let app = app_for(mgr.clone());
    mgr.send(&id, "go".into(), None).expect("send");
    // Allow the first command; decline the write and the second command.
    let mut n = 0;
    member_answers(&app, &s, &id, move |_, _| {
        n += 1;
        n == 1
    })
    .await;
    for c in ["c2", "c3"] {
        let r = result_of(&s, c).await;
        assert_eq!(r["status"], "denied", "{r}");
        let msg = r["content"].as_str().unwrap_or_default();
        assert!(msg.contains("ask the member"), "{msg}");
        assert!(msg.contains("instead of retrying"), "{msg}");
    }
}
