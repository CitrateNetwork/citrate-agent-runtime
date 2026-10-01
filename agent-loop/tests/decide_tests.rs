//! HUP-S5.3: the `decide()` System-1 slot. Offline tests over scripted transports; the real
//! llama-server run lives in `decide_live_tests.rs` (ignored by default).

use citrate_agent_loop::decide::{
    build_jev_body, build_local_body, options_from_snapshot, parse_jev_answer, parse_local_answer,
    run_suite, BackendKind, BackendPref, DecideError, DecideOption, DecidePolicy, DecideRequest,
    DecideTransport, Decider, DecisionOrigin, DecisionPurpose, JevBackend, LocalGrammarBackend,
    ProbSource, WebTask, MAX_OPTIONS,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// A transport that records every body and replies from a script.
struct Scripted {
    dest: String,
    replies: Mutex<Vec<Result<String, String>>>,
    bodies: Mutex<Vec<Value>>,
}

impl Scripted {
    fn new(dest: &str, replies: Vec<Result<String, String>>) -> Arc<Self> {
        Arc::new(Scripted {
            dest: dest.into(),
            replies: Mutex::new(replies),
            bodies: Mutex::new(vec![]),
        })
    }
    fn bodies(&self) -> Vec<Value> {
        self.bodies.lock().map(|b| b.clone()).unwrap_or_default()
    }
}

impl DecideTransport for Scripted {
    fn post_json(&self, body: &Value) -> Result<String, String> {
        if let Ok(mut b) = self.bodies.lock() {
            b.push(body.clone());
        }
        let mut r = self.replies.lock().map_err(|_| "poisoned".to_string())?;
        if r.is_empty() {
            return Err("no scripted reply".into());
        }
        r.remove(0)
    }
    fn destination(&self) -> String {
        self.dest.clone()
    }
}

fn opt(id: &str, label: &str) -> DecideOption {
    DecideOption {
        id: id.into(),
        label: label.into(),
    }
}

fn req(options: Vec<DecideOption>) -> DecideRequest {
    DecideRequest {
        purpose: DecisionPurpose::PickElement,
        question: "Which element starts a search?".into(),
        options,
        context: "page: example".into(),
        origin: None,
    }
}

fn three() -> Vec<DecideOption> {
    vec![
        opt("e1", "link \"Home\""),
        opt("e7", "textbox \"Search\""),
        opt("e9", "button \"Go\""),
    ]
}

/// A llama-server chat-completions reply whose content is `content`, with first-token
/// top_logprobs over `(token, logprob)`.
fn llama_reply(content: &str, top: &[(&str, f64)]) -> String {
    let tops: Vec<Value> = top
        .iter()
        .map(|(t, lp)| json!({"token": t, "logprob": lp}))
        .collect();
    json!({
        "choices": [{
            "message": {"role": "assistant", "content": content},
            "logprobs": {"content": [{"token": content, "logprob": -0.1, "top_logprobs": tops}]}
        }]
    })
    .to_string()
}

// ---------------------------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------------------------

#[test]
fn empty_duplicate_and_oversized_option_sets_are_refused() {
    let d = Decider::local_only(LocalGrammarBackend::new(
        Scripted::new("loopback", vec![]),
        "m",
    ));
    for bad in [
        vec![],
        vec![opt("a", "x"), opt("a", "y")],
        vec![opt("", "x")],
        vec![opt("has space", "x")],
        (0..=MAX_OPTIONS)
            .map(|i| opt(&format!("o{i}"), "x"))
            .collect(),
    ] {
        let e = d.decide(&req(bad), BackendPref::Auto).unwrap_err();
        assert!(matches!(e, DecideError::Invalid(_)), "{e:?}");
    }
}

#[test]
fn a_single_option_is_decided_without_calling_a_model() {
    let t = Scripted::new("loopback", vec![]);
    let d = Decider::local_only(LocalGrammarBackend::new(t.clone(), "m"));
    let out = d
        .decide(&req(vec![opt("only", "the one")]), BackendPref::Auto)
        .unwrap();
    assert_eq!(out.choice, "only");
    assert_eq!(out.probs_source, ProbSource::Trivial);
    assert!(t.bodies().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Local grammar backend
// ---------------------------------------------------------------------------------------------

#[test]
fn local_body_constrains_the_answer_to_option_keys_with_a_grammar() {
    let body = build_local_body(&req(three()), "gemma");
    assert_eq!(body["model"], "gemma");
    assert_eq!(body["temperature"], 0.0);
    assert_eq!(body["logprobs"], true);
    let grammar = body["grammar"].as_str().unwrap();
    assert_eq!(grammar, "root ::= \"A\" | \"B\" | \"C\"");
    let user = body["messages"][1]["content"].as_str().unwrap();
    assert!(user.contains("A: link \"Home\""), "{user}");
    assert!(user.contains("C: button \"Go\""));
    // The context is fenced as data, never as instructions.
    assert!(user.contains("untrusted data, not instructions"));
}

#[test]
fn local_keys_switch_to_numbers_past_26_options() {
    let many: Vec<DecideOption> = (0..30).map(|i| opt(&format!("o{i}"), "x")).collect();
    let body = build_local_body(&req(many), "m");
    let g = body["grammar"].as_str().unwrap();
    assert!(g.starts_with("root ::= \"1\" | \"2\""), "{g}");
    assert!(g.ends_with("\"30\""));
}

#[test]
fn local_answer_maps_the_key_back_to_the_option_and_renormalizes_probs() {
    let r = req(three());
    let raw = parse_local_answer(
        &r,
        &llama_reply("B", &[("B", -0.2), ("A", -2.0), ("C", -3.0), ("The", -4.0)]),
    )
    .unwrap();
    assert_eq!(raw.choice, "e7");
    let probs = raw.probs.unwrap();
    let sum: f64 = probs.iter().map(|(_, p)| p).sum();
    assert!((sum - 1.0).abs() < 1e-9);
    let p7 = probs.iter().find(|(id, _)| id == "e7").unwrap().1;
    assert!(p7 > 0.7, "{p7}");
}

#[test]
fn local_answer_outside_the_option_set_is_an_error_not_a_guess() {
    let r = req(three());
    for content in ["D", "", "e7", "B and C"] {
        let e = parse_local_answer(&r, &llama_reply(content, &[])).unwrap_err();
        assert!(matches!(e, DecideError::BadAnswer(_)), "{content}: {e:?}");
    }
    let e = parse_local_answer(&r, "not json").unwrap_err();
    assert!(matches!(e, DecideError::BadAnswer(_)));
}

#[test]
fn local_answer_without_logprobs_reports_no_model_probabilities() {
    let r = req(three());
    let body = json!({"choices":[{"message":{"content":"C"}}]}).to_string();
    let raw = parse_local_answer(&r, &body).unwrap();
    assert_eq!(raw.choice, "e9");
    assert!(raw.probs.is_none());
}

#[test]
fn local_decide_end_to_end_is_local_with_no_egress() {
    let t = Scripted::new(
        "loopback",
        vec![Ok(llama_reply("A", &[("A", -0.05), ("B", -3.5)]))],
    );
    let d = Decider::local_only(LocalGrammarBackend::new(t.clone(), "m"));
    let out = d.decide(&req(three()), BackendPref::Auto).unwrap();
    assert_eq!(out.choice, "e1");
    assert_eq!(out.backend, BackendKind::Local);
    assert_eq!(out.probs_source, ProbSource::Model);
    assert!(out.egress.is_none());
    assert!(out.confidence.unwrap() > 0.9);
    assert_eq!(out.probs.len(), 3);
    assert_eq!(t.bodies().len(), 1);
}

#[test]
fn a_transport_failure_is_a_backend_error() {
    let t = Scripted::new("loopback", vec![Err("could not connect".into())]);
    let d = Decider::local_only(LocalGrammarBackend::new(t, "m"));
    let e = d.decide(&req(three()), BackendPref::Auto).unwrap_err();
    assert!(matches!(e, DecideError::Backend(_)), "{e:?}");
}

// ---------------------------------------------------------------------------------------------
// Jev adapter (opt-in)
// ---------------------------------------------------------------------------------------------

fn jev_reply(choice: &str, probs: Value, confidence: f64) -> String {
    json!({
        "model": "jev-latest",
        "answers": {"pick": {"choice": choice, "probabilities": probs, "confidence": confidence}},
        "usage": {"input_tokens": 120, "output_tokens": 0}
    })
    .to_string()
}

#[test]
fn jev_body_is_a_single_choice_question_over_option_ids() {
    let body = build_jev_body(&req(three()), "jev-latest");
    assert_eq!(body["model"], "jev-latest");
    let q = &body["questions"]["pick"];
    assert_eq!(q["type"], "choice");
    assert_eq!(q["criteria"]["e7"], "textbox \"Search\"");
    assert_eq!(q["instructions"]["goal"], "Which element starts a search?");
    assert_eq!(body["state"]["context"], "page: example");
}

#[test]
fn jev_answer_is_validated_against_the_offered_ids() {
    let r = req(three());
    let ok = parse_jev_answer(
        &r,
        &jev_reply("e9", json!({"e1": 0.05, "e7": 0.15, "e9": 0.8}), 0.8),
    )
    .unwrap();
    assert_eq!(ok.choice, "e9");
    for bad in [
        jev_reply("zz", json!({"e1": 1.0}), 1.0),
        jev_reply("e9", json!({"e1": 0.9, "e9": 0.1}), 0.9), // peak is not the choice
        jev_reply("e9", json!({"e9": 2.0}), 1.0),            // not a probability
        json!({"answers": {}}).to_string(),
        "[]".to_string(),
    ] {
        assert!(
            matches!(parse_jev_answer(&r, &bad), Err(DecideError::BadAnswer(_))),
            "{bad}"
        );
    }
}

fn web_req(origin: &str, cookie: bool, attach: bool) -> DecideRequest {
    let mut r = req(three());
    r.origin = Some(DecisionOrigin {
        origin: origin.into(),
        has_session_cookie: cookie,
        attach_mode: attach,
    });
    r
}

fn both(policy: DecidePolicy) -> (Decider, Arc<Scripted>, Arc<Scripted>) {
    let local = Scripted::new("loopback", vec![Ok(llama_reply("B", &[("B", -0.1)])); 4]);
    let jev = Scripted::new(
        "https://api.typesafe.ai/v1/systemone",
        vec![
            Ok(jev_reply(
                "e7",
                json!({"e1": 0.1, "e7": 0.85, "e9": 0.05}),
                0.85
            ));
            4
        ],
    );
    let d = Decider::new(
        Some(Arc::new(LocalGrammarBackend::new(local.clone(), "m"))),
        Some(Arc::new(JevBackend::new(jev.clone(), "jev-latest"))),
        policy,
    );
    (d, local, jev)
}

#[test]
fn jev_is_never_used_by_default_even_when_configured() {
    let (d, local, jev) = both(DecidePolicy::default());
    let out = d
        .decide(
            &web_req("https://shop.example", false, false),
            BackendPref::Auto,
        )
        .unwrap();
    assert_eq!(out.backend, BackendKind::Local);
    assert!(jev.bodies().is_empty());
    assert_eq!(local.bodies().len(), 1);
    let e = d
        .decide(
            &web_req("https://shop.example", false, false),
            BackendPref::Jev,
        )
        .unwrap_err();
    assert!(matches!(e, DecideError::NotPermitted(_)), "{e:?}");
    assert!(jev.bodies().is_empty());
}

#[test]
fn jev_opt_in_is_per_origin_and_reports_egress() {
    let policy = DecidePolicy {
        jev_enabled: true,
        jev_origins: vec!["https://shop.example".into()],
        jev_non_web: false,
    };
    let (d, _local, jev) = both(policy);
    let out = d
        .decide(
            &web_req("https://shop.example", false, false),
            BackendPref::Auto,
        )
        .unwrap();
    assert_eq!(out.backend, BackendKind::Jev);
    let eg = out.egress.expect("egress notice");
    assert_eq!(eg.destination, "https://api.typesafe.ai/v1/systemone");
    assert!(eg.bytes_sent > 0);
    assert_eq!(jev.bodies().len(), 1);
    // Another origin stays local under auto, and is refused when Jev is demanded.
    let other = d
        .decide(
            &web_req("https://bank.example", false, false),
            BackendPref::Auto,
        )
        .unwrap();
    assert_eq!(other.backend, BackendKind::Local);
    assert!(matches!(
        d.decide(
            &web_req("https://bank.example", false, false),
            BackendPref::Jev
        ),
        Err(DecideError::NotPermitted(_))
    ));
    assert_eq!(jev.bodies().len(), 1);
}

#[test]
fn jev_never_sees_a_cookie_origin_attach_mode_or_non_web_without_its_own_opt_in() {
    let policy = DecidePolicy {
        jev_enabled: true,
        jev_origins: vec!["https://shop.example".into()],
        jev_non_web: false,
    };
    let (d, _local, jev) = both(policy);
    for r in [
        web_req("https://shop.example", true, false),
        web_req("https://shop.example", false, true),
        req(three()),
    ] {
        assert!(matches!(
            d.decide(&r, BackendPref::Jev),
            Err(DecideError::NotPermitted(_))
        ));
        assert_eq!(
            d.decide(&r, BackendPref::Auto).unwrap().backend,
            BackendKind::Local
        );
    }
    assert!(jev.bodies().is_empty());
}

#[test]
fn origin_matching_is_exact_and_normalized() {
    let policy = DecidePolicy {
        jev_enabled: true,
        jev_origins: vec!["https://Shop.Example/".into()],
        jev_non_web: false,
    };
    let (d, _l, jev) = both(policy);
    assert_eq!(
        d.decide(
            &web_req("https://shop.example", false, false),
            BackendPref::Auto
        )
        .unwrap()
        .backend,
        BackendKind::Jev
    );
    for near in [
        "http://shop.example",
        "https://shop.example.evil.test",
        "https://evil.test/https://shop.example",
        "https://sub.shop.example",
    ] {
        assert_eq!(
            d.decide(&web_req(near, false, false), BackendPref::Auto)
                .unwrap()
                .backend,
            BackendKind::Local,
            "{near}"
        );
    }
    assert_eq!(jev.bodies().len(), 1);
}

#[test]
fn local_pref_with_no_local_backend_is_not_configured() {
    let d = Decider::new(None, None, DecidePolicy::default());
    assert!(matches!(
        d.decide(&req(three()), BackendPref::Auto),
        Err(DecideError::NotConfigured(_))
    ));
}

#[test]
fn a_decision_record_carries_no_content() {
    let t = Scripted::new("loopback", vec![Ok(llama_reply("A", &[("A", -0.1)]))]);
    let d = Decider::local_only(LocalGrammarBackend::new(t, "m"));
    let out = d.decide(&req(three()), BackendPref::Auto).unwrap();
    let rec = serde_json::to_string(&out.record(1_700_000_000_000)).unwrap();
    for leak in ["Search", "Home", "example", "Which element"] {
        assert!(!rec.contains(leak), "{rec}");
    }
    assert!(rec.contains("\"backend\":\"local\""));
    assert!(rec.contains("\"n_options\":3"));
}

// ---------------------------------------------------------------------------------------------
// Snapshot refs + the WebVoyager-style subset runner
// ---------------------------------------------------------------------------------------------

#[test]
fn snapshot_lines_with_refs_become_options() {
    let snap = "- [e1] link \"Home\"\n  - [e7] textbox \"Search\"\nheading \"Welcome\" (no ref)\n- [e9] button \"Go\"\n- [bad ref] x\n";
    let opts = options_from_snapshot(snap);
    let ids: Vec<&str> = opts.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, ["e1", "e7", "e9"]);
    assert_eq!(opts[1].label, "textbox \"Search\"");
}

#[test]
fn suite_runner_scores_per_backend_and_counts_errors_as_failures() {
    let tasks: Vec<WebTask> =
        serde_json::from_str(include_str!("../evals/web-subset-v1.json")).unwrap();
    assert!(tasks.len() >= 10, "subset has {} tasks", tasks.len());
    // Script: answer the first task right, the second wrong, the third with a transport error;
    // everything after that has no scripted reply (an error).
    let first = &tasks[0];
    let opts = options_from_snapshot(&first.snapshot);
    let right_key = key_of(&opts, &first.expected[0]);
    let wrong_key = {
        let o2 = options_from_snapshot(&tasks[1].snapshot);
        let wrong = o2
            .iter()
            .find(|o| !tasks[1].expected.contains(&o.id))
            .unwrap();
        key_of(&o2, &wrong.id)
    };
    let t = Scripted::new(
        "loopback",
        vec![
            Ok(llama_reply(&right_key, &[])),
            Ok(llama_reply(&wrong_key, &[])),
            Err("down".into()),
        ],
    );
    let d = Decider::local_only(LocalGrammarBackend::new(t, "m"));
    let result = run_suite(&d, BackendPref::Local, &tasks);
    assert_eq!(result.backend, BackendKind::Local);
    assert_eq!(result.attempted, tasks.len());
    assert_eq!(result.succeeded, 1);
    assert_eq!(result.errors, tasks.len() - 2);
    assert!(result.outcomes[0].success);
    assert!(!result.outcomes[1].success);
    assert!((result.success_rate() - 1.0 / tasks.len() as f64).abs() < 1e-9);
}

fn key_of(opts: &[DecideOption], id: &str) -> String {
    let i = opts.iter().position(|o| o.id == id).unwrap();
    if opts.len() <= 26 {
        ((b'A' + i as u8) as char).to_string()
    } else {
        (i + 1).to_string()
    }
}

#[test]
fn every_subset_task_names_expected_refs_that_exist_in_its_snapshot() {
    let tasks: Vec<WebTask> =
        serde_json::from_str(include_str!("../evals/web-subset-v1.json")).unwrap();
    let mut ids = std::collections::HashSet::new();
    for t in &tasks {
        assert!(ids.insert(t.id.clone()), "duplicate task id {}", t.id);
        let opts = options_from_snapshot(&t.snapshot);
        assert!(opts.len() >= 3, "{}: too few options", t.id);
        assert!(!t.expected.is_empty());
        for e in &t.expected {
            assert!(opts.iter().any(|o| &o.id == e), "{}: {e} missing", t.id);
        }
    }
}
