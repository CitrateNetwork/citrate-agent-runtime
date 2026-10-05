//! HUP-S9.3 / RA-15: the exported trajectory fixture the federated-learning data converter is
//! tested against (citrate-compute-pool `training-worker/src/fl/dataset.rs`).
//!
//! The fixture is produced by [`export_verified`] itself, never written by hand, so the
//! converter's test proves something about what this exporter really emits. Both repos pin the
//! file's sha256 (`FL_EXPORT_V1_SHA256`): a change to the exporter's output shape or its
//! redaction fails here until the fixture is regenerated and copied, byte for byte, to
//! compute-pool `training-worker/tests/fixtures/fl/export-v1.jsonl`, and both pins are bumped.
//!
//! Regenerate with `CITRATE_UPDATE_FL_FIXTURE=1 cargo test -p citrate-agent-trajectory --test
//! fl_fixture_tests`.
//!
//! The trajectories are scripted, not recorded from a member: every name, address and path in
//! them is synthetic. One turn deliberately repeats a toolcall-v2 eval prompt with different
//! casing and punctuation, so the converter's held-out check has a real case to remove.
use citrate_agent_loop::{Message, Role, ToolCall};
use citrate_agent_trajectory::*;
use sha2::{Digest, Sha256};

const FIXTURE: &str = "tests/fixtures/fl-export-v1.jsonl";
/// Pinned in compute-pool too (`training-worker/src/fl/dataset_tests.rs`).
const FL_EXPORT_V1_SHA256: &str =
    "3db35d06ea8ff9bdcfabf39abcb16e73b9a43eccdfa8747c5db4ebb82273a719";

fn assistant(content: &str, calls: &[(&str, &str, &str)]) -> Message {
    Message {
        role: Role::Assistant,
        content: content.into(),
        tool_calls: calls
            .iter()
            .map(|(id, name, args)| ToolCall {
                id: (*id).into(),
                name: (*name).into(),
                arguments: (*args).into(),
            })
            .collect(),
        tool_call_id: None,
    }
}

fn turn(
    messages: Vec<Message>,
    verifiers: &[(&str, bool)],
    outcome: &str,
    tainted: bool,
) -> TurnTrajectory {
    TurnTrajectory {
        session_id: "sess-fixture".into(),
        model: "gemma-4-E4B-it-Q4_0".into(),
        workflow: None,
        step: None,
        outcome: outcome.into(),
        messages,
        verifiers: verifiers
            .iter()
            .map(|(n, p)| VerifierVerdict {
                name: (*n).into(),
                passed: *p,
            })
            .collect(),
        session_tainted: tainted,
    }
}

fn trajectories() -> Vec<TurnTrajectory> {
    let node_status = || {
        vec![
            Message::user("Is my node synced? Reply to member@example.org if anything looks off."),
            assistant("", &[("c1", "node_status", "{}")]),
            Message::tool_result(
                "c1",
                r#"{"height":71604,"syncing":false,"peer":"0x1111111111111111111111111111111111111111"}"#,
            ),
            assistant("Your node is synced at block 71604.", &[]),
        ]
    };
    vec![
        // 1. verified, two parity-v1 tools, an email and an address to redact
        turn(
            node_status(),
            &[("tool_succeeded node_status", true)],
            "answered",
            false,
        ),
        // 2. verified, a path outside the granted root and one inside it
        turn(
            vec![
                Message::user(
                    "Note in my journal that the audit notes in /Users/member/private/audit.md \
                     and /Users/member/work/app/README.md are done.",
                ),
                assistant(
                    "",
                    &[(
                        "c2",
                        "journal_append",
                        r#"{"text":"Audit notes done: /Users/member/private/audit.md, /Users/member/work/app/README.md"}"#,
                    )],
                ),
                Message::tool_result("c2", r#"{"ok":true}"#),
                assistant("Added to your journal.", &[]),
            ],
            &[("tool_succeeded journal_append", true)],
            "answered",
            false,
        ),
        // 3. verified, but the tool is an MCP server's, outside the parity-v1 schema
        turn(
            vec![
                Message::user("Write a note saying the deploy finished."),
                assistant(
                    "",
                    &[(
                        "c3",
                        "mcp__fixture__write_note",
                        r#"{"text":"deploy finished"}"#,
                    )],
                ),
                Message::tool_result("c3", r#"{"ok":true}"#),
                assistant("Saved the note.", &[]),
            ],
            &[("tool_succeeded mcp__fixture__write_note", true)],
            "answered",
            false,
        ),
        // 4. verified, and its prompt is toolcall-v2's tc-node-height (case and punctuation differ)
        turn(
            vec![
                Message::user("what block height is my node at, right now"),
                assistant("", &[("c4", "node_status", "{}")]),
                Message::tool_result("c4", r#"{"height":71604}"#),
                assistant("Block 71604.", &[]),
            ],
            &[("tool_succeeded node_status", true)],
            "answered",
            false,
        ),
        // 5. verified, but the model's arguments are not a JSON object
        turn(
            vec![
                Message::user("List the models I have installed."),
                assistant("", &[("c5", "models_list", "models please")]),
                Message::tool_result("c5", r#"{"models":[]}"#),
                assistant("You have no models installed.", &[]),
            ],
            &[("answer_contains no models", true)],
            "answered",
            false,
        ),
        // 6. verified, an exact repeat of 1
        turn(
            node_status(),
            &[("tool_succeeded node_status", true)],
            "answered",
            false,
        ),
        // 7. no verifier judged it: the exporter leaves it out
        turn(
            vec![
                Message::user("What groups am I in?"),
                assistant("You are in two groups.", &[]),
            ],
            &[],
            "answered",
            false,
        ),
        // 8. the session read untrusted content: the exporter leaves it out
        turn(
            vec![
                Message::user("Summarize that page and add it to my journal."),
                assistant("", &[("c8", "journal_append", r#"{"text":"summary"}"#)]),
                Message::tool_result("c8", r#"{"ok":true}"#),
                assistant("Done.", &[]),
            ],
            &[("tool_succeeded journal_append", true)],
            "answered",
            true,
        ),
    ]
}

fn policy() -> ExportPolicy {
    ExportPolicy::new()
        .with_granted_root("/Users/member/work/app")
        .with_home("/Users/member")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn the_fl_export_fixture_is_what_export_verified_emits() {
    let ex = export_verified(&trajectories(), &policy()).unwrap();
    assert_eq!(ex.report.considered, 8);
    assert_eq!(ex.report.exported, 6);
    assert_eq!(ex.report.excluded.unverified, 1);
    assert_eq!(ex.report.excluded.tainted_session, 1);
    let jsonl = ex.to_jsonl().unwrap();

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    if std::env::var("CITRATE_UPDATE_FL_FIXTURE").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &jsonl).unwrap();
        eprintln!(
            "wrote {} sha256 {}",
            path.display(),
            sha256_hex(jsonl.as_bytes())
        );
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        committed, jsonl,
        "regenerate the fixture (see the module docs)"
    );
    assert_eq!(sha256_hex(committed.as_bytes()), FL_EXPORT_V1_SHA256);
}

#[test]
fn the_fixture_carries_redaction_markers_and_no_raw_value() {
    let ex = export_verified(&trajectories(), &policy()).unwrap();
    let jsonl = ex.to_jsonl().unwrap();
    for marker in [
        "[REDACTED:email]",
        "[REDACTED:address]",
        "[REDACTED:path]",
        "[root:0]",
    ] {
        assert!(jsonl.contains(marker), "{marker} missing");
    }
    for raw in [
        "member@example.org",
        "0x1111111111111111111111111111111111111111",
        "/Users/member",
        "sess-fixture",
    ] {
        assert!(!jsonl.contains(raw), "{raw} leaked");
    }
}
