//! HUP-S2.1: the serde persistence format core stores. A round trip keeps
//! every decision; a stored document that breaks a grant rule is refused as
//! a whole (fail closed) rather than loaded partially.

#![cfg(unix)]

use citrate_agent_grants::{
    Access, Decision, FolderGrants, GrantError, GrantRequest, GrantState, Op, STATE_VERSION,
};
use std::path::PathBuf;
use tempfile::TempDir;

const T0: u64 = 1_790_000_000;
const MEMBER: &str = "0x00000000000000000000000000000000000000aa";

fn fixture() -> (TempDir, PathBuf, PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let home = std::fs::canonicalize(tmp.path())
        .expect("canon")
        .join("home");
    let proj = home.join("proj");
    std::fs::create_dir_all(proj.join("src")).expect("mkdir");
    std::fs::write(proj.join("src/a.rs"), b"a").expect("write");
    (tmp, home, proj)
}

fn is_allowed(d: &Decision) -> bool {
    matches!(d, Decision::Allowed { .. })
}

#[test]
fn round_trip_preserves_grants_revocations_and_ids() {
    let (_t, home, proj) = fixture();
    let mut g = FolderGrants::new(&home, &proj);
    let a = g
        .grant(
            GrantRequest::folder(&proj, Access::Read, MEMBER, "read the code"),
            T0,
        )
        .expect("grant");
    let b = g
        .grant(
            GrantRequest::folder(&proj, Access::Write, MEMBER, "edit").with_ttl_secs(600),
            T0,
        )
        .expect("grant");
    let c = g
        .grant(GrantRequest::full_access(&home, 3600, MEMBER, "look"), T0)
        .expect("grant");
    g.revoke(&c, T0 + 1).expect("revoke");

    let json = g.to_json().expect("serialize");
    let back = FolderGrants::from_json(&json, &home, &proj).expect("load");
    assert_eq!(back.state(), g.state());

    let p = proj.join("src/a.rs").display().to_string();
    for (op, now) in [
        (Op::Read, T0),
        (Op::Write, T0 + 1),
        (Op::Write, T0 + 600),
        (Op::Read, T0 + 2),
    ] {
        assert_eq!(
            is_allowed(&g.check(&p, op, now)),
            is_allowed(&back.check(&p, op, now)),
            "{op:?} at {now}"
        );
    }

    // New ids never collide with loaded ones.
    let mut back = back;
    let d = back
        .grant(
            GrantRequest::folder(&proj, Access::Read, MEMBER, "again"),
            T0,
        )
        .expect("grant");
    assert!(d != a && d != b && d != c, "{d}");
}

#[test]
fn the_format_is_versioned_json_with_named_fields() {
    let (_t, home, proj) = fixture();
    let mut g = FolderGrants::new(&home, &proj);
    g.grant(GrantRequest::full_access(&home, 3600, MEMBER, "look"), T0)
        .expect("grant");
    let v: serde_json::Value = serde_json::from_str(&g.to_json().expect("json")).expect("parse");
    assert_eq!(v["version"], STATE_VERSION);
    let grant = &v["grants"][0];
    for key in [
        "id",
        "kind",
        "root",
        "access",
        "scope",
        "granted_at",
        "expires_at",
        "granted_by",
        "reason",
        "revoked_at",
    ] {
        assert!(grant.get(key).is_some(), "missing {key} in {grant}");
    }
    assert_eq!(grant["kind"], "full_access");
    assert_eq!(grant["access"], "read");
    assert_eq!(grant["expires_at"], T0 + 3600);
}

fn tamper(json: &str, f: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut v: serde_json::Value = serde_json::from_str(json).expect("parse");
    f(&mut v);
    serde_json::to_string(&v).expect("json")
}

#[test]
fn stored_documents_that_break_a_rule_are_refused() {
    let (_t, home, proj) = fixture();
    let mut g = FolderGrants::new(&home, &proj);
    g.grant(GrantRequest::full_access(&home, 3600, MEMBER, "look"), T0)
        .expect("grant");
    g.grant(
        GrantRequest::folder(&proj, Access::Write, MEMBER, "edit"),
        T0,
    )
    .expect("grant");
    let good = g.to_json().expect("json");
    assert!(FolderGrants::from_json(&good, &home, &proj).is_ok());

    let cases: Vec<(&str, String)> = vec![
        (
            "full access widened to write",
            tamper(&good, |v| v["grants"][0]["access"] = "write".into()),
        ),
        (
            "full access without expiry",
            tamper(&good, |v| {
                v["grants"][0]["expires_at"] = serde_json::Value::Null
            }),
        ),
        (
            "full access longer than 24 h",
            tamper(&good, |v| {
                v["grants"][0]["expires_at"] = (T0 + 86_401).into()
            }),
        ),
        (
            "relative root",
            tamper(&good, |v| v["grants"][1]["root"] = "proj".into()),
        ),
        (
            "write on the filesystem root",
            tamper(&good, |v| v["grants"][1]["root"] = "/".into()),
        ),
        (
            "root inside the deny list",
            tamper(&good, |v| {
                v["grants"][1]["root"] = home.join(".ssh").display().to_string().into()
            }),
        ),
        (
            "duplicate id",
            tamper(&good, |v| {
                let id = v["grants"][0]["id"].clone();
                v["grants"][1]["id"] = id;
            }),
        ),
        (
            "id at or above next_id",
            tamper(&good, |v| v["next_id"] = 1.into()),
        ),
        (
            "expiry not after grant time",
            tamper(&good, |v| v["grants"][1]["expires_at"] = T0.into()),
        ),
        (
            "empty granted_by",
            tamper(&good, |v| v["grants"][1]["granted_by"] = "".into()),
        ),
        (
            "unknown version",
            tamper(&good, |v| v["version"] = 99.into()),
        ),
        (
            "unknown field",
            tamper(&good, |v| v["grants"][1]["allow_all"] = true.into()),
        ),
        ("not json", "{".to_string()),
    ];
    for (name, doc) in cases {
        match FolderGrants::from_json(&doc, &home, &proj) {
            Err(GrantError::InvalidState(_)) => {}
            other => panic!("{name}: expected InvalidState, got {other:?}"),
        }
    }
}

#[test]
fn state_values_can_be_loaded_directly() {
    let (_t, home, proj) = fixture();
    let mut g = FolderGrants::new(&home, &proj);
    g.grant(GrantRequest::folder(&proj, Access::Read, MEMBER, "r"), T0)
        .expect("grant");
    let state: GrantState = g.state().clone();
    let back = FolderGrants::from_state(state, &home, &proj).expect("load");
    assert!(is_allowed(&back.check(
        proj.join("src/a.rs").display().to_string(),
        Op::Read,
        T0
    )));
}
