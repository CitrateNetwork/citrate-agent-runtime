//! HUP-S5.4 over HUP-S2.9: a step's diff for the Code and diff pop-out. The before side is the
//! step's own snapshot; the after side is read from disk only while it still holds what the step
//! left there.

use std::fs;

use citrate_agent_checkpoints::{
    Change, CheckpointStore, Config, Error, SessionId, Side, StepStatus,
};

fn setup() -> (tempfile::TempDir, CheckpointStore, std::path::PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().join("granted");
    fs::create_dir_all(&root).expect("root");
    let store = CheckpointStore::open(&tmp.path().join("cp"), Config::default()).expect("open");
    (tmp, store, root)
}

fn sid(s: &str) -> SessionId {
    SessionId::new(s).expect("sid")
}

fn text(s: &str) -> Side {
    Side::Text {
        text: s.to_string(),
    }
}

#[test]
fn an_edit_shows_the_snapshot_before_and_the_file_after() {
    let (_t, store, root) = setup();
    let p = root.join("notes.md");
    fs::write(&p, "line one\nline two\n").expect("seed");
    let s = sid("d1");
    let step = store
        .begin_step(
            &s,
            &root,
            &[Change::write("notes.md", b"line one\nline 2\n")],
        )
        .expect("begin");
    fs::write(&p, "line one\nline 2\n").expect("write");
    step.commit().expect("commit");
    let d = store.step_diff(&s, 1, 1024).expect("diff");
    assert_eq!(d.seq, 1);
    assert_eq!(d.status, StepStatus::Committed);
    assert_eq!(d.files.len(), 1);
    assert_eq!(d.files[0].path, "notes.md");
    assert_eq!(d.files[0].before, text("line one\nline two\n"));
    assert_eq!(d.files[0].after, text("line one\nline 2\n"));
    let json = serde_json::to_value(&d).expect("json");
    assert_eq!(json["files"][0]["before"]["kind"], "text");
    assert_eq!(json["status"], "committed");
}

#[test]
fn a_new_file_a_deletion_and_a_rename_show_absent_sides() {
    let (_t, store, root) = setup();
    let s = sid("d2");
    let step = store
        .begin_step(&s, &root, &[Change::write("new.txt", b"hello")])
        .expect("begin");
    fs::write(root.join("new.txt"), "hello").expect("write");
    step.commit().expect("commit");
    let d = store.step_diff(&s, 1, 1024).expect("diff");
    assert_eq!(d.files[0].before, Side::Absent);
    assert_eq!(d.files[0].after, text("hello"));

    let step = store
        .begin_step(&s, &root, &[Change::delete("new.txt")])
        .expect("begin");
    fs::remove_file(root.join("new.txt")).expect("rm");
    step.commit().expect("commit");
    let d = store.step_diff(&s, 2, 1024).expect("diff");
    assert_eq!(d.files[0].before, text("hello"));
    assert_eq!(d.files[0].after, Side::Absent);

    fs::write(root.join("a.txt"), "AAA").expect("a");
    let step = store
        .begin_step(&s, &root, &[Change::rename("a.txt", "b.txt")])
        .expect("begin");
    fs::rename(root.join("a.txt"), root.join("b.txt")).expect("mv");
    step.commit().expect("commit");
    let d = store.step_diff(&s, 3, 1024).expect("diff");
    let by: std::collections::HashMap<&str, (&Side, &Side)> = d
        .files
        .iter()
        .map(|f| (f.path.as_str(), (&f.before, &f.after)))
        .collect();
    assert_eq!(by["a.txt"], (&text("AAA"), &Side::Absent));
    assert_eq!(by["b.txt"], (&Side::Absent, &text("AAA")));
}

#[test]
fn a_later_change_or_an_undo_hides_the_after_side_with_a_reason() {
    let (_t, store, root) = setup();
    let p = root.join("f.txt");
    fs::write(&p, "v1").expect("seed");
    let s = sid("d3");
    let step = store
        .begin_step(&s, &root, &[Change::write("f.txt", b"v2")])
        .expect("begin");
    fs::write(&p, "v2").expect("write");
    step.commit().expect("commit");
    fs::write(&p, "v3 by the member").expect("later edit");
    let d = store.step_diff(&s, 1, 1024).expect("diff");
    assert_eq!(d.files[0].before, text("v1"));
    match &d.files[0].after {
        Side::Unavailable { reason } => {
            assert!(reason.contains("changed after this step"), "{reason}")
        }
        other => panic!("{other:?}"),
    }
    fs::write(&p, "v2").expect("back");
    store.undo_step(&s, 1).expect("undo");
    let d = store.step_diff(&s, 1, 1024).expect("diff");
    assert_eq!(d.status, StepStatus::Undone);
    assert_eq!(d.files[0].before, text("v1"), "the snapshot is still shown");
    match &d.files[0].after {
        Side::Unavailable { reason } => assert!(reason.contains("undone"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn binary_and_large_content_is_described_not_sent() {
    let (_t, store, root) = setup();
    let s = sid("d4");
    fs::write(root.join("img.bin"), [0u8, 159, 146, 150]).expect("bin");
    fs::write(root.join("big.txt"), "x".repeat(4096)).expect("big");
    let step = store
        .begin_step(
            &s,
            &root,
            &[
                Change::write("img.bin", &[1u8, 0, 2]),
                Change::write("big.txt", "y".repeat(5000).as_bytes()),
            ],
        )
        .expect("begin");
    fs::write(root.join("img.bin"), [1u8, 0, 2]).expect("w");
    fs::write(root.join("big.txt"), "y".repeat(5000)).expect("w");
    step.commit().expect("commit");
    let d = store.step_diff(&s, 1, 1024).expect("diff");
    let img = d.files.iter().find(|f| f.path == "img.bin").expect("img");
    assert_eq!(img.before, Side::Binary { size: 4 });
    assert_eq!(img.after, Side::Binary { size: 3 });
    let big = d.files.iter().find(|f| f.path == "big.txt").expect("big");
    assert_eq!(big.before, Side::TooLarge { size: 4096 });
    assert_eq!(big.after, Side::TooLarge { size: 5000 });
    let json = serde_json::to_string(&d).expect("json");
    assert!(
        !json.contains("xxxx") && !json.contains("yyyy"),
        "no oversize content"
    );
}

#[test]
fn an_unknown_step_is_not_found_and_reading_changes_nothing() {
    let (_t, store, root) = setup();
    let s = sid("d5");
    assert!(matches!(
        store.step_diff(&s, 1, 1024),
        Err(Error::NotFound { .. })
    ));
    fs::write(root.join("k.txt"), "keep").expect("seed");
    let step = store
        .begin_step(&s, &root, &[Change::write("k.txt", b"kept")])
        .expect("begin");
    fs::write(root.join("k.txt"), "kept").expect("w");
    step.commit().expect("commit");
    let before = store.steps(&s).expect("steps");
    let _ = store.step_diff(&s, 1, 1024).expect("diff");
    assert_eq!(store.steps(&s).expect("steps"), before);
    assert_eq!(
        fs::read_to_string(root.join("k.txt")).expect("read"),
        "kept"
    );
    store
        .undo_step(&s, 1)
        .expect("undo still works after a diff");
    assert_eq!(
        fs::read_to_string(root.join("k.txt")).expect("read"),
        "keep"
    );
}

/// Every file under `dir` (recursively) whose bytes are exactly `content`.
fn files_holding(dir: &std::path::Path, content: &[u8]) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).expect("read_dir").flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files_holding(&p, content));
        } else if fs::read(&p).map(|b| b == content).unwrap_or(false) {
            out.push(p);
        }
    }
    out
}

#[test]
fn a_tampered_or_missing_snapshot_is_unavailable_never_shown() {
    let (t, store, root) = setup();
    let p = root.join("t.txt");
    fs::write(&p, "original snapshot text").expect("seed");
    let s = sid("d6");
    let step = store
        .begin_step(&s, &root, &[Change::write("t.txt", b"after")])
        .expect("begin");
    fs::write(&p, "after").expect("write");
    step.commit().expect("commit");
    let blobs = files_holding(&t.path().join("cp"), b"original snapshot text");
    assert_eq!(blobs.len(), 1, "one saved copy of the before side");
    fs::write(&blobs[0], "tampered snapshot text").expect("tamper");
    let d = store.step_diff(&s, 1, 1024).expect("diff");
    match &d.files[0].before {
        Side::Unavailable { reason } => assert!(reason.contains("checksum"), "{reason}"),
        other => panic!("tampered content was shown: {other:?}"),
    }
    assert_eq!(d.files[0].after, text("after"));
    fs::remove_file(&blobs[0]).expect("remove");
    let d = store.step_diff(&s, 1, 1024).expect("diff");
    match &d.files[0].before {
        Side::Unavailable { reason } => assert!(reason.contains("missing"), "{reason}"),
        other => panic!("{other:?}"),
    }
}
