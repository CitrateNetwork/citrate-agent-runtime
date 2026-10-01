//! Red-green tests for HUP-S2.9 (runtime half): undo checkpoints for agent file writes.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use citrate_agent_checkpoints::{
    Change, CheckpointStore, Config, Error, SessionId, StepStatus, LOCK_FILE,
};

const MIB: u64 = 1024 * 1024;

struct Fx {
    _tmp: tempfile::TempDir,
    store_dir: PathBuf,
    root: PathBuf,
}

fn fx() -> Fx {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store_dir = tmp.path().join("app-data").join("checkpoints");
    let root = tmp.path().join("granted");
    fs::create_dir_all(&root).expect("mkdir root");
    Fx {
        _tmp: tmp,
        store_dir,
        root,
    }
}

fn cfg() -> Config {
    Config {
        max_store_bytes: 64 * MIB,
        max_file_bytes: 8 * MIB,
    }
}

fn open(f: &Fx) -> CheckpointStore {
    CheckpointStore::open(&f.store_dir, cfg()).expect("open store")
}

fn sid(s: &str) -> SessionId {
    SessionId::new(s).expect("session id")
}

fn read(p: &Path) -> Vec<u8> {
    fs::read(p).expect("read")
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(p).expect("meta").permissions().mode() & 0o7777
}

#[cfg(unix)]
fn set_mode(p: &Path, m: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(m)).expect("chmod");
}

// ---------------------------------------------------------------- basic undo

#[test]
fn write_then_undo_restores_prior_content() {
    let f = fx();
    let p = f.root.join("notes.md");
    fs::write(&p, b"original").expect("seed");
    let store = open(&f);
    let s = sid("sess-1");

    let step = store
        .begin_step(&s, &f.root, &[Change::write("notes.md", b"agent edit")])
        .expect("begin");
    fs::write(&p, b"agent edit").expect("write");
    let summary = step.commit().expect("commit");
    assert_eq!(summary.seq, 1);
    assert_eq!(summary.status, StepStatus::Committed);
    assert_eq!(summary.paths, vec!["notes.md".to_string()]);

    let report = store.undo_step(&s, 1).expect("undo");
    assert_eq!(report.restored, vec!["notes.md".to_string()]);
    assert_eq!(read(&p), b"original");
    let steps = store.steps(&s).expect("steps");
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].status, StepStatus::Undone);
}

#[cfg(unix)]
#[test]
fn undo_preserves_file_mode() {
    let f = fx();
    let p = f.root.join("run.sh");
    fs::write(&p, b"#!/bin/sh\necho hi\n").expect("seed");
    set_mode(&p, 0o751);
    let store = open(&f);
    let s = sid("mode");

    let step = store
        .begin_step(&s, &f.root, &[Change::write("run.sh", b"rm -rf /tmp/x\n")])
        .expect("begin");
    fs::write(&p, b"rm -rf /tmp/x\n").expect("write");
    set_mode(&p, 0o644);
    step.commit().expect("commit");

    store.undo_step(&s, 1).expect("undo");
    assert_eq!(read(&p), b"#!/bin/sh\necho hi\n");
    assert_eq!(mode(&p), 0o751);
}

#[test]
fn create_then_undo_removes_file_and_the_directories_it_created() {
    let f = fx();
    let store = open(&f);
    let s = sid("create");
    let p = f.root.join("new/deep/file.txt");

    let step = store
        .begin_step(&s, &f.root, &[Change::write("new/deep/file.txt", b"hello")])
        .expect("begin");
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(&p, b"hello").expect("write");
    step.commit().expect("commit");

    store.undo_step(&s, 1).expect("undo");
    assert!(!p.exists());
    assert!(!f.root.join("new").exists(), "created dirs removed");
    assert!(f.root.exists(), "the granted root itself stays");
}

#[test]
fn created_directory_that_gained_other_files_is_kept() {
    let f = fx();
    let store = open(&f);
    let s = sid("create2");
    let p = f.root.join("new/file.txt");

    let step = store
        .begin_step(&s, &f.root, &[Change::write("new/file.txt", b"hello")])
        .expect("begin");
    fs::create_dir_all(f.root.join("new")).expect("mkdir");
    fs::write(&p, b"hello").expect("write");
    step.commit().expect("commit");
    fs::write(f.root.join("new/member.txt"), b"member's own file").expect("member write");

    store.undo_step(&s, 1).expect("undo");
    assert!(!p.exists());
    assert_eq!(read(&f.root.join("new/member.txt")), b"member's own file");
}

#[cfg(unix)]
#[test]
fn delete_then_undo_recreates_file_with_content_and_mode() {
    let f = fx();
    let p = f.root.join("keep.txt");
    fs::write(&p, b"precious").expect("seed");
    set_mode(&p, 0o600);
    let store = open(&f);
    let s = sid("del");

    let step = store
        .begin_step(&s, &f.root, &[Change::delete("keep.txt")])
        .expect("begin");
    fs::remove_file(&p).expect("rm");
    step.commit().expect("commit");

    store.undo_step(&s, 1).expect("undo");
    assert_eq!(read(&p), b"precious");
    assert_eq!(mode(&p), 0o600);
}

#[test]
fn rename_then_undo_restores_source_and_overwritten_destination() {
    let f = fx();
    let a = f.root.join("a.txt");
    let b = f.root.join("b.txt");
    fs::write(&a, b"AAA").expect("seed a");
    fs::write(&b, b"BBB").expect("seed b");
    let store = open(&f);
    let s = sid("ren");

    let step = store
        .begin_step(&s, &f.root, &[Change::rename("a.txt", "b.txt")])
        .expect("begin");
    fs::rename(&a, &b).expect("rename");
    step.commit().expect("commit");
    assert!(!a.exists());
    assert_eq!(read(&b), b"AAA");

    store.undo_step(&s, 1).expect("undo");
    assert_eq!(read(&a), b"AAA");
    assert_eq!(read(&b), b"BBB");
}

#[test]
fn rename_to_new_path_then_undo_removes_destination() {
    let f = fx();
    let a = f.root.join("a.txt");
    fs::write(&a, b"AAA").expect("seed a");
    let store = open(&f);
    let s = sid("ren2");

    let step = store
        .begin_step(&s, &f.root, &[Change::rename("a.txt", "sub/c.txt")])
        .expect("begin");
    fs::create_dir_all(f.root.join("sub")).expect("mkdir");
    fs::rename(&a, f.root.join("sub/c.txt")).expect("rename");
    step.commit().expect("commit");

    store.undo_step(&s, 1).expect("undo");
    assert_eq!(read(&a), b"AAA");
    assert!(!f.root.join("sub").exists());
}

// ---------------------------------------------------------------- symlinks

#[cfg(unix)]
#[test]
fn symlink_is_recorded_not_followed() {
    let f = fx();
    let outside = f._tmp.path().join("outside.txt");
    fs::write(&outside, b"outside content").expect("seed outside");
    let link = f.root.join("link");
    std::os::unix::fs::symlink(&outside, &link).expect("symlink");
    let store = open(&f);
    let s = sid("sym");

    let step = store
        .begin_step(&s, &f.root, &[Change::delete("link")])
        .expect("begin");
    fs::remove_file(&link).expect("rm link");
    step.commit().expect("commit");

    // Only the link was snapshotted, not the target's bytes.
    let usage = store.usage().expect("usage");
    assert_eq!(
        usage.blob_bytes, 0,
        "symlink target content must not be copied"
    );

    store.undo_step(&s, 1).expect("undo");
    let meta = fs::symlink_metadata(&link).expect("meta");
    assert!(meta.file_type().is_symlink());
    assert_eq!(fs::read_link(&link).expect("readlink"), outside);
    assert_eq!(read(&outside), b"outside content");
}

#[cfg(unix)]
#[test]
fn writing_through_a_symlink_is_refused() {
    let f = fx();
    let outside = f._tmp.path().join("outside.txt");
    fs::write(&outside, b"outside").expect("seed");
    std::os::unix::fs::symlink(&outside, f.root.join("link")).expect("symlink");
    let store = open(&f);
    let err = store
        .begin_step(&sid("sym2"), &f.root, &[Change::write("link", b"x")])
        .expect_err("must refuse");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

#[cfg(unix)]
#[test]
fn symlinked_parent_directory_is_refused() {
    let f = fx();
    let outside_dir = f._tmp.path().join("outside-dir");
    fs::create_dir_all(&outside_dir).expect("mkdir");
    std::os::unix::fs::symlink(&outside_dir, f.root.join("escape")).expect("symlink");
    let store = open(&f);
    let err = store
        .begin_step(
            &sid("sym3"),
            &f.root,
            &[Change::write("escape/file.txt", b"x")],
        )
        .expect_err("must refuse");
    match &err {
        Error::Path { reason, .. } => assert!(reason.contains("symbolic link"), "{reason}"),
        other => panic!("expected Path, got {other:?}"),
    }
}

// ---------------------------------------------------------------- path rules

#[test]
fn paths_outside_the_granted_folder_are_refused() {
    let f = fx();
    let store = open(&f);
    let s = sid("paths");
    for bad in ["../x.txt", "a/../../x.txt", "/etc/hosts", ""] {
        let err = store
            .begin_step(&s, &f.root, &[Change::write(bad, b"x")])
            .err()
            .unwrap_or_else(|| panic!("{bad:?} must be refused"));
        assert!(matches!(err, Error::Path { .. }), "{bad:?}: {err:?}");
    }
    assert!(store.steps(&s).expect("steps").is_empty());
}

#[test]
fn absolute_path_inside_the_root_is_accepted() {
    let f = fx();
    let p = f.root.join("abs.txt");
    fs::write(&p, b"v1").expect("seed");
    let store = open(&f);
    let s = sid("abs");
    let step = store
        .begin_step(&s, &f.root, &[Change::write(&p, b"v2")])
        .expect("begin");
    fs::write(&p, b"v2").expect("write");
    let sum = step.commit().expect("commit");
    assert_eq!(sum.paths, vec!["abs.txt".to_string()]);
    store.undo_step(&s, 1).expect("undo");
    assert_eq!(read(&p), b"v1");
}

#[test]
fn directories_are_not_snapshotted() {
    let f = fx();
    fs::create_dir_all(f.root.join("dir")).expect("mkdir");
    let store = open(&f);
    let err = store
        .begin_step(&sid("dir"), &f.root, &[Change::delete("dir")])
        .expect_err("must refuse");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

#[test]
fn the_same_path_twice_in_one_step_is_refused() {
    let f = fx();
    let store = open(&f);
    let err = store
        .begin_step(
            &sid("dup"),
            &f.root,
            &[Change::write("x", b"1"), Change::write("./x", b"2")],
        )
        .expect_err("must refuse");
    assert!(matches!(err, Error::Path { .. }), "{err:?}");
}

#[test]
fn session_ids_are_validated() {
    for bad in ["", "-x", ".x", "a/b", "a b", "a..b", &"x".repeat(65), "ü"] {
        assert!(SessionId::new(bad).is_err(), "{bad:?} must be rejected");
    }
    for ok in ["a", "sess-1", "S_2", &"x".repeat(64)] {
        assert!(SessionId::new(ok).is_ok(), "{ok:?} must be accepted");
    }
}

// ---------------------------------------------------------------- conflicts

#[test]
fn undo_refuses_when_the_file_changed_since_and_does_not_clobber() {
    let f = fx();
    let p = f.root.join("doc.txt");
    fs::write(&p, b"v1").expect("seed");
    let store = open(&f);
    let s = sid("conflict");

    let step = store
        .begin_step(&s, &f.root, &[Change::write("doc.txt", b"v2")])
        .expect("begin");
    fs::write(&p, b"v2").expect("write");
    step.commit().expect("commit");
    fs::write(&p, b"member edit").expect("member edit");

    let err = store.undo_step(&s, 1).expect_err("must refuse");
    match &err {
        Error::Conflict(c) => {
            assert_eq!(c.len(), 1);
            assert_eq!(c[0].path, "doc.txt");
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert_eq!(read(&p), b"member edit", "never clobber silently");
    assert_eq!(
        store.steps(&s).expect("steps")[0].status,
        StepStatus::Committed,
        "a refused undo leaves the step undoable"
    );
}

#[test]
fn undo_refuses_when_a_deleted_file_reappeared() {
    let f = fx();
    let p = f.root.join("gone.txt");
    fs::write(&p, b"old").expect("seed");
    let store = open(&f);
    let s = sid("reappear");
    let step = store
        .begin_step(&s, &f.root, &[Change::delete("gone.txt")])
        .expect("begin");
    fs::remove_file(&p).expect("rm");
    step.commit().expect("commit");
    fs::write(&p, b"member recreated it").expect("member");

    assert!(matches!(store.undo_step(&s, 1), Err(Error::Conflict(_))));
    assert_eq!(read(&p), b"member recreated it");
}

#[test]
fn undo_of_an_earlier_step_conflicts_when_a_later_step_touched_the_file() {
    let f = fx();
    let p = f.root.join("x.txt");
    fs::write(&p, b"0").expect("seed");
    let store = open(&f);
    let s = sid("order");
    for v in [b"1", b"2"] {
        let step = store
            .begin_step(&s, &f.root, &[Change::write("x.txt", v)])
            .expect("begin");
        fs::write(&p, v).expect("write");
        step.commit().expect("commit");
    }
    assert!(matches!(store.undo_step(&s, 1), Err(Error::Conflict(_))));
    assert_eq!(read(&p), b"2");
    store.undo_step(&s, 2).expect("undo 2");
    assert_eq!(read(&p), b"1");
    store.undo_step(&s, 1).expect("undo 1");
    assert_eq!(read(&p), b"0");
}

#[test]
fn undo_twice_is_refused() {
    let f = fx();
    fs::write(f.root.join("t.txt"), b"a").expect("seed");
    let store = open(&f);
    let s = sid("twice");
    let step = store
        .begin_step(&s, &f.root, &[Change::write("t.txt", b"b")])
        .expect("begin");
    fs::write(f.root.join("t.txt"), b"b").expect("write");
    step.commit().expect("commit");
    store.undo_step(&s, 1).expect("undo");
    assert!(matches!(
        store.undo_step(&s, 1),
        Err(Error::AlreadyUndone { .. })
    ));
    assert!(matches!(
        store.undo_step(&s, 9),
        Err(Error::NotFound { .. })
    ));
}

// ---------------------------------------------------------------- whole session

#[test]
fn undo_session_restores_every_step_in_reverse_order() {
    let f = fx();
    let a = f.root.join("a.txt");
    let b = f.root.join("b.txt");
    fs::write(&a, b"a0").expect("seed");
    fs::write(&b, b"b0").expect("seed");
    let store = open(&f);
    let s = sid("whole");

    let st = store
        .begin_step(&s, &f.root, &[Change::write("a.txt", b"a1")])
        .expect("1");
    fs::write(&a, b"a1").expect("w");
    st.commit().expect("c");
    let st = store
        .begin_step(
            &s,
            &f.root,
            &[Change::write("a.txt", b"a2"), Change::delete("b.txt")],
        )
        .expect("2");
    fs::write(&a, b"a2").expect("w");
    fs::remove_file(&b).expect("rm");
    st.commit().expect("c");
    let st = store
        .begin_step(&s, &f.root, &[Change::write("c.txt", b"c1")])
        .expect("3");
    fs::write(f.root.join("c.txt"), b"c1").expect("w");
    st.commit().expect("c");

    let report = store.undo_session(&s).expect("undo session");
    assert_eq!(report.steps, vec![3, 2, 1]);
    assert_eq!(read(&a), b"a0");
    assert_eq!(read(&b), b"b0");
    assert!(!f.root.join("c.txt").exists());
    assert!(store
        .steps(&s)
        .expect("steps")
        .iter()
        .all(|x| x.status == StepStatus::Undone));
}

#[test]
fn undo_session_is_all_or_nothing_on_conflict() {
    let f = fx();
    let a = f.root.join("a.txt");
    let b = f.root.join("b.txt");
    fs::write(&a, b"a0").expect("seed");
    fs::write(&b, b"b0").expect("seed");
    let store = open(&f);
    let s = sid("aon");
    for (name, v) in [("a.txt", b"a1"), ("b.txt", b"b1")] {
        let st = store
            .begin_step(&s, &f.root, &[Change::write(name, v)])
            .expect("begin");
        fs::write(f.root.join(name), v).expect("w");
        st.commit().expect("c");
    }
    fs::write(&a, b"member").expect("member edits a");

    assert!(matches!(store.undo_session(&s), Err(Error::Conflict(_))));
    assert_eq!(read(&a), b"member");
    assert_eq!(read(&b), b"b1", "nothing restored when any path conflicts");
}

#[test]
fn sessions_are_independent() {
    let f = fx();
    let store = open(&f);
    let (s1, s2) = (sid("one"), sid("two"));
    for (s, name) in [(&s1, "one.txt"), (&s2, "two.txt")] {
        let st = store
            .begin_step(s, &f.root, &[Change::write(name, b"x")])
            .expect("begin");
        fs::write(f.root.join(name), b"x").expect("w");
        st.commit().expect("c");
    }
    store.undo_session(&s1).expect("undo one");
    assert!(!f.root.join("one.txt").exists());
    assert!(f.root.join("two.txt").exists());
    assert_eq!(store.steps(&s2).expect("steps")[0].seq, 1);
}

// ---------------------------------------------------------------- crash safety

#[test]
fn crash_between_snapshot_and_write_leaves_a_no_op_undo() {
    let f = fx();
    let p = f.root.join("c.txt");
    fs::write(&p, b"before").expect("seed");
    let s = sid("crash1");
    {
        let store = open(&f);
        let step = store
            .begin_step(&s, &f.root, &[Change::write("c.txt", b"after")])
            .expect("begin");
        // Process dies here: no write, no commit, no Drop.
        std::mem::forget(step);
    }
    let store = open(&f);
    let steps = store.steps(&s).expect("steps");
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].status, StepStatus::Interrupted);
    store.undo_step(&s, 1).expect("undo interrupted step");
    assert_eq!(read(&p), b"before");
}

#[test]
fn crash_after_write_before_commit_is_still_undoable() {
    let f = fx();
    let p = f.root.join("c.txt");
    fs::write(&p, b"before").expect("seed");
    let s = sid("crash2");
    {
        let store = open(&f);
        let step = store
            .begin_step(&s, &f.root, &[Change::write("c.txt", b"after")])
            .expect("begin");
        fs::write(&p, b"after").expect("write");
        std::mem::forget(step);
    }
    let store = open(&f);
    assert_eq!(
        store.steps(&s).expect("steps")[0].status,
        StepStatus::Interrupted
    );
    store.undo_step(&s, 1).expect("undo");
    assert_eq!(read(&p), b"before");
}

#[test]
fn crash_then_a_third_change_is_a_conflict() {
    let f = fx();
    let p = f.root.join("c.txt");
    fs::write(&p, b"before").expect("seed");
    let s = sid("crash3");
    {
        let store = open(&f);
        let step = store
            .begin_step(&s, &f.root, &[Change::write("c.txt", b"after")])
            .expect("begin");
        std::mem::forget(step);
    }
    fs::write(&p, b"something else entirely").expect("other writer");
    let store = open(&f);
    assert!(matches!(store.undo_step(&s, 1), Err(Error::Conflict(_))));
    assert_eq!(read(&p), b"something else entirely");
}

#[test]
fn dropping_an_uncommitted_step_marks_it_interrupted_and_frees_the_path() {
    let f = fx();
    let store = open(&f);
    let s = sid("drop");
    {
        let _step = store
            .begin_step(&s, &f.root, &[Change::write("d.txt", b"x")])
            .expect("begin");
    }
    assert_eq!(
        store.steps(&s).expect("steps")[0].status,
        StepStatus::Interrupted
    );
    store
        .begin_step(&s, &f.root, &[Change::write("d.txt", b"x")])
        .expect("path is free again")
        .abort()
        .expect("abort");
    assert_eq!(
        store.steps(&s).expect("steps")[1].status,
        StepStatus::Interrupted
    );
}

#[test]
fn stale_temp_files_from_a_crash_are_removed_on_open() {
    let f = fx();
    {
        let _store = open(&f);
    }
    let tmp = f.store_dir.join("tmp");
    fs::create_dir_all(&tmp).expect("mkdir");
    fs::write(tmp.join("blob-123.part"), b"half a blob").expect("stale");
    let _store = open(&f);
    assert_eq!(fs::read_dir(&tmp).expect("ls").count(), 0);
}

#[test]
fn steps_survive_reopen() {
    let f = fx();
    fs::write(f.root.join("r.txt"), b"1").expect("seed");
    let s = sid("reopen");
    {
        let store = open(&f);
        let st = store
            .begin_step(&s, &f.root, &[Change::write("r.txt", b"2")])
            .expect("begin");
        fs::write(f.root.join("r.txt"), b"2").expect("w");
        st.commit().expect("c");
    }
    let store = open(&f);
    let st = store
        .begin_step(&s, &f.root, &[Change::write("r.txt", b"3")])
        .expect("begin");
    fs::write(f.root.join("r.txt"), b"3").expect("w");
    assert_eq!(st.commit().expect("c").seq, 2, "seq continues after reopen");
    store.undo_session(&s).expect("undo");
    assert_eq!(read(&f.root.join("r.txt")), b"1");
}

#[test]
fn a_second_process_cannot_open_the_same_store() {
    let f = fx();
    let _a = open(&f);
    assert!(f.store_dir.join(LOCK_FILE).exists());
    assert!(matches!(
        CheckpointStore::open(&f.store_dir, cfg()),
        Err(Error::Locked(_))
    ));
}

#[test]
fn a_tampered_blob_is_detected_and_nothing_is_clobbered() {
    let f = fx();
    let p = f.root.join("t.txt");
    fs::write(&p, b"original bytes").expect("seed");
    let store = open(&f);
    let s = sid("tamper");
    let st = store
        .begin_step(&s, &f.root, &[Change::write("t.txt", b"new")])
        .expect("begin");
    fs::write(&p, b"new").expect("w");
    st.commit().expect("c");

    // Corrupt every blob on disk.
    for e in walk(&f.store_dir.join("blobs")) {
        fs::write(&e, b"evil").expect("tamper");
    }
    assert!(matches!(store.undo_step(&s, 1), Err(Error::Corrupt { .. })));
    assert_eq!(read(&p), b"new");
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

// ---------------------------------------------------------------- size caps + pruning

#[test]
fn a_file_over_the_cap_is_refused_with_a_reason() {
    let f = fx();
    let p = f.root.join("big.bin");
    fs::write(&p, vec![7u8; 2048]).expect("seed");
    let store = CheckpointStore::open(
        &f.store_dir,
        Config {
            max_store_bytes: 1 << 20,
            max_file_bytes: 1024,
        },
    )
    .expect("open");
    let s = sid("big");
    let err = store
        .begin_step(&s, &f.root, &[Change::write("big.bin", b"x")])
        .expect_err("must refuse");
    match &err {
        Error::TooLarge { path, size, cap } => {
            assert_eq!(path, "big.bin");
            assert_eq!(*size, 2048);
            assert_eq!(*cap, 1024);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    let msg = err.to_string();
    assert!(
        msg.contains("big.bin") && msg.contains("2048") && msg.contains("1024"),
        "{msg}"
    );
    assert!(
        store.steps(&s).expect("steps").is_empty(),
        "no step recorded"
    );
    assert_eq!(
        store.usage().expect("usage").blob_bytes,
        0,
        "no partial blob kept"
    );
    assert_eq!(read(&p).len(), 2048);
}

#[test]
fn a_step_larger_than_the_whole_store_is_refused() {
    let f = fx();
    fs::write(f.root.join("a"), vec![1u8; 600]).expect("seed");
    fs::write(f.root.join("b"), vec![2u8; 600]).expect("seed");
    let store = CheckpointStore::open(
        &f.store_dir,
        Config {
            max_store_bytes: 1000,
            max_file_bytes: 1000,
        },
    )
    .expect("open");
    let err = store
        .begin_step(
            &sid("huge"),
            &f.root,
            &[Change::delete("a"), Change::delete("b")],
        )
        .expect_err("must refuse");
    assert!(
        matches!(
            err,
            Error::StepTooLarge {
                size: 1200,
                cap: 1000
            }
        ),
        "{err:?}"
    );
    assert_eq!(store.usage().expect("usage").blob_bytes, 0);
}

#[test]
fn identical_content_is_stored_once() {
    let f = fx();
    fs::write(f.root.join("x"), b"same bytes").expect("seed");
    fs::write(f.root.join("y"), b"same bytes").expect("seed");
    let store = open(&f);
    let st = store
        .begin_step(
            &sid("dedup"),
            &f.root,
            &[Change::delete("x"), Change::delete("y")],
        )
        .expect("begin");
    st.commit().expect("c");
    let u = store.usage().expect("usage");
    assert_eq!(u.blob_count, 1);
    assert_eq!(u.blob_bytes, 10);
}

#[test]
fn least_recently_used_session_is_pruned_first_and_says_so() {
    let f = fx();
    for n in ["a1", "a2", "b1", "c1"] {
        fs::write(f.root.join(n), vec![n.as_bytes()[0]; 400]).expect("seed");
    }
    // Cap fits two 400-byte snapshots, not three.
    let store = CheckpointStore::open(
        &f.store_dir,
        Config {
            max_store_bytes: 1000,
            max_file_bytes: 1000,
        },
    )
    .expect("open");
    let (sa, sb) = (sid("old"), sid("recent"));
    let one = |s: &SessionId, name: &str| {
        let st = store
            .begin_step(s, &f.root, &[Change::write(name, b"z")])
            .expect("begin");
        fs::write(f.root.join(name), b"z").expect("w");
        st.commit().expect("c")
    };
    one(&sa, "a1"); // old: seq 1  (400 bytes)
    one(&sb, "b1"); // recent: seq 1 (800 bytes); 'recent' is now the most recently used
    one(&sb, "c1"); // forces eviction: must evict old/1, not recent/1

    let u = store.usage().expect("usage");
    assert!(u.blob_bytes <= 1000, "{u:?}");
    assert!(matches!(store.undo_step(&sa, 1), Err(Error::Pruned { .. })));
    let steps_a = store.steps(&sa).expect("steps a");
    assert!(steps_a.is_empty());
    // Recent session is intact and fully undoable.
    store.undo_session(&sb).expect("undo recent");
    assert_eq!(read(&f.root.join("b1")), vec![b'b'; 400]);
    assert_eq!(read(&f.root.join("c1")), vec![b'c'; 400]);
    let _ = one(&sa, "a2");
}

#[test]
fn pruning_survives_reopen_and_reports_pruned() {
    let f = fx();
    for n in ["p", "q", "r"] {
        fs::write(f.root.join(n), vec![9u8; 400]).expect("seed");
    }
    let c = Config {
        max_store_bytes: 1000,
        max_file_bytes: 1000,
    };
    let s = sid("prune");
    {
        let store = CheckpointStore::open(&f.store_dir, c.clone()).expect("open");
        for (i, n) in ["p", "q", "r"].iter().enumerate() {
            // distinct content so blobs do not dedup
            fs::write(f.root.join(n), vec![i as u8; 400]).expect("seed distinct");
            let st = store
                .begin_step(&s, &f.root, &[Change::delete(*n)])
                .expect("begin");
            fs::remove_file(f.root.join(n)).expect("rm");
            st.commit().expect("c");
        }
    }
    let store = CheckpointStore::open(&f.store_dir, c).expect("reopen");
    assert!(matches!(store.undo_step(&s, 1), Err(Error::Pruned { .. })));
    let report = store.undo_session(&s).expect("undo what is left");
    assert_eq!(report.steps, vec![3, 2]);
    assert_eq!(report.pruned_through, Some(1));
}

// ---------------------------------------------------------------- concurrency

#[test]
fn concurrent_steps_on_different_files_all_record_and_undo() {
    let f = fx();
    for i in 0..8 {
        fs::write(f.root.join(format!("f{i}.txt")), format!("orig {i}")).expect("seed");
    }
    let store = Arc::new(open(&f));
    let s = sid("conc");
    let root = Arc::new(f.root.clone());
    let mut handles = Vec::new();
    for i in 0..8 {
        let store = Arc::clone(&store);
        let s = s.clone();
        let root = Arc::clone(&root);
        handles.push(std::thread::spawn(move || {
            let name = format!("f{i}.txt");
            let body = format!("agent {i}");
            let st = store
                .begin_step(&s, &root, &[Change::write(&name, body.as_bytes())])
                .expect("begin");
            fs::write(root.join(&name), body).expect("w");
            st.commit().expect("c").seq
        }));
    }
    let mut seqs: Vec<u64> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=8).collect::<Vec<_>>());
    store.undo_session(&s).expect("undo all");
    for i in 0..8 {
        assert_eq!(
            read(&f.root.join(format!("f{i}.txt"))),
            format!("orig {i}").into_bytes()
        );
    }
}

#[test]
fn concurrent_step_on_the_same_path_is_refused_while_in_flight() {
    let f = fx();
    fs::write(f.root.join("same.txt"), b"0").expect("seed");
    let store = open(&f);
    let (s1, s2) = (sid("w1"), sid("w2"));
    let first = store
        .begin_step(&s1, &f.root, &[Change::write("same.txt", b"1")])
        .expect("begin");
    let err = store
        .begin_step(&s2, &f.root, &[Change::write("same.txt", b"2")])
        .expect_err("second writer must wait");
    assert!(matches!(err, Error::Busy { .. }), "{err:?}");
    // Undo touching that path is also refused while the write is in flight.
    fs::write(f.root.join("same.txt"), b"1").expect("w");
    first.commit().expect("c");
    let second = store
        .begin_step(&s2, &f.root, &[Change::write("same.txt", b"2")])
        .expect("free after commit");
    assert!(matches!(store.undo_step(&s1, 1), Err(Error::Busy { .. })));
    second.abort().expect("abort");
    store.undo_step(&s1, 1).expect("undo");
    assert_eq!(read(&f.root.join("same.txt")), b"0");
}

#[test]
fn every_blob_is_verified_before_any_path_is_restored() {
    let f = fx();
    let (a, b) = (f.root.join("a.txt"), f.root.join("b.txt"));
    fs::write(&a, b"a-original").expect("seed");
    fs::write(&b, b"b-original").expect("seed");
    let store = open(&f);
    let s = sid("verify-all");
    let st = store
        .begin_step(
            &s,
            &f.root,
            &[Change::write("a.txt", b"a2"), Change::write("b.txt", b"b2")],
        )
        .expect("begin");
    fs::write(&a, b"a2").expect("w");
    fs::write(&b, b"b2").expect("w");
    st.commit().expect("c");

    // Corrupt only b's snapshot; a's restore must not run either.
    use sha2::Digest;
    let b_hex = hex_lower(&sha2::Sha256::digest(b"b-original"));
    let b_blob = walk(&f.store_dir.join("blobs"))
        .into_iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(b_hex.as_str()))
        .expect("b blob");
    fs::write(&b_blob, b"evil").expect("tamper");

    assert!(matches!(store.undo_step(&s, 1), Err(Error::Corrupt { .. })));
    assert_eq!(read(&a), b"a2", "a untouched when b cannot be restored");
    assert_eq!(read(&b), b"b2");
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn in_flight_steps_are_never_pruned() {
    let f = fx();
    fs::write(f.root.join("held"), vec![1u8; 400]).expect("seed");
    fs::write(f.root.join("big"), vec![2u8; 800]).expect("seed");
    let store = CheckpointStore::open(
        &f.store_dir,
        Config {
            max_store_bytes: 1000,
            max_file_bytes: 1000,
        },
    )
    .expect("open");
    let (s1, s2) = (sid("inflight"), sid("other"));
    let held = store
        .begin_step(&s1, &f.root, &[Change::delete("held")])
        .expect("begin held");
    let err = store
        .begin_step(&s2, &f.root, &[Change::delete("big")])
        .expect_err("no room without evicting an in-flight step");
    assert!(
        matches!(
            err,
            Error::StoreFull {
                needed: 800,
                cap: 1000
            }
        ),
        "{err:?}"
    );
    fs::remove_file(f.root.join("held")).expect("rm");
    held.commit().expect("commit");
    store.undo_step(&s1, 1).expect("still undoable");
    assert_eq!(read(&f.root.join("held")), vec![1u8; 400]);
}

#[cfg(unix)]
#[test]
fn the_store_directory_is_private_to_the_member() {
    let f = fx();
    let _store = open(&f);
    assert_eq!(
        mode(&f.store_dir),
        0o700,
        "snapshots are copies of member files"
    );
}

#[cfg(unix)]
#[test]
fn undo_refuses_when_a_parent_directory_became_a_symlink_since_the_step() {
    // Review fix: undo re-checks each path against the granted folder, so a parent directory
    // swapped for a link after the step can never steer a restore outside the folder.
    let f = fx();
    fs::create_dir_all(f.root.join("a")).expect("mkdir");
    fs::write(f.root.join("a/f.txt"), b"prior").expect("seed");
    let store = open(&f);
    let s = sid("swap");
    let step = store
        .begin_step(&s, &f.root, &[Change::write("a/f.txt", b"post")])
        .expect("begin");
    fs::write(f.root.join("a/f.txt"), b"post").expect("write");
    step.commit().expect("commit");

    let outside = f._tmp.path().join("outside");
    fs::create_dir_all(&outside).expect("mkdir");
    fs::write(outside.join("f.txt"), b"post").expect("outside file");
    fs::rename(f.root.join("a"), f._tmp.path().join("moved-a")).expect("move a away");
    std::os::unix::fs::symlink(&outside, f.root.join("a")).expect("symlink");

    let err = store.undo_step(&s, 1).expect_err("must refuse");
    match &err {
        Error::Path { reason, .. } => assert!(reason.contains("symbolic link"), "{reason}"),
        other => panic!("expected Path, got {other:?}"),
    }
    assert_eq!(read(&outside.join("f.txt")), b"post", "outside untouched");
}
