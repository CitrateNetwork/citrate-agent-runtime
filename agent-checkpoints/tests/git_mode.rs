//! Git mode: a checkpoint commit on a private ref, without touching HEAD, the index, or the
//! working branch (HUP-S2.9, runtime half).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use citrate_agent_checkpoints::{checkpoint_ref, CheckpointStore, Config, Error, SessionId};

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn sha256_file(p: &Path) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(fs::read(p).expect("read")).to_vec()
}

struct Repo {
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    store_dir: PathBuf,
}

fn repo_with_commit() -> Repo {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&repo).expect("mkdir");
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("tracked.txt"), b"v1").expect("w");
    fs::write(repo.join(".gitignore"), b"ignored.log\n").expect("w");
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    // A member config that would sign every commit with a program that always fails: checkpoint
    // commits must never try to sign.
    git(&repo, &["config", "commit.gpgsign", "true"]);
    git(&repo, &["config", "gpg.program", "false"]);
    let store_dir = tmp.path().join("store");
    Repo {
        _tmp: tmp,
        repo,
        store_dir,
    }
}

fn open(r: &Repo) -> CheckpointStore {
    CheckpointStore::open(&r.store_dir, Config::default()).expect("open")
}

struct Snapshot {
    head: String,
    symref: String,
    index: Vec<u8>,
    status: String,
    branches: String,
}

fn snapshot(repo: &Path) -> Snapshot {
    Snapshot {
        head: git(repo, &["rev-parse", "HEAD"]),
        symref: git(repo, &["symbolic-ref", "HEAD"]),
        index: sha256_file(&repo.join(".git/index")),
        status: git(repo, &["status", "--porcelain=v1", "--untracked-files=all"]),
        branches: git(repo, &["for-each-ref", "refs/heads"]),
    }
}

#[test]
fn checkpoint_commit_lands_on_a_private_ref_and_touches_nothing_else() {
    let r = repo_with_commit();
    // Working tree: a modified tracked file, a staged new file, an untracked file, an ignored file.
    fs::write(r.repo.join("tracked.txt"), b"v2 (unstaged)").expect("w");
    fs::write(r.repo.join("staged.txt"), b"staged").expect("w");
    git(&r.repo, &["add", "staged.txt"]);
    fs::write(r.repo.join("untracked.txt"), b"new").expect("w");
    fs::write(r.repo.join("ignored.log"), b"noise").expect("w");

    let before = snapshot(&r.repo);
    let store = open(&r);
    let s = SessionId::new("git-1").expect("sid");
    let cp = store
        .git_checkpoint(&s, &r.repo, "before agent step 1")
        .expect("checkpoint");

    assert_eq!(cp.reference, "refs/citrate/checkpoints/git-1");
    assert_eq!(cp.reference, checkpoint_ref(&s));
    assert!(cp.created);
    assert_eq!(cp.parent.as_deref(), Some(before.head.as_str()));
    assert_eq!(git(&r.repo, &["rev-parse", &cp.reference]), cp.commit);

    // Nothing visible to the member moved.
    let after = snapshot(&r.repo);
    assert_eq!(after.head, before.head, "HEAD unchanged");
    assert_eq!(after.symref, before.symref, "branch unchanged");
    assert_eq!(after.index, before.index, "index file byte-identical");
    assert_eq!(after.status, before.status, "status unchanged");
    assert_eq!(
        after.branches, before.branches,
        "no branch created or moved"
    );

    // The checkpoint captured the working tree as it is, ignoring ignored files.
    let show = |p: &str| git(&r.repo, &["show", &format!("{}:{p}", cp.commit)]);
    assert_eq!(show("tracked.txt"), "v2 (unstaged)");
    assert_eq!(show("staged.txt"), "staged");
    assert_eq!(show("untracked.txt"), "new");
    let files = git(&r.repo, &["ls-tree", "-r", "--name-only", &cp.commit]);
    assert!(!files.lines().any(|l| l == "ignored.log"), "{files}");

    // Not signed, fixed identity, message as given.
    let raw = git(&r.repo, &["cat-file", "commit", &cp.commit]);
    assert!(
        !raw.contains("gpgsig"),
        "checkpoint commits are never signed"
    );
    assert!(raw.contains("before agent step 1"));
}

#[test]
fn second_checkpoint_chains_on_the_first_and_unchanged_tree_is_a_no_op() {
    let r = repo_with_commit();
    let store = open(&r);
    let s = SessionId::new("git-2").expect("sid");
    fs::write(r.repo.join("tracked.txt"), b"step 1").expect("w");
    let one = store.git_checkpoint(&s, &r.repo, "one").expect("one");
    fs::write(r.repo.join("tracked.txt"), b"step 2").expect("w");
    let two = store.git_checkpoint(&s, &r.repo, "two").expect("two");
    assert_eq!(two.parent.as_deref(), Some(one.commit.as_str()));
    let three = store.git_checkpoint(&s, &r.repo, "three").expect("three");
    assert!(!three.created, "same tree, no new commit");
    assert_eq!(three.commit, two.commit);
    assert_eq!(
        store.git_checkpoint_head(&s, &r.repo).expect("head"),
        Some(two.commit.clone())
    );
}

#[test]
fn checkpoint_from_a_subfolder_grant_keeps_the_rest_of_the_tree_at_head() {
    let r = repo_with_commit();
    fs::create_dir_all(r.repo.join("sub")).expect("mkdir");
    fs::write(r.repo.join("sub/inside.txt"), b"in").expect("w");
    git(&r.repo, &["add", "-A"]);
    git(&r.repo, &["commit", "-q", "-m", "sub"]);
    fs::write(r.repo.join("sub/inside.txt"), b"in v2").expect("w");
    fs::write(r.repo.join("tracked.txt"), b"outside the grant").expect("w");

    let store = open(&r);
    let s = SessionId::new("git-sub").expect("sid");
    let cp = store
        .git_checkpoint(&s, &r.repo.join("sub"), "sub only")
        .expect("checkpoint");
    let show = |p: &str| git(&r.repo, &["show", &format!("{}:{p}", cp.commit)]);
    assert_eq!(show("sub/inside.txt"), "in v2");
    assert_eq!(show("tracked.txt"), "v1", "outside the grant: as at HEAD");
}

#[test]
fn unborn_head_repository_gets_a_root_checkpoint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo = tmp.path().join("fresh");
    fs::create_dir_all(&repo).expect("mkdir");
    git(&repo, &["init", "-q", "-b", "main"]);
    fs::write(repo.join("a.txt"), b"a").expect("w");
    let store = CheckpointStore::open(&tmp.path().join("store"), Config::default()).expect("open");
    let s = SessionId::new("fresh").expect("sid");
    let cp = store
        .git_checkpoint(&s, &repo, "first")
        .expect("checkpoint");
    assert!(cp.parent.is_none());
    assert!(
        !repo.join(".git/index").exists(),
        "no index created for the member"
    );
    let out = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["rev-parse", "--verify", "-q", "HEAD"])
        .output()
        .expect("git");
    assert!(!out.status.success(), "HEAD stays unborn");
}

#[test]
fn a_folder_that_is_not_a_git_work_tree_is_reported() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let plain = tmp.path().join("plain");
    fs::create_dir_all(&plain).expect("mkdir");
    let store = CheckpointStore::open(&tmp.path().join("store"), Config::default()).expect("open");
    let s = SessionId::new("plain").expect("sid");
    assert!(!store.is_git_work_tree(&plain).expect("probe"));
    assert!(matches!(
        store.git_checkpoint(&s, &plain, "x"),
        Err(Error::NotGitWorkTree(_))
    ));
}

#[test]
fn the_temporary_index_is_cleaned_up() {
    let r = repo_with_commit();
    let store = open(&r);
    let s = SessionId::new("tidy").expect("sid");
    store.git_checkpoint(&s, &r.repo, "x").expect("checkpoint");
    let tmp = r.store_dir.join("tmp");
    let left: Vec<_> = fs::read_dir(&tmp)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "{left:?}");
}
