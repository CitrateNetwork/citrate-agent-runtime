use super::*;
use citrate_agent_core::audit::{AuditChain, FilesystemSink};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "citrate-agent-demo-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp tree");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn capsules_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
        .join("capsules")
}

fn args(evidence_dir: PathBuf, capsules_dir: PathBuf) -> DemoArgs {
    DemoArgs {
        capsules_dir,
        evidence_dir,
    }
}

#[test]
fn two_fresh_runs_emit_byte_identical_evidence() {
    let temp = TempTree::new("deterministic");
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    std::fs::create_dir(&first).expect("first evidence dir");
    std::fs::create_dir(&second).expect("second evidence dir");

    assert_eq!(
        execute(&args(first.clone(), capsules_root())).expect("first run"),
        EXPECTED_OUTPUT
    );
    assert_eq!(
        execute(&args(second.clone(), capsules_root())).expect("second run"),
        EXPECTED_OUTPUT
    );
    assert_eq!(
        std::fs::read(first.join("audit.jsonl")).expect("first audit"),
        std::fs::read(second.join("audit.jsonl")).expect("second audit")
    );
    assert_eq!(
        std::fs::read(first.join("summary.json")).expect("first summary"),
        std::fs::read(second.join("summary.json")).expect("second summary")
    );
}

#[test]
fn real_signed_hello_returns_exact_output_and_reopens_as_a_verified_chain() {
    let temp = TempTree::new("signed");
    let evidence = temp.path().join("evidence");
    std::fs::create_dir(&evidence).expect("evidence dir");

    let output = execute(&args(evidence.clone(), capsules_root())).expect("demo succeeds");
    assert_eq!(output, "Hello, Tech Week");

    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(evidence.join("summary.json")).expect("summary"))
            .expect("summary JSON");
    assert_eq!(summary["capsule_signature_verified"], true);
    assert_eq!(summary["evidence_signed"], false);
    assert_eq!(summary["chain_anchored"], false);
    assert_eq!(summary["external_network_used"], false);
    assert_eq!(summary["audit_chain_verified"], true);
    assert!(!evidence.join(".audit.jsonl.tmp").exists());
    assert!(!evidence.join(".summary.json.tmp").exists());

    let sink = Arc::new(FilesystemSink::open(&evidence.join("audit.jsonl")).expect("sink"));
    let chain = AuditChain::open_existing(sink)
        .expect("reopen")
        .expect("non-empty chain");
    assert_eq!(chain.verify_integrity().expect("verified chain"), 2);
}

#[test]
fn loose_unsigned_hello_is_refused_without_a_summary() {
    let temp = TempTree::new("unsigned");
    let fleet_hello = temp.path().join("fleet").join("hello");
    let evidence = temp.path().join("evidence");
    std::fs::create_dir_all(&fleet_hello).expect("loose capsule dir");
    std::fs::create_dir(&evidence).expect("evidence dir");
    for file in ["manifest.toml", "capsule.wasm"] {
        std::fs::copy(
            capsules_root().join("hello").join(file),
            fleet_hello.join(file),
        )
        .expect("copy loose capsule file");
    }

    let error = execute(&args(evidence.clone(), temp.path().join("fleet")))
        .expect_err("unsigned capsule must fail closed");
    assert!(error.contains("unverified capsule \"hello\""), "{error}");
    assert!(!evidence.join("summary.json").exists());
}

#[test]
fn a_different_signed_capsule_cannot_substitute_for_hello() {
    let temp = TempTree::new("capabilities");
    let fleet_hello = temp.path().join("fleet").join("hello");
    let evidence = temp.path().join("evidence");
    std::fs::create_dir_all(&fleet_hello).expect("capsule dir");
    std::fs::create_dir(&evidence).expect("evidence dir");
    std::fs::copy(
        capsules_root().join("echo-chain").join("echo-chain.cps"),
        fleet_hello.join("hello.cps"),
    )
    .expect("copy signed capability-bearing capsule");

    let error = execute(&args(evidence.clone(), temp.path().join("fleet")))
        .expect_err("a capability-bearing capsule must not run as the offline demo");
    assert!(error.contains("capsule \"hello\" not loaded"), "{error}");
    assert!(!evidence.join("audit.jsonl").exists());
    assert!(!evidence.join("summary.json").exists());
}

#[test]
fn missing_or_nonempty_evidence_directory_is_refused_without_overwrite() {
    let temp = TempTree::new("evidence-guard");
    let missing = temp.path().join("missing");
    assert!(execute(&args(missing.clone(), capsules_root())).is_err());
    assert!(!missing.exists());

    let nonempty = temp.path().join("nonempty");
    std::fs::create_dir(&nonempty).expect("nonempty dir");
    std::fs::write(nonempty.join("keep.txt"), b"keep").expect("sentinel");
    assert!(execute(&args(nonempty.clone(), capsules_root())).is_err());
    assert_eq!(
        std::fs::read(nonempty.join("keep.txt")).expect("sentinel"),
        b"keep"
    );
    assert!(!nonempty.join("summary.json").exists());

    let file_path = temp.path().join("not-a-directory");
    std::fs::write(&file_path, b"keep").expect("file path");
    assert!(execute(&args(file_path.clone(), capsules_root())).is_err());
    assert_eq!(std::fs::read(&file_path).expect("preserved file"), b"keep");
}

#[cfg(unix)]
#[test]
fn symlink_evidence_directory_is_refused() {
    use std::os::unix::fs::symlink;

    let temp = TempTree::new("symlink");
    let target = temp.path().join("target");
    let link = temp.path().join("link");
    std::fs::create_dir(&target).expect("target dir");
    symlink(&target, &link).expect("symlink");

    let error = execute(&args(link, capsules_root())).expect_err("symlink must be refused");
    assert!(error.contains("must not be a symlink"), "{error}");
    assert!(std::fs::read_dir(&target)
        .expect("target remains readable")
        .next()
        .is_none());
}
