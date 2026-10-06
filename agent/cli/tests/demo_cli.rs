use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "citrate-agent-demo-cli-{label}-{}-{id}",
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

#[test]
fn demo_binary_prints_only_the_exact_capsule_output() {
    let temp = TempTree::new("success");
    let evidence = temp.path().join("evidence");
    std::fs::create_dir(&evidence).expect("evidence dir");

    let output = Command::new(env!("CARGO_BIN_EXE_citrate-agent"))
        .args([
            "demo",
            "--capsules-dir",
            capsules_root().to_str().expect("UTF-8 capsule path"),
            "--evidence-dir",
            evidence.to_str().expect("UTF-8 evidence path"),
        ])
        .output()
        .expect("run citrate-agent demo");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"Hello, Tech Week\n");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(evidence.join("audit.jsonl").is_file());
    assert!(evidence.join("summary.json").is_file());
}

#[test]
fn demo_binary_fails_nonzero_without_creating_a_missing_evidence_directory() {
    let temp = TempTree::new("failure");
    let missing = temp.path().join("missing");

    let output = Command::new(env!("CARGO_BIN_EXE_citrate-agent"))
        .args([
            "demo",
            "--capsules-dir",
            capsules_root().to_str().expect("UTF-8 capsule path"),
            "--evidence-dir",
            missing.to_str().expect("UTF-8 evidence path"),
        ])
        .output()
        .expect("run citrate-agent demo failure");

    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("demo failed:"),
        "{output:?}"
    );
    assert!(!missing.exists());
}
