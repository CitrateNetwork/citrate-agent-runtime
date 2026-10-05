// HUP-S2.5: escape tests driven by a compiled guest capsule.
//
// `test-fixtures/guests/sandbox-probe/capsule.wasm` is a real wasm32-wasip2
// component built from `guest/` (Rust std over wasi-libc). Each call makes
// the guest try one filesystem or network operation through its own WASI
// imports, so these tests cover the full path a shipped capsule takes:
// libc path resolution, the component's imports, the per-capsule linker and
// the sandboxed host context. The host-function tests in `sandbox.rs` cover
// the same rules one layer down.

use super::*;
use crate::capsule::archive::ArchiveContents;
use crate::capsule::manifest::Manifest;
use crate::capsule::wasm::EngineFactory;
use crate::capsule::Capsule;
use citrate_agent_grants::{Access, GrantRequest};
use wasmtime::component::Val;

const NOW: u64 = 1_800_000_000;
const PROBE_IFACE: &str = "citrate:sandbox-probe/probe@0.1.0";
/// A Rust std guest links wasi-libc, which imports `wasi:filesystem` even
/// when it never opens a file, and the per-capsule linker registers that
/// interface only for a capsule that declares a filesystem entry. The
/// network tests declare one and bind no mount, so the guest has no
/// preopened folder.
const STD_GUEST_FS: &[&str] = &["read:/work"];

fn probe_wasm() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-fixtures/guests/sandbox-probe/capsule.wasm");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn probe_manifest(network: &str, filesystem: &[&str]) -> Manifest {
    let fs = filesystem
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    Manifest::parse(&format!(
        r#"
[capsule]
name = "sandbox-probe"
version = "0.1.0"
content_hash = "sha256:{zeros}"

[capability]
{network}
filesystem = [{fs}]
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = []

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "hup-s2.5"
tla_spec = ""

[signing]
tier = "bundled"
"#,
        zeros = "0".repeat(64),
    ))
    .expect("probe manifest parses")
}

fn probe_capsule(manifest: Manifest) -> Capsule {
    Capsule {
        manifest,
        archive: ArchiveContents {
            wasm: probe_wasm(),
            ..Default::default()
        },
    }
}

/// Instantiate the probe under `plan` and run one operation.
fn run_probe(
    capsule: &Capsule,
    plan: &SandboxPlan,
    op: &str,
    target: &str,
) -> Result<String, AgentError> {
    let engine = EngineFactory::build()?;
    let linker = capsule.prepare_linker(&engine)?.into_linker();
    let (mut store, instance) =
        capsule.instantiate_sandboxed(&engine, &linker, None, None, None, plan)?;
    let (_, iface) = instance
        .get_export(&mut store, None, PROBE_IFACE)
        .ok_or_else(|| AgentError::Capsule("probe interface missing".into()))?;
    let (_, func) = instance
        .get_export(&mut store, Some(&iface), "run")
        .ok_or_else(|| AgentError::Capsule("probe run missing".into()))?;
    let func = instance
        .get_func(&mut store, func)
        .ok_or_else(|| AgentError::Capsule("probe run resolve".into()))?;
    let mut out = [Val::Bool(false)];
    func.call(
        &mut store,
        &[Val::String(op.into()), Val::String(target.into())],
        &mut out,
    )
    .map_err(|e| AgentError::Capsule(format!("probe call: {e}")))?;
    match &out[0] {
        Val::String(s) => Ok(s.to_string()),
        other => Err(AgentError::Capsule(format!("probe returned {other:?}"))),
    }
}

/// A member home with a granted project folder and a file beside it.
struct World {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
    outside: PathBuf,
}

fn world() -> World {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = std::fs::canonicalize(tmp.path()).expect("canonical tempdir");
    let home = base.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join("src")).expect("mkdir");
    std::fs::write(project.join("notes.txt"), b"granted").expect("write");
    std::fs::write(project.join("src").join("lib.txt"), b"nested").expect("write");
    let outside = home.join("private.txt");
    std::fs::write(&outside, b"not granted").expect("write");
    World {
        _tmp: tmp,
        home,
        project,
        outside,
    }
}

fn grants(w: &World, access: &[Access]) -> FolderGrants {
    let mut g = FolderGrants::new(&w.home, &w.home);
    for a in access {
        g.grant(
            GrantRequest::folder(&w.project, *a, "0xmember", "guest probe"),
            NOW - 10,
        )
        .expect("grant");
    }
    g
}

/// `broker-only` links the socket imports (the probe uses them) but the
/// plan reaches no address, so the filesystem tests see no network.
fn fs_capsule(access: &str) -> Capsule {
    probe_capsule(probe_manifest(
        r#"network = "broker-only""#,
        &[&format!("{access}:/work")],
    ))
}

fn fs_plan(w: &World, capsule: &Capsule, access: &[Access]) -> SandboxPlan {
    SandboxPlan::resolve(
        &capsule.manifest,
        &[FsMount::new("/work", &w.project)],
        &grants(w, access),
        NOW,
    )
    .expect("plan")
}

fn assert_err(got: &str, what: &str) {
    assert!(got.starts_with("err:"), "{what}: the guest got {got:?}");
}

#[test]
fn the_guest_reads_and_lists_inside_its_mount() {
    let w = world();
    let c = fs_capsule("read");
    let plan = fs_plan(&w, &c, &[Access::Read]);
    assert_eq!(
        run_probe(&c, &plan, "read", "/work/notes.txt").expect("call"),
        "ok:granted"
    );
    assert_eq!(
        run_probe(&c, &plan, "read", "/work/src/lib.txt").expect("call"),
        "ok:nested"
    );
    assert_eq!(
        run_probe(&c, &plan, "list", "/work").expect("call"),
        "ok:notes.txt,src"
    );
}

#[test]
fn the_guest_cannot_read_outside_its_mount() {
    let w = world();
    let c = fs_capsule("read");
    let plan = fs_plan(&w, &c, &[Access::Read]);
    let outside = w.outside.to_string_lossy().into_owned();
    for target in [
        "/work/../private.txt",
        "/work/src/../../private.txt",
        "../private.txt",
        "/etc/hosts",
        "/",
        outside.as_str(),
    ] {
        let op = if target == "/" { "list" } else { "read" };
        assert_err(&run_probe(&c, &plan, op, target).expect("call"), target);
    }
}

#[cfg(unix)]
#[test]
fn the_guest_cannot_follow_a_symlink_out_of_its_mount() {
    let w = world();
    std::os::unix::fs::symlink(&w.outside, w.project.join("escape")).expect("symlink");
    let c = fs_capsule("read");
    let plan = fs_plan(&w, &c, &[Access::Read]);
    assert_err(
        &run_probe(&c, &plan, "read", "/work/escape").expect("call"),
        "symlink out",
    );
}

#[test]
fn without_a_mount_the_guest_sees_no_filesystem() {
    let w = world();
    let c = fs_capsule("read");
    let plan = SandboxPlan::without_grants(&c.manifest).expect("plan");
    assert_err(
        &run_probe(&c, &plan, "read", "/work/notes.txt").expect("call"),
        "no preopen",
    );
    assert_err(
        &run_probe(&c, &plan, "read", &w.outside.to_string_lossy()).expect("call"),
        "no preopen, absolute host path",
    );
}

#[test]
fn a_read_only_mount_refuses_the_guests_writes() {
    let w = world();
    let c = fs_capsule("read");
    let plan = fs_plan(&w, &c, &[Access::Read]);
    assert_err(
        &run_probe(&c, &plan, "write", "/work/new.txt").expect("call"),
        "write on a read-only mount",
    );
    assert!(!w.project.join("new.txt").exists());
    assert_err(
        &run_probe(&c, &plan, "write", "/work/notes.txt").expect("call"),
        "overwrite on a read-only mount",
    );
    assert_eq!(
        std::fs::read(w.project.join("notes.txt")).expect("read"),
        b"granted"
    );
}

#[test]
fn a_read_write_mount_takes_the_guests_writes_inside_only() {
    let w = world();
    let c = fs_capsule("both");
    let plan = fs_plan(&w, &c, &[Access::Read, Access::Write]);
    assert_eq!(
        run_probe(&c, &plan, "write", "/work/new.txt").expect("call"),
        "ok:written"
    );
    assert_eq!(
        std::fs::read(w.project.join("new.txt")).expect("written on the host"),
        b"written by a capsule"
    );
    assert_err(
        &run_probe(&c, &plan, "write", "/work/../planted.txt").expect("call"),
        "write outside",
    );
    assert!(!w.home.join("planted.txt").exists());
}

#[test]
fn a_guest_that_imports_sockets_does_not_link_under_network_none() {
    let c = probe_capsule(probe_manifest(r#"network = "none""#, &["read:/work"]));
    let err = run_probe(&c, &SandboxPlan::deny_all(), "read", "/work/notes.txt")
        .expect_err("sockets are not linked for a network-none capsule");
    assert!(err.to_string().contains("instantiate"), "{err}");
}

/// Loopback listeners stand in for remote hosts here (the real allowlist
/// refuses non-global addresses, so this plan is built directly).
#[test]
fn the_guest_reaches_only_allowlisted_addresses() {
    let allowed = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let other = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let allowed_addr = allowed.local_addr().expect("addr");
    let other_addr = other.local_addr().expect("addr");
    let c = probe_capsule(probe_manifest(
        "network = \"egress-allowed\"\nnetwork_allow = [\"1.1.1.1:443\"]",
        STD_GUEST_FS,
    ));
    let plan = SandboxPlan {
        preopens: Vec::new(),
        network: NetworkPlan::Allow(vec![allowed_addr]),
    };
    assert_eq!(
        run_probe(&c, &plan, "connect", &allowed_addr.to_string()).expect("call"),
        "ok:connected"
    );
    assert_err(
        &run_probe(&c, &plan, "connect", &other_addr.to_string()).expect("call"),
        "not allowlisted",
    );
    assert_err(
        &run_probe(
            &c,
            &SandboxPlan::deny_all(),
            "connect",
            &allowed_addr.to_string(),
        )
        .expect("call"),
        "deny-all plan",
    );
}

/// M-6 path end to end: an egress capsule run with no member consent gets
/// no address, even one its signed manifest lists.
#[test]
fn an_egress_capsule_without_consent_reaches_nothing() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let addr = listener.local_addr().expect("addr");
    let c = probe_capsule(probe_manifest(
        "network = \"egress-allowed\"\nnetwork_allow = [\"1.1.1.1:443\"]",
        STD_GUEST_FS,
    ));
    let plan = SandboxPlan::without_grants(&c.manifest).expect("plan");
    assert_eq!(plan.network(), &NetworkPlan::DenyAll);
    assert_err(
        &run_probe(&c, &plan, "connect", &addr.to_string()).expect("call"),
        "no consent",
    );
}
