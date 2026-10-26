//! Pins on the capsule LOAD entry points (`Capsule::from_archive`,
//! `Capsule::from_archive_verified`, `CapsuleDispatch::load_from_dir`).
//!
//! The unit tests in `capsule/archive.rs` exercise `read_archive_capped`
//! with an explicit test cap. These tests go through the production
//! readers, so they fail if a load path stops applying the production
//! decompression bound.

use std::io::{Read, Write};

use citrate_agent_core::capsule::archive::MAX_DECOMPRESSED_BYTES;
use citrate_agent_core::capsule::dispatch::CapsuleDispatch;
use citrate_agent_core::capsule::Capsule;

/// A `.cps` (zstd tar) whose first entry, `procedure.md`, decompresses to
/// `MAX_DECOMPRESSED_BYTES + 1 MiB` of zeros. The compressed archive is a few
/// KiB; it is produced by streaming, so the test never holds the expanded
/// body on the write side.
fn over_cap_cps() -> Vec<u8> {
    let over = MAX_DECOMPRESSED_BYTES + 1024 * 1024;
    let mut enc = zstd::Encoder::new(Vec::new(), 1).expect("zstd encoder");
    {
        let mut tar = tar::Builder::new(&mut enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(over);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "procedure.md", std::io::repeat(0).take(over))
            .expect("append over-cap entry");
        for (path, bytes) in [
            ("manifest.toml", &b"[capsule]\nname = \"hello\"\n"[..]),
            ("capsule.wit", &b"// wit"[..]),
            ("capsule.wasm", &b"\x00asm\x01\x00\x00\x00"[..]),
            ("SIGNATURES/publisher.sig", &[0u8; 64][..]),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(bytes.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, path, bytes).expect("append entry");
        }
        tar.finish().expect("tar finish");
    }
    let out = enc.finish().expect("zstd finish");
    assert!(
        out.len() < 1024 * 1024,
        "fixture must stay small compressed"
    );
    out
}

/// The production reader stops at `MAX_DECOMPRESSED_BYTES`: an archive that
/// expands past it is refused while it is being read, before the manifest is
/// parsed or any hash is computed. Without the bound the whole body is read
/// and the load only fails later, at manifest parsing or the hash check.
#[test]
fn from_archive_stops_reading_at_the_decompression_bound() {
    let cps = over_cap_cps();
    let err = Capsule::from_archive(&cps[..]).expect_err("over-cap archive must not load");
    let msg = err.to_string();
    assert!(
        msg.contains("read entry procedure.md") || msg.contains("tar entr"),
        "the read itself must fail at the bound, got: {msg}"
    );
}

/// Same bound on the verified path the fleet loader uses.
#[test]
fn verified_load_stops_reading_at_the_decompression_bound() {
    let cps = over_cap_cps();
    let registry = citrate_agent_core::capsule::bundled_key::registry();
    let err = Capsule::from_archive_verified(&cps[..], &registry)
        .expect_err("over-cap archive must not load");
    let msg = err.to_string();
    assert!(
        msg.contains("read entry procedure.md") || msg.contains("tar entr"),
        "the read itself must fail at the bound, got: {msg}"
    );
}

/// At the fleet entry point: an over-cap `.cps` is refused on its own, the
/// reason is the bounded read, and the capsule never becomes runnable.
#[test]
fn load_from_dir_refuses_an_over_cap_capsule_at_the_read() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("hello");
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::File::create(dir.join("hello.cps"))
        .and_then(|mut f| f.write_all(&over_cap_cps()))
        .expect("write cps");
    let dispatch = CapsuleDispatch::load_from_dir(tmp.path(), None, None, None)
        .expect("one bad archive does not fail the fleet load");
    assert!(!dispatch.has("hello"));
    assert!(!dispatch.is_runnable("hello"));
    let reason = dispatch
        .refused_capsules()
        .get("hello")
        .expect("over-cap capsule is listed as refused");
    assert!(
        reason.contains("read entry procedure.md") || reason.contains("tar entr"),
        "refused at the bounded read, got: {reason}"
    );
}

// ── wasmtime floor ────────────────────────────────────────────────────────

/// Lowest wasmtime / wasmtime-wasi / wasmtime-wasi-io release the capsule
/// sandbox may resolve to (the floor documented in `agent/core/Cargo.toml`).
const WASMTIME_FLOOR: (u64, u64, u64) = (49, 0, 2);
const SANDBOX_CRATES: [&str; 3] = ["wasmtime", "wasmtime-wasi", "wasmtime-wasi-io"];

/// Every `(name, version)` in a Cargo.lock for the sandbox crates.
fn sandbox_versions(lock: &str) -> Vec<(String, (u64, u64, u64))> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in lock.lines() {
        if let Some(n) = line.strip_prefix("name = \"") {
            name = Some(n.trim_end_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("version = \"") {
            if let Some(n) = name.take() {
                if SANDBOX_CRATES.contains(&n.as_str()) {
                    let parts: Vec<u64> = v
                        .trim_end_matches('"')
                        .split(['.', '-', '+'])
                        .take(3)
                        .map(|p| p.parse().unwrap_or(0))
                        .collect();
                    out.push((n, (parts[0], parts[1], parts[2])));
                }
            }
        }
    }
    out
}

fn below_floor(lock: &str) -> Vec<String> {
    sandbox_versions(lock)
        .into_iter()
        .filter(|(_, v)| *v < WASMTIME_FLOOR)
        .map(|(n, v)| format!("{n} {}.{}.{}", v.0, v.1, v.2))
        .collect()
}

#[test]
fn resolved_wasmtime_is_at_or_above_the_floor() {
    let lock_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path).expect("read workspace Cargo.lock");
    let found = sandbox_versions(&lock);
    for c in SANDBOX_CRATES {
        assert!(
            found.iter().any(|(n, _)| n == c),
            "{c} not found in Cargo.lock"
        );
    }
    assert_eq!(below_floor(&lock), Vec::<String>::new());
}

/// Negative control: the parser flags a lockfile that resolves below the floor.
#[test]
fn floor_check_flags_an_old_wasmtime() {
    let lock = "[[package]]\nname = \"wasmtime\"\nversion = \"45.0.0\"\n\n\
                [[package]]\nname = \"wasmtime-wasi\"\nversion = \"49.0.1\"\n\n\
                [[package]]\nname = \"wasmtime-environ\"\nversion = \"1.0.0\"\n";
    assert_eq!(
        below_floor(lock),
        vec!["wasmtime 45.0.0", "wasmtime-wasi 49.0.1"]
    );
}

// ── WIT / manifest cross-check on the verified load path ──────────────────

/// The shipped `hello` capsule, repacked and signed with a test key, with its
/// WIT optionally rewritten. Verified against a registry trusting that key, so
/// the only thing under test is the WIT/manifest cross-check.
fn repacked_hello(
    wit_extra_import: Option<&str>,
) -> (
    Vec<u8>,
    citrate_agent_core::capsule::tiers::StaticKeyRegistry,
) {
    use citrate_agent_core::capsule::archive::read_archive;
    use citrate_agent_core::capsule::pack::{pack, CapsuleSource};
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../capsules/hello/hello.cps");
    let shipped =
        read_archive(&std::fs::read(&path).expect("read hello.cps")[..]).expect("hello reads");
    let mut wit = String::from_utf8(shipped.wit.clone()).expect("utf8 wit");
    if let Some(import) = wit_extra_import {
        wit = wit.replacen(
            "world hello {",
            &format!("world hello {{\n    import {import};"),
            1,
        );
        assert!(wit.contains(import), "fixture rewrite applied");
    }
    let source = CapsuleSource {
        manifest_toml: String::from_utf8(shipped.manifest.clone()).expect("utf8 manifest"),
        wit: wit.into_bytes(),
        wasm: shipped.wasm.clone(),
        procedure: shipped.procedure.clone(),
        gherkin: shipped.gherkin.clone(),
        specs: shipped.specs.clone(),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x2c; 32]);
    let registry = citrate_agent_core::capsule::tiers::StaticKeyRegistry {
        bundled: Some(key.verifying_key().to_bytes()),
        managed: None,
    };
    (pack(&source, &key).expect("pack"), registry)
}

/// Control: the repacked capsule verifies under the test key.
#[test]
fn verified_load_accepts_a_consistent_capsule() {
    let (cps, registry) = repacked_hello(None);
    Capsule::from_archive_verified(&cps[..], &registry).expect("consistent capsule loads");
}

/// A validly signed capsule whose WIT imports sockets while its manifest
/// declares `network = "none"` is refused at load.
#[test]
fn verified_load_refuses_a_wit_socket_import_the_manifest_denies() {
    let (cps, registry) = repacked_hello(Some("wasi:sockets/tcp@0.2.0"));
    let err = Capsule::from_archive_verified(&cps[..], &registry)
        .expect_err("WIT/manifest mismatch must refuse the load");
    assert!(err.to_string().contains("WIT mismatch"), "got: {err}");
}

/// Same for a filesystem import with an empty `[capability].filesystem`.
#[test]
fn verified_load_refuses_a_wit_filesystem_import_the_manifest_denies() {
    let (cps, registry) = repacked_hello(Some("wasi:filesystem/types@0.2.0"));
    let err = Capsule::from_archive_verified(&cps[..], &registry)
        .expect_err("WIT/manifest mismatch must refuse the load");
    assert!(err.to_string().contains("WIT mismatch"), "got: {err}");
}

// ── instantiate-time compute bound ────────────────────────────────────────

fn unsigned_test_capsule(wasm: Vec<u8>) -> Capsule {
    let manifest = citrate_agent_core::capsule::manifest::Manifest::parse(
        r#"
[capsule]
name = "spin"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false
[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]
[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false
[overlay]
[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "test"
tla_spec = ""
[signing]
tier = "bundled"
"#,
    )
    .expect("manifest parses");
    Capsule {
        manifest,
        archive: citrate_agent_core::capsule::archive::ArchiveContents {
            wasm,
            ..Default::default()
        },
    }
}

/// A component whose core `start` function never returns traps during
/// `Capsule::instantiate*` once the engine's epoch advances, instead of
/// parking the calling thread. The deadline armed before `linker.instantiate`
/// is ~120 ticks; here a test ticker advances the epoch every 10 ms, so the
/// trap lands in about a second. 60 s is the "it hung" verdict.
#[test]
fn a_runaway_start_function_traps_during_instantiate() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let wat = r#"(component
        (core module $m
            (func $spin (loop $l (br $l)))
            (start $spin))
        (core instance (instantiate $m)))"#;
    let capsule = unsigned_test_capsule(wat::parse_str(wat).expect("WAT compiles"));
    let engine = citrate_agent_core::capsule::wasm::EngineFactory::build().expect("engine");
    let linker = capsule
        .prepare_linker(&engine)
        .expect("linker")
        .into_linker();

    let stop = Arc::new(AtomicBool::new(false));
    let ticker = {
        let (engine, stop) = (engine.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                engine.increment_epoch();
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(
            capsule
                .instantiate(&engine, &linker)
                .map_err(|e| e.to_string()),
        );
    });
    let outcome = rx.recv_timeout(Duration::from_secs(60));
    stop.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    let result = outcome.expect("instantiate of a spinning start function hung past 60 s");
    assert!(
        result.is_err(),
        "a start function that never returns must not instantiate"
    );
}

// ── eth-send host call carries the manifest's risk tier to the gate ───────

struct RecordingGate(
    std::sync::Mutex<Vec<citrate_agent_core::capsule::dispatcher::ApprovalRequest>>,
);
impl citrate_agent_core::capsule::dispatcher::ApprovalGate for RecordingGate {
    fn request(
        &self,
        req: citrate_agent_core::capsule::dispatcher::ApprovalRequest,
    ) -> Result<(), String> {
        self.0.lock().expect("lock").push(req);
        Err("recorded, not approved".to_string())
    }
}

const ETH_SENDER_HIGH_TIER: &str = r#"
[capsule]
name = "eth-sender-test"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
[capability]
network = "none"
filesystem = []
chain_calls = ["eth_send:0x4a86659BDab24dc444C72fbbaD4cd83491820E40"]
subagent_spawn = false
[data_class]
reads = ["PUBLIC"]
writes = ["PUBLIC"]
emits = ["PUBLIC"]
[risk]
tier = "high"
required_roles = ["Reviewer", "ComplianceOfficer"]
break_glass_eligible = false
[overlay]
[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "test"
tla_spec = ""
[signing]
tier = "bundled"
"#;

/// The `citrate:chain/eth-send` host function hands the approval gate the
/// risk tier and required roles from the CALLING capsule's manifest, so the
/// gate can demand the role quorum. A gate that saw a lower tier would
/// release a privileged write on the low-tier path.
#[test]
fn eth_send_host_call_carries_the_manifest_tier_to_the_gate() {
    use citrate_agent_core::capsule::manifest::{Manifest, RiskTier, Role};
    use std::sync::Arc;
    use wasmtime::component::Val;

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-fixtures/capsules/eth-sender-test");
    let capsule = Capsule {
        manifest: Manifest::parse(ETH_SENDER_HIGH_TIER).expect("manifest"),
        archive: citrate_agent_core::capsule::archive::ArchiveContents {
            wasm: std::fs::read(dir.join("capsule.wasm")).expect("read wasm"),
            ..Default::default()
        },
    };
    let engine = citrate_agent_core::capsule::wasm::EngineFactory::build().expect("engine");
    let linker = capsule
        .prepare_linker(&engine)
        .expect("linker")
        .into_linker();
    let gate = Arc::new(RecordingGate(std::sync::Mutex::new(Vec::new())));
    let (mut store, instance) = capsule
        .instantiate_with_write_path(&engine, &linker, None, None, Some(gate.clone()))
        .expect("instantiate");

    let iface = instance
        .get_export(&mut store, None, "citrate:eth-sender-test/action@0.1.0")
        .expect("action interface");
    let func_idx = instance
        .get_export(&mut store, Some(&iface.1), "send")
        .expect("send func");
    let func = instance.get_func(&mut store, func_idx.1).expect("func");
    let to = hex::decode("4a86659BDab24dc444C72fbbaD4cd83491820E40").expect("hex");
    let args = [
        Val::List(to.into_iter().map(Val::U8).collect()),
        Val::List(vec![Val::U8(0xab)]),
    ];
    let mut results = [Val::Bool(false)];
    func.call(&mut store, &args, &mut results)
        .expect("call completes");

    let seen = gate.0.lock().expect("lock");
    assert_eq!(seen.len(), 1, "the gate is consulted once");
    assert_eq!(
        seen[0].tier,
        RiskTier::High,
        "gate must see the manifest tier"
    );
    assert_eq!(
        seen[0].required_roles,
        vec![Role::Reviewer, Role::ComplianceOfficer]
    );
    assert_eq!(seen[0].capsule_name, "eth-sender-test");
}
