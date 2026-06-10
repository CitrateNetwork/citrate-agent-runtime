//! CIT-AGENT-3e — re-pack the in-tree capsule fleet into signed `.cps` archives.
//!
//! Reads each `capsules/<name>/` loose dir, packs it with
//! [`citrate_agent_core::capsule::pack::pack`] (computes the real content_hash,
//! embeds it, signs `sha256(content_hash)`), and writes `capsules/<name>/<name>.cps`.
//!
//! Key custody (FUA-AGENT-RUNTIME-02): the bundled-tier signing seed comes from
//! `CITRATE_CAPSULE_SIGNING_SEED` (64 hex) or a pre-existing (gitignored)
//! `<repo>/.capsule-signing-key.env`. The packer **never mints a key into the
//! working tree on its own** — if no seed is provided it exits with instructions,
//! so a private key never lands on disk by accident. The PUBLIC key is what the
//! runtime embeds (`capsule::bundled_key`); production injects an HSM-resident
//! key the same way.
//!
//! Usage: `cargo run -p citrate-agent-core --bin cit-capsule-pack [-- <capsules_dir>]`

use citrate_agent_core::capsule::pack::{pack, CapsuleSource};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // agent/core -> agent -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("agent/core has a repo root two levels up")
        .to_path_buf()
}

fn parse_seed_hex(h: &str) -> [u8; 32] {
    let bytes = hex::decode(h.trim()).expect("CITRATE_CAPSULE_SIGNING_SEED must be hex");
    assert_eq!(bytes.len(), 32, "signing seed must be 32 bytes (64 hex chars)");
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes);
    s
}

/// FUA-AGENT-RUNTIME-02 (SECREM-02): load the signing seed from an EXPLICIT
/// source — the `CITRATE_CAPSULE_SIGNING_SEED` env var, else a pre-existing
/// (gitignored) `.capsule-signing-key.env`. The packer never *mints* a key into
/// the working tree on its own: a private key landing on disk by accident is
/// exactly the footgun the audit flagged. If no seed is found, fail with
/// instructions rather than silently create one.
fn load_key(repo: &Path) -> SigningKey {
    if let Ok(h) = std::env::var("CITRATE_CAPSULE_SIGNING_SEED") {
        return SigningKey::from_bytes(&parse_seed_hex(&h));
    }
    let key_file = repo.join(".capsule-signing-key.env");
    if let Ok(contents) = std::fs::read_to_string(&key_file) {
        for line in contents.lines() {
            if let Some(v) = line.trim().strip_prefix("CITRATE_CAPSULE_SIGNING_SEED=") {
                return SigningKey::from_bytes(&parse_seed_hex(v));
            }
        }
    }
    eprintln!(
        "no capsule signing seed found — refusing to mint one into the working tree.\n\
         Provide it explicitly, e.g.:\n  \
         CITRATE_CAPSULE_SIGNING_SEED=$(openssl rand -hex 32) cargo run --bin cit-capsule-pack\n\
         or write `CITRATE_CAPSULE_SIGNING_SEED=<64hex>` into {} (gitignored).\n\
         Production injects the HSM-resident bundled key the same way.",
        key_file.display()
    );
    std::process::exit(2);
}

fn read_dir_files(dir: &Path, prefix: &str) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    out.insert(format!("{prefix}{name}"), std::fs::read(&p).expect("read sub file"));
                }
            }
        }
    }
    out
}

fn main() {
    let repo = repo_root();
    let capsules_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("capsules"));
    let key = load_key(&repo);
    let pubkey = key.verifying_key().to_bytes();

    let mut names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&capsules_dir).expect("read capsules dir") {
        let dir = entry.expect("dir entry").path();
        if !dir.is_dir() {
            continue;
        }
        if !dir.join("manifest.toml").exists() || !dir.join("capsule.wasm").exists() {
            continue;
        }
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let source = CapsuleSource {
            manifest_toml: std::fs::read_to_string(dir.join("manifest.toml")).expect("manifest"),
            wit: std::fs::read(dir.join("wit/world.wit")).unwrap_or_default(),
            wasm: std::fs::read(dir.join("capsule.wasm")).expect("wasm"),
            procedure: std::fs::read(dir.join("procedure.md")).unwrap_or_default(),
            gherkin: read_dir_files(&dir.join("gherkin"), "gherkin/"),
            specs: read_dir_files(&dir.join("specs"), "specs/"),
        };
        let cps = pack(&source, &key).unwrap_or_else(|e| panic!("pack {name}: {e}"));
        let out_path = dir.join(format!("{name}.cps"));
        std::fs::write(&out_path, &cps).expect("write .cps");
        println!("packed {name} → {} ({} bytes)", out_path.display(), cps.len());
        names.push(name);
    }
    names.sort();
    eprintln!("\n{} capsules packed: {names:?}", names.len());
    eprintln!("BUNDLED publisher public key (embed in capsule::bundled_key::BUNDLED_PUBLISHER_KEY):");
    println!("PUBKEY={}", hex::encode(pubkey));
}
