//! CIT-AGENT-3e — re-pack the in-tree capsule fleet into signed `.cps` archives.
//!
//! Reads each `capsules/<name>/` loose dir, packs it with
//! [`citrate_agent_core::capsule::pack::pack`] (computes the real content_hash,
//! embeds it, signs `sha256(content_hash)`), and writes `capsules/<name>/<name>.cps`.
//!
//! Key custody: the bundled-tier signing seed comes from
//! `CITRATE_CAPSULE_SIGNING_SEED` (64 hex) or `<repo>/.capsule-signing-key.env`
//! (gitignored, `.env.*`). If neither exists a fresh key is generated + written
//! there and its PUBLIC key printed — the private seed is never committed. The
//! PUBLIC key is what the runtime embeds (`capsule::bundled_key`). Production
//! swaps the staging seed for an HSM-resident key (same public-key wiring).
//!
//! Usage: `cargo run -p citrate-agent-core --bin cit-capsule-pack [-- <capsules_dir>]`

use citrate_agent_core::capsule::pack::{pack, CapsuleSource};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // agent/core -> agent -> repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("agent/core has a repo root two levels up")
        .to_path_buf()
}

fn random_seed() -> [u8; 32] {
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    let mut s = [0u8; 32];
    f.read_exact(&mut s).expect("read /dev/urandom");
    s
}

fn parse_seed_hex(h: &str) -> [u8; 32] {
    let bytes = hex::decode(h.trim()).expect("CITRATE_CAPSULE_SIGNING_SEED must be hex");
    assert_eq!(bytes.len(), 32, "signing seed must be 32 bytes (64 hex chars)");
    let mut s = [0u8; 32];
    s.copy_from_slice(&bytes);
    s
}

fn load_or_create_key(repo: &Path) -> SigningKey {
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
    let seed = random_seed();
    let body = format!(
        "# Citrate capsule publisher signing key (BUNDLED tier — STAGING).\n\
         # Gitignored (.env.*). Never commit. Production swaps to an HSM-resident key.\n\
         CITRATE_CAPSULE_SIGNING_SEED={}\n",
        hex::encode(seed)
    );
    std::fs::write(&key_file, body).expect("write .capsule-signing-key.env");
    eprintln!("generated a new bundled signing key → {}", key_file.display());
    SigningKey::from_bytes(&seed)
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
    let key = load_or_create_key(&repo);
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
