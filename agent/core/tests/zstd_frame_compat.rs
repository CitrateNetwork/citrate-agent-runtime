//! zstd compatibility pins for the `.cps` capsule format.
//!
//! A `.cps` is a zstd-compressed tar, and the fleet under `capsules/` was
//! packed with zstd 0.13. These tests pin that the zstd in the graph still
//! decodes those bytes to the same content, that a frame written by zstd
//! 0.13.3 still decodes, that the encoder `pack` uses still writes the same
//! bytes (reproducible `.cps` output), and that streams round-trip.
//!
//! The last test is a lockfile tripwire: the zstd crates must stay at or
//! above the fixed versions (RUSTSEC-2026-0391/0398/0403/0410), and
//! wasmtime's compilation-cache crate (which holds zstd at 0.13) must stay
//! out of the graph. The runtime never configures a wasmtime cache.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use citrate_agent_core::capsule::archive::read_archive;
use sha2::{Digest, Sha256};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/zstd")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The payload the golden frames were written from: 16 KiB of
/// low-entropy pseudo-random letters (fixed-seed LCG), then a repeated line.
fn golden_payload() -> Vec<u8> {
    let mut v = Vec::with_capacity(48 * 1024);
    let mut x: u32 = 0x4369_7472;
    for _ in 0..16384 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push(b'a' + ((x >> 24) % 16) as u8);
    }
    for _ in 0..1024 {
        v.extend_from_slice(b"citrate capsule golden frame\n");
    }
    v
}

/// sha256 of `golden_payload()`, computed independently with the zstd CLI
/// (`zstd -dc golden-zstd0133-level19.zst | shasum -a 256`).
const GOLDEN_PAYLOAD_SHA256: &str =
    "50806362c55d23baed581877bcdb3a56139839588dc0fba0735cfab1ddec1906";

/// Streamed `zstd::Encoder` output, the way `pack` writes a `.cps`.
fn encode_streamed(data: &[u8], level: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = zstd::Encoder::new(&mut out, level).expect("encoder init");
    enc.write_all(data).expect("encoder write");
    enc.finish().expect("encoder finish");
    out
}

fn decode_streamed(frame: &[u8]) -> Vec<u8> {
    let mut dec = zstd::Decoder::new(frame).expect("decoder init");
    let mut out = Vec::new();
    dec.read_to_end(&mut out).expect("decode");
    out
}

#[test]
fn golden_payload_matches_its_pinned_hash() {
    let payload = golden_payload();
    assert_eq!(payload.len(), 16384 + 1024 * 29);
    assert_eq!(sha256_hex(&payload), GOLDEN_PAYLOAD_SHA256);
}

/// Frames written by zstd 0.13.3 (levels 3 and 19, the levels the tests and
/// `pack` use) decode to the original payload, by stream and by one shot.
#[test]
fn frames_written_by_zstd_0_13_still_decode() {
    let payload = golden_payload();
    for name in ["golden-zstd0133-level3.zst", "golden-zstd0133-level19.zst"] {
        let frame = fixture(name);
        assert_eq!(decode_streamed(&frame), payload, "{name}: streamed decode");
        assert_eq!(
            zstd::decode_all(&frame[..]).expect("decode_all"),
            payload,
            "{name}: decode_all"
        );
    }
}

/// The encoder writes the same bytes zstd 0.13.3 wrote, so a repacked `.cps`
/// is byte-for-byte reproducible across the upgrade. If a future libzstd
/// changes its output, this fails and the change is a deliberate decision.
#[test]
fn encoder_output_is_byte_identical_to_zstd_0_13() {
    let payload = golden_payload();
    for (level, name) in [
        (3, "golden-zstd0133-level3.zst"),
        (19, "golden-zstd0133-level19.zst"),
    ] {
        assert!(
            encode_streamed(&payload, level) == fixture(name),
            "level {level}: encoder output differs from the zstd 0.13.3 frame {name}"
        );
    }
}

#[test]
fn streams_round_trip_across_sizes_and_levels() {
    let payload = golden_payload();
    let inputs: [&[u8]; 4] = [b"", b"x", &payload[..100], &payload];
    for level in [1, 3, 19] {
        for input in inputs {
            let frame = encode_streamed(input, level);
            assert_eq!(
                decode_streamed(&frame),
                input,
                "level {level}, {} bytes",
                input.len()
            );
            assert_eq!(
                zstd::decode_all(&zstd::encode_all(input, level).expect("encode_all")[..])
                    .expect("decode_all"),
                input,
                "one-shot level {level}, {} bytes",
                input.len()
            );
        }
    }
}

/// Two frames back to back decode as one stream (the `.cps` reader uses the
/// streaming decoder, which reads concatenated frames).
#[test]
fn concatenated_frames_decode_as_one_stream() {
    let payload = golden_payload();
    let (a, b) = payload.split_at(payload.len() / 2);
    let mut stream = encode_streamed(a, 19);
    stream.extend_from_slice(&encode_streamed(b, 3));
    assert_eq!(decode_streamed(&stream), payload);
}

/// Every committed `.cps` (packed with zstd 0.13) decompresses to the same
/// tar it held before the upgrade, and still reads as an archive. Hashes
/// computed with the zstd CLI: `zstd -dc <file> | shasum -a 256`.
#[test]
fn committed_capsules_decode_to_their_pinned_tars() {
    const PINS: &[(&str, &str, usize)] = &[
        (
            "capsules/anchor-session/anchor-session.cps",
            "6d1409bfc361bd428014fc4b2d1822e7a763f96773e4510a3ed763d278524ed7",
            36864,
        ),
        (
            "capsules/echo-chain/echo-chain.cps",
            "550c7fa42e317f968631590a7545b877d83b6755ade7f6174c1907fdf69d5479",
            21504,
        ),
        (
            "capsules/hello/hello.cps",
            "c2b45a7574bbdbc8607f76be10da02260431417bea3c9706548814e494850c62",
            23552,
        ),
        (
            "capsules/list-compliance-posture/list-compliance-posture.cps",
            "e1e233c3d859425bc0cc3ad1802284b86395d22baa6bcd67422471876884881b",
            41472,
        ),
        (
            "capsules/provision-user/provision-user.cps",
            "5fc6cfdd4ce146378026123c24860f2350b90f5d4982e6342b24ac37c9efa036",
            38400,
        ),
        (
            "capsules/query-decisions-by-tenant/query-decisions-by-tenant.cps",
            "ef629a591d57359447d6d8b0db02ac830224196ae343ba3671e265646a6729a5",
            42496,
        ),
        (
            "capsules/query-supplier-status/query-supplier-status.cps",
            "bff72efca126afc656913af78f3ee5f15045b5d214abf33a404dfa0bc3e90906",
            36864,
        ),
        (
            "capsules/revoke-role/revoke-role.cps",
            "dd5751c63396679f8d1bf1d26801515a9e2ab03008291506998c8cf9361fab3e",
            36352,
        ),
        (
            "capsules/verify-provenance-chain/verify-provenance-chain.cps",
            "2e5224ce008116630fea23e409f692379c988ed2727029f9b866493685f43211",
            38400,
        ),
        (
            "test-fixtures/capsules/eth-sender-test/eth-sender-test.cps",
            "357505b403ced7de94e4aeda62445f731fff2d46750cf14b6c95a1208436047c",
            22016,
        ),
    ];
    for (rel, want_sha, want_len) in PINS {
        let bytes = std::fs::read(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let tar = decode_streamed(&bytes);
        assert_eq!(tar.len(), *want_len, "{rel}: decompressed length");
        assert_eq!(&sha256_hex(&tar), want_sha, "{rel}: decompressed tar hash");
        let contents = read_archive(&bytes[..]).unwrap_or_else(|e| panic!("{rel}: {e}"));
        assert!(!contents.wasm.is_empty(), "{rel}: capsule.wasm present");
        assert!(
            !contents.manifest.is_empty(),
            "{rel}: manifest.toml present"
        );
    }
}

// ── lockfile tripwire ──────────────────────────────────────────────────────

/// `(name, version)` for every `[[package]]` in the workspace `Cargo.lock`.
fn locked_packages() -> Vec<(String, String)> {
    let lock = std::fs::read_to_string(repo_root().join("Cargo.lock")).expect("read Cargo.lock");
    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            block
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key} = \"")))
                .and_then(|r| r.strip_suffix('"'))
                .map(str::to_string)
        };
        if let (Some(name), Some(version)) = (field("name"), field("version")) {
            out.push((name, version));
        }
    }
    out
}

/// `"2.1.2+zstd.1.5.7"` -> `(2, 1, 2)`.
fn semver_triple(v: &str) -> (u64, u64, u64) {
    let core = v.split(['+', '-']).next().unwrap_or(v);
    let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

#[test]
fn tripwire_lockfile_zstd_is_at_fixed_versions_and_wasmtime_cache_is_absent() {
    let pkgs = locked_packages();
    assert!(
        pkgs.iter().any(|(n, _)| n == "wasmtime"),
        "lockfile parse sanity: wasmtime is locked"
    );
    let floors: &[(&str, (u64, u64, u64))] = &[
        ("zstd", (0, 14, 3)),     // RUSTSEC-2026-0391
        ("zstd-safe", (8, 2, 0)), // RUSTSEC-2026-0398, 0403
        ("zstd-sys", (2, 1, 2)),  // RUSTSEC-2026-0410
    ];
    let mut bad = Vec::new();
    for (name, version) in &pkgs {
        if name == "wasmtime-internal-cache" {
            bad.push(format!(
                "{name} {version} (wasmtime `cache` feature; requires zstd 0.13)"
            ));
        }
        for (crate_name, floor) in floors {
            if name == crate_name && semver_triple(version) < *floor {
                bad.push(format!(
                    "{name} {version} < {}.{}.{}",
                    floor.0, floor.1, floor.2
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "Cargo.lock holds vulnerable zstd or the wasmtime cache crate: {bad:?}"
    );
}
