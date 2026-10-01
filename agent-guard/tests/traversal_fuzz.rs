//! HUP-S2.8 traversal fuzz: a deterministic generator builds thousands of
//! paths from hostile pieces (`..`, `.`, case variants, symlinks to denied
//! dirs, relative and dangling links, Windows separators, doubled and
//! trailing slashes, `~`) against a real directory tree, and an oracle that
//! asks the OS (`std::fs::canonicalize`) where each one really lands.
//!
//! Properties:
//!  1. No path the OS resolves inside a denied root is ever allowed.
//!  2. No allowed path is inside a denied root.
//!  3. When the guard allows and the OS can resolve, both agree on the target.
//!
//! The generator is a fixed-seed xorshift so failures replay exactly
//! (proptest is pinned to a version this lockfile cannot take without
//! downgrading other crates; see the README).

#![cfg(unix)]

use citrate_agent_guard::{check_path, GuardContext};
use std::os::unix::fs::symlink;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

struct World {
    _tmp: TempDir,
    home: PathBuf,
    proj: PathBuf,
    denied_roots: Vec<PathBuf>,
}

fn mkdir(p: &Path) {
    std::fs::create_dir_all(p).expect("mkdir");
}

fn touch(p: &Path) {
    if let Some(parent) = p.parent() {
        mkdir(parent);
    }
    std::fs::write(p, b"secret").expect("write");
}

fn build_world() -> World {
    let tmp = TempDir::new().expect("tempdir");
    let base = std::fs::canonicalize(tmp.path()).expect("canon");
    let home = base.join("home");
    let proj = home.join("work/proj");
    mkdir(&proj.join("src"));
    mkdir(&home.join("data"));
    mkdir(&home.join("other"));

    let ssh = home.join(".ssh");
    touch(&ssh.join("id_rsa"));
    mkdir(&ssh.join("sub"));
    let aws = home.join(".aws");
    touch(&aws.join("credentials"));
    let gnupg = home.join(".gnupg");
    mkdir(&gnupg);
    let keychains = home.join("Library/Keychains");
    touch(&keychains.join("login.keychain-db"));
    let chrome = home.join("Library/Application Support/Google/Chrome");
    touch(&chrome.join("Default/Cookies"));
    let citrate = home.join("Library/Application Support/ai.citrate.core");
    touch(&citrate.join("hermes/bearer.token"));
    let fish = home.join(".local/share/fish/fish_history");
    touch(&fish);
    let zsh = home.join(".zsh_history");
    touch(&zsh);

    symlink(&ssh, proj.join("k")).expect("k");
    symlink("../../.aws", proj.join("rk")).expect("rk");
    symlink(&home, proj.join("up")).expect("up");
    symlink(ssh.join("sub"), proj.join("deep")).expect("deep");
    symlink(&gnupg, home.join("work/c2")).expect("c2");
    symlink(home.join("work/c2"), proj.join("chain")).expect("chain");
    symlink(home.join("data"), proj.join("data")).expect("data");
    symlink(ssh.join("new_key"), proj.join("dangle")).expect("dangle");
    symlink(&zsh, proj.join("hist")).expect("hist");
    symlink(&citrate, home.join("data/appdata")).expect("appdata");

    World {
        _tmp: tmp,
        home,
        proj,
        denied_roots: vec![ssh, aws, gnupg, keychains, chrome, citrate, fish, zsh],
    }
}

const SEGMENTS: &[&str] = &[
    ".",
    "..",
    "..",
    "..",
    "work",
    "proj",
    "src",
    "k",
    "rk",
    "up",
    "deep",
    "chain",
    "data",
    "dangle",
    "hist",
    "appdata",
    ".ssh",
    ".SSH",
    ".aws",
    ".gnupg",
    "Library",
    "Keychains",
    "keychains",
    "Application Support",
    "Google",
    "Chrome",
    "ai.citrate.core",
    "hermes",
    "bearer.token",
    ".local",
    "share",
    "fish",
    "fish_history",
    ".zsh_history",
    "id_rsa",
    "sub",
    "new",
    "x.txt",
    "other",
    "",
];

fn generate(rng: &mut XorShift, home: &Path) -> String {
    let mut s = match rng.below(4) {
        0 => "~/".to_string(),
        1 => format!("{}/", home.display()),
        2 => String::new(),
        _ => "./".to_string(),
    };
    let n = 1 + rng.below(8);
    for i in 0..n {
        let mut seg = SEGMENTS[rng.below(SEGMENTS.len())].to_string();
        if rng.chance(10) {
            seg = seg.to_uppercase();
        }
        s.push_str(&seg);
        if i + 1 < n {
            s.push(if rng.chance(20) { '\\' } else { '/' });
        }
    }
    if rng.chance(15) {
        s.push('/');
    }
    s
}

/// Guided generation: walk the real tree, choosing names that exist where
/// the walk currently is (so most paths resolve), with `..`, `.`, case and
/// separator mutations mixed in.
fn generate_guided(rng: &mut XorShift, w: &World) -> String {
    let (mut s, mut cur) = match rng.below(3) {
        0 => ("~/".to_string(), w.home.clone()),
        1 => (String::new(), w.proj.clone()),
        _ => (format!("{}/", w.proj.display()), w.proj.clone()),
    };
    let n = 1 + rng.below(7);
    for i in 0..n {
        let mut names: Vec<String> = std::fs::read_dir(&cur)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        let seg = if names.is_empty() || rng.chance(15) {
            if rng.chance(70) {
                "..".to_string()
            } else {
                ".".to_string()
            }
        } else {
            names[rng.below(names.len())].clone()
        };
        cur = std::fs::canonicalize(cur.join(&seg)).unwrap_or_else(|_| cur.join(&seg));
        let shown = if rng.chance(10) {
            seg.to_uppercase()
        } else {
            seg
        };
        s.push_str(&shown);
        if i + 1 < n {
            s.push(if rng.chance(20) { '\\' } else { '/' });
        }
    }
    s
}

/// The test's own interpretation of the string (the documented contract:
/// `\` is a separator, `~/` is home, relative joins cwd). Resolution is
/// then left entirely to the OS.
fn interpret(s: &str, home: &Path, cwd: &Path) -> PathBuf {
    let u = s.replace('\\', "/");
    let p = if u == "~" {
        home.to_path_buf()
    } else if let Some(rest) = u.strip_prefix("~/") {
        home.join(rest.trim_start_matches('/'))
    } else {
        PathBuf::from(u)
    };
    if p.is_absolute() {
        p
    } else {
        cwd.join(p)
    }
}

/// Where the OS says `p` lands, if it can tell: the path itself when it
/// exists, else its existing parent plus the new leaf, following dangling
/// symlinks to their targets.
fn os_target(p: &Path, depth: usize) -> Option<PathBuf> {
    if depth > 8 {
        return None;
    }
    if let Ok(c) = std::fs::canonicalize(p) {
        return Some(c);
    }
    if let Ok(md) = std::fs::symlink_metadata(p) {
        if md.file_type().is_symlink() {
            let t = std::fs::read_link(p).ok()?;
            let t = if t.is_absolute() {
                t
            } else {
                p.parent()?.join(t)
            };
            return os_target(&t, depth + 1);
        }
    }
    let name = match p.components().next_back()? {
        Component::Normal(n) => n.to_owned(),
        _ => return None,
    };
    let parent = std::fs::canonicalize(p.parent()?).ok()?;
    if !parent.is_dir() {
        return None;
    }
    Some(parent.join(name))
}

fn lower(p: &Path) -> Vec<String> {
    p.components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect()
}

fn inside_any(p: &Path, roots: &[PathBuf]) -> bool {
    let pk = lower(p);
    roots.iter().any(|r| {
        let rk = lower(r);
        pk.len() >= rk.len() && pk[..rk.len()] == rk[..]
    })
}

#[test]
fn no_constructed_path_into_a_denied_root_is_ever_allowed() {
    let w = build_world();
    let ctx = GuardContext::new(&w.home, &w.proj).with_project_root(&w.proj);
    let mut rng = XorShift(0x5EED_C17A_7E5A_2026);

    // How much of the generated space resolves depends on the filesystem (case-sensitive ext4 on
    // Linux resolves far fewer of the case-mutated names than case-insensitive APFS). So instead
    // of a fixed iteration count, generate deterministic batches until the run is provably
    // non-vacuous on every outcome, up to a hard cap.
    const MIN_KNOWN: usize = 2_000;
    const MIN_DENIED: usize = 1_000;
    const MIN_ALLOWED: usize = 1_000;
    const BATCH: usize = 500;
    const MAX_BASES: usize = 30_000;
    let (mut total, mut oracle_known, mut oracle_denied, mut allowed) = (0, 0, 0, 0);
    let mut bases = 0;
    while bases < MAX_BASES
        && (bases < 3_000
            || oracle_known < MIN_KNOWN
            || oracle_denied < MIN_DENIED
            || allowed < MIN_ALLOWED)
    {
        for _ in 0..BATCH {
            bases += 1;
            let base = if rng.chance(50) {
                generate(&mut rng, &w.home)
            } else {
                generate_guided(&mut rng, &w)
            };
            // Each base is also tried as the parent of a new file (a write).
            for s in [
                base.clone(),
                format!("{}/new_file.txt", base.trim_end_matches('/')),
            ] {
                total += 1;
                let interp = interpret(&s, &w.home, &w.proj);
                let target = os_target(&interp, 0);
                let verdict = check_path(&s, &ctx);

                if let Some(t) = &target {
                    oracle_known += 1;
                    if inside_any(t, &w.denied_roots) {
                        oracle_denied += 1;
                        assert!(
                            verdict.is_err(),
                            "ALLOWED {s:?}, which the OS resolves to {t:?} inside a denied root"
                        );
                    }
                }
                if let Ok(p) = &verdict {
                    allowed += 1;
                    assert!(
                        !inside_any(p.as_path(), &w.denied_roots),
                        "ALLOWED {s:?} as {:?}, inside a denied root",
                        p.as_path()
                    );
                    if let Some(t) = &target {
                        assert_eq!(
                            lower(p.as_path()),
                            lower(t),
                            "guard and OS disagree on where {s:?} lands"
                        );
                    }
                }
            }
        }
    }
    eprintln!(
        "bases={bases} total={total} known={oracle_known} denied={oracle_denied} allowed={allowed}"
    );
    // Guard against a vacuous run: every outcome must be reached many times, on every platform.
    assert_eq!(total, bases * 2);
    assert!(
        oracle_known >= MIN_KNOWN,
        "oracle resolved only {oracle_known} in {bases} bases"
    );
    assert!(
        oracle_denied >= MIN_DENIED,
        "only {oracle_denied} denied-root hits in {bases} bases"
    );
    assert!(
        allowed >= MIN_ALLOWED,
        "only {allowed} allowed paths in {bases} bases"
    );
}
