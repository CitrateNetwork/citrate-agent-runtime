//! HUP-S2.1 traversal fuzz for folder grants. A fixed-seed generator builds
//! paths from hostile pieces (`..`, `.`, case variants, symlinks out of and
//! into grants, `link/..`, relative and dangling links, Windows separators,
//! doubled and trailing slashes, `~`) against a real tree holding live,
//! revoked and expired grants plus default-deny locations. An oracle asks
//! the OS (`std::fs::canonicalize`) where each path really lands.
//!
//! Properties, for every generated path and both operations:
//!  1. Allowed ⇒ the OS target is inside a live grant for that operation.
//!  2. Allowed ⇒ the OS target is not inside a default-deny location.
//!  3. The OS target is inside a deny location, or outside every live grant
//!     for that operation ⇒ denied (revoked and expired grants count for
//!     nothing; full access never allows a write).
//!  4. Allowed and the OS can resolve ⇒ grant check and OS agree on the
//!     target.
//!
//! Like agent-guard's fuzz, the run continues in deterministic batches until
//! every outcome has been reached a minimum number of times, so it is not
//! vacuous on case-sensitive filesystems either.

#![cfg(unix)]

use citrate_agent_grants::{Access, Decision, FolderGrants, GrantRequest, GrantScope, Op};
use std::os::unix::fs::symlink;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;

const T0: u64 = 1_790_000_000;
const NOW: u64 = T0 + 1_000;
const MEMBER: &str = "0x00000000000000000000000000000000000000aa";

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
    /// Live grant roots per operation (what the oracle may allow).
    live_read: Vec<PathBuf>,
    live_write: Vec<PathBuf>,
    /// Roots of grants that are revoked or expired at `NOW`.
    dead: Vec<PathBuf>,
    /// `.env` files no live folder grant covers: never allowed, even under
    /// full access and a shallow folder grant on their grandparent.
    stray_env: Vec<PathBuf>,
    grants: FolderGrants,
    case_insensitive: bool,
}

fn mkdir(p: &Path) {
    std::fs::create_dir_all(p).expect("mkdir");
}

fn touch(p: &Path) {
    if let Some(parent) = p.parent() {
        mkdir(parent);
    }
    std::fs::write(p, b"x").expect("write");
}

/// `full_access`: the second world adds a read-only full-access grant over
/// home, so the write side of every path must still come from folder grants.
fn build_world(full_access: bool) -> World {
    let tmp = TempDir::new().expect("tempdir");
    let base = std::fs::canonicalize(tmp.path()).expect("canon");
    let home = base.join("home");
    let proj = home.join("work/proj");
    let src = proj.join("src");
    let other = home.join("other");
    let data = home.join("data");
    let sibling = home.join("work/proj-old");
    touch(&src.join("main.rs"));
    touch(&proj.join("readme.md"));
    touch(&proj.join(".env"));
    touch(&other.join("notes.txt"));
    touch(&other.join(".env"));
    touch(&data.join("d.csv"));
    touch(&sibling.join("old.rs"));
    let ssh = home.join(".ssh");
    touch(&ssh.join("id_rsa"));
    let aws = home.join(".aws");
    touch(&aws.join("credentials"));
    let keychains = home.join("Library/Keychains");
    touch(&keychains.join("login.keychain-db"));
    let zsh = home.join(".zsh_history");
    touch(&zsh);

    // Links out of the grants, into them, `..` traps and dangling links.
    symlink(&other, proj.join("out")).expect("out");
    symlink("../..", proj.join("esc")).expect("esc");
    symlink(&ssh, src.join("k")).expect("k");
    symlink("../../../.aws", src.join("rk")).expect("rk");
    symlink(&src, other.join("in")).expect("in");
    symlink(&data, src.join("d")).expect("d");
    symlink(other.join("later.txt"), src.join("dangle")).expect("dangle");
    symlink(&zsh, proj.join("hist")).expect("hist");
    symlink(&sibling, src.join("sib")).expect("sib");

    let mut grants = FolderGrants::new(&home, &proj);
    let req = |root: &Path, access| GrantRequest::folder(root, access, MEMBER, "fuzz");
    grants.grant(req(&proj, Access::Read), T0).expect("grant");
    grants.grant(req(&src, Access::Write), T0).expect("grant");
    let revoked = grants.grant(req(&other, Access::Write), T0).expect("grant");
    grants.revoke(&revoked, T0 + 1).expect("revoke");
    grants
        .grant(req(&other, Access::Read).with_ttl_secs(500), T0)
        .expect("grant");
    grants
        .grant(req(&data, Access::Write).with_ttl_secs(999), T0)
        .expect("grant");
    let mut live_read = vec![proj.clone()];
    if full_access {
        grants
            .grant(GrantRequest::full_access(&home, 3600, MEMBER, "fuzz"), T0)
            .expect("grant");
        // A shallow folder grant on home makes home a `.env` project root
        // for the guard without covering `other/.env` (the TLC finding).
        grants
            .grant(req(&home, Access::Read).with_scope(GrantScope::Shallow), T0)
            .expect("grant");
        live_read.push(home.clone());
    }

    let case_insensitive = home.join("WORK").exists();
    World {
        _tmp: tmp,
        home,
        proj,
        denied_roots: vec![ssh, aws, keychains, zsh],
        live_read,
        live_write: vec![src],
        stray_env: vec![other.join(".env")],
        dead: vec![other, data],
        grants,
        case_insensitive,
    }
}

const SEGMENTS: &[&str] = &[
    ".",
    "..",
    "..",
    "..",
    "work",
    "proj",
    "proj-old",
    "src",
    "main.rs",
    "readme.md",
    ".env",
    "out",
    "esc",
    "k",
    "rk",
    "in",
    "d",
    "dangle",
    "hist",
    "sib",
    "other",
    "notes.txt",
    "data",
    "d.csv",
    ".ssh",
    ".SSH",
    ".aws",
    "Library",
    "Keychains",
    ".zsh_history",
    "id_rsa",
    "new",
    "x.txt",
    "",
];

fn generate(rng: &mut XorShift, w: &World) -> String {
    let mut s = match rng.below(4) {
        0 => "~/".to_string(),
        1 => format!("{}/", w.home.display()),
        2 => String::new(),
        _ => format!("{}/", w.proj.display()),
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

/// Walk the real tree choosing names that exist where the walk is, so most
/// paths resolve, with `..`, `.`, case and separator mutations mixed in.
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

/// The documented interpretation: `\` is a separator, `~/` is home,
/// relative joins cwd. Resolution is left to the OS.
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

/// `Path` drops a trailing `/` or `/.`, which would make the oracle treat
/// `dangling-link/.` as the link itself; the kernel follows the link there.
/// Strip them from the string so the oracle follows it too.
fn trim_trailing(p: PathBuf) -> PathBuf {
    let mut s = p.to_string_lossy().into_owned();
    loop {
        if s.len() > 1 && s.ends_with('/') {
            s.pop();
        } else if s.len() > 2 && s.ends_with("/.") {
            s.truncate(s.len() - 2);
        } else {
            return PathBuf::from(s);
        }
    }
}

/// Where the OS says `p` lands, if it can tell.
fn os_target(p: &Path, depth: usize) -> Option<PathBuf> {
    if depth > 8 {
        return None;
    }
    if let Ok(c) = std::fs::canonicalize(p) {
        return Some(c);
    }
    match std::fs::symlink_metadata(p) {
        Ok(md) if md.file_type().is_symlink() => {
            let t = std::fs::read_link(p).ok()?;
            let t = if t.is_absolute() {
                t
            } else {
                p.parent()?.join(t)
            };
            return os_target(&t, depth + 1);
        }
        Ok(_) => {}
        // Only a plain "not found" has a meaningful landing place. A path
        // through a regular file (`file/../x`) is ENOTDIR to the kernel,
        // while macOS `realpath` would pop it lexically: no oracle answer.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
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

fn key(p: &Path, fold: bool) -> Vec<String> {
    p.components()
        .map(|c| {
            let s = c.as_os_str().to_string_lossy();
            if fold {
                s.to_lowercase()
            } else {
                s.into_owned()
            }
        })
        .collect()
}

fn inside_any(p: &Path, roots: &[PathBuf], fold: bool) -> bool {
    let pk = key(p, fold);
    roots.iter().any(|r| {
        let rk = key(r, fold);
        pk.len() >= rk.len() && pk[..rk.len()] == rk[..]
    })
}

#[derive(Default, Debug)]
struct Counts {
    total: usize,
    known: usize,
    deny_hits: usize,
    outside_hits: usize,
    dead_hits: usize,
    allowed: usize,
    allowed_write: usize,
}

fn run(full_access: bool, seed: u64) -> Counts {
    let w = build_world(full_access);
    let fold = w.case_insensitive;
    let mut rng = XorShift(seed);
    const MIN_KNOWN: usize = 2_000;
    const MIN_DENY: usize = 500;
    const MIN_OUTSIDE: usize = 500;
    const MIN_DEAD: usize = 200;
    const MIN_ALLOWED: usize = 1_000;
    const MIN_ALLOWED_WRITE: usize = 200;
    const BATCH: usize = 500;
    const MAX_BASES: usize = 40_000;
    let mut c = Counts::default();
    let mut bases = 0;
    while bases < MAX_BASES
        && (bases < 3_000
            || c.known < MIN_KNOWN
            || c.deny_hits < MIN_DENY
            || c.outside_hits < MIN_OUTSIDE
            || c.dead_hits < MIN_DEAD
            || c.allowed < MIN_ALLOWED
            || c.allowed_write < MIN_ALLOWED_WRITE)
    {
        for _ in 0..BATCH {
            bases += 1;
            let base = if rng.chance(50) {
                generate(&mut rng, &w)
            } else {
                generate_guided(&mut rng, &w)
            };
            for s in [
                base.clone(),
                format!("{}/new_file.txt", base.trim_end_matches('/')),
            ] {
                let interp = trim_trailing(interpret(&s, &w.home, &w.proj));
                let target = os_target(&interp, 0);
                for op in [Op::Read, Op::Write] {
                    c.total += 1;
                    let live = match op {
                        Op::Read => &w.live_read,
                        Op::Write => &w.live_write,
                    };
                    let verdict = w.grants.check(&s, op, NOW);
                    if let Some(t) = &target {
                        c.known += 1;
                        let in_deny = inside_any(t, &w.denied_roots, true);
                        // Folded on a case-insensitive disk, exact otherwise:
                        // "outside" must not be over-approximated.
                        let in_live = inside_any(t, live, fold);
                        if in_deny {
                            c.deny_hits += 1;
                        }
                        if !in_live {
                            c.outside_hits += 1;
                            if inside_any(t, &w.dead, fold) {
                                c.dead_hits += 1;
                            }
                        }
                        if in_deny || !in_live {
                            assert!(
                                !matches!(verdict, Decision::Allowed { .. }),
                                "ALLOWED {op:?} {s:?}, which the OS resolves to {t:?} \
                                 (deny={in_deny}, live={in_live})"
                            );
                        }
                    }
                    if let Decision::Allowed { canonical, .. } = &verdict {
                        c.allowed += 1;
                        if op == Op::Write {
                            c.allowed_write += 1;
                        }
                        let p = canonical.as_path();
                        assert!(
                            !inside_any(p, &w.denied_roots, true),
                            "ALLOWED {op:?} {s:?} as {p:?}, inside a deny location"
                        );
                        assert!(
                            !inside_any(p, &w.stray_env, true),
                            "ALLOWED {op:?} {s:?} as {p:?}, a .env no folder grant covers"
                        );
                        assert!(
                            inside_any(p, live, fold),
                            "ALLOWED {op:?} {s:?} as {p:?}, outside every live grant"
                        );
                        if let Some(t) = &target {
                            assert_eq!(
                                key(p, true),
                                key(t, true),
                                "grant check and OS disagree on where {s:?} lands"
                            );
                        }
                    }
                }
            }
        }
    }
    eprintln!("full_access={full_access} bases={bases} {c:?}");
    assert_eq!(c.total, bases * 4);
    assert!(c.known >= MIN_KNOWN, "{c:?}");
    assert!(c.deny_hits >= MIN_DENY, "{c:?}");
    assert!(c.outside_hits >= MIN_OUTSIDE, "{c:?}");
    assert!(c.dead_hits >= MIN_DEAD, "{c:?}");
    assert!(c.allowed >= MIN_ALLOWED, "{c:?}");
    assert!(c.allowed_write >= MIN_ALLOWED_WRITE, "{c:?}");
    c
}

#[test]
fn folder_grants_never_allow_outside_a_live_grant_or_inside_the_deny_list() {
    run(false, 0x5EED_6A47_F01D_2026);
}

#[test]
fn full_access_reads_never_unlock_writes_or_the_deny_list() {
    run(true, 0x5EED_FA11_ACCE_5524);
}
