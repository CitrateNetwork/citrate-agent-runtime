//! HUP-S2.1 red-green tests for folder grants: descendants only, read and
//! write separate, symlinks resolved before the check (including the
//! `link/..` shape a lexical-first check gets wrong), the deny list winning
//! over every grant, expiry at use time, immediate revocation, and the
//! read-only 24 h full-access grant.

#![cfg(unix)]

use citrate_agent_grants::{
    Access, Decision, DenialReason, FolderGrants, GrantError, GrantKind, GrantRequest, GrantScope,
    GrantStatus, Op, FULL_ACCESS_MAX_TTL_SECS,
};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const T0: u64 = 1_790_000_000;
const MEMBER: &str = "0x00000000000000000000000000000000000000aa";

struct Fx {
    _tmp: TempDir,
    home: PathBuf,
    proj: PathBuf,
    other: PathBuf,
}

fn fixture() -> Fx {
    let tmp = TempDir::new().expect("tempdir");
    let base = std::fs::canonicalize(tmp.path()).expect("canon");
    let home = base.join("home");
    let proj = home.join("work").join("proj");
    let other = home.join("other");
    for d in [
        proj.join("src"),
        proj.join("docs"),
        other.clone(),
        home.join(".ssh"),
        home.join("work").join("proj-secrets"),
    ] {
        std::fs::create_dir_all(&d).expect("mkdir");
    }
    std::fs::write(proj.join("src").join("main.rs"), b"fn main() {}").expect("write");
    std::fs::write(proj.join(".env"), b"K=V").expect("write");
    std::fs::write(other.join(".env"), b"K=V").expect("write");
    std::fs::write(other.join("notes.txt"), b"n").expect("write");
    std::fs::write(home.join(".ssh").join("id_ed25519"), b"k").expect("write");
    Fx {
        _tmp: tmp,
        home,
        proj,
        other,
    }
}

fn grants(fx: &Fx) -> FolderGrants {
    FolderGrants::new(&fx.home, &fx.proj)
}

fn folder(root: &Path, access: Access) -> GrantRequest {
    GrantRequest::folder(root, access, MEMBER, "work on the project")
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

fn allowed(g: &FolderGrants, path: &str, op: Op, now: u64) -> PathBuf {
    match g.check(path, op, now) {
        Decision::Allowed { canonical, .. } => canonical.into_path_buf(),
        Decision::Denied { reason } => {
            panic!("{path:?} {op:?} DENIED ({reason}); expected allowed")
        }
    }
}

fn denied(g: &FolderGrants, path: &str, op: Op, now: u64) -> DenialReason {
    match g.check(path, op, now) {
        Decision::Allowed { canonical, .. } => panic!(
            "{path:?} {op:?} ALLOWED as {:?}; expected denied",
            canonical.as_path()
        ),
        Decision::Denied { reason } => reason,
    }
}

// ------------------------------------------------------------ no grant at all

#[test]
fn nothing_is_allowed_without_a_grant() {
    let fx = fixture();
    let g = grants(&fx);
    let r = denied(&g, &s(&fx.proj.join("src/main.rs")), Op::Read, T0);
    assert!(matches!(r, DenialReason::NoGrant { .. }), "{r:?}");
}

// ------------------------------------------------------ descendants, not parents

#[test]
fn a_read_grant_covers_the_folder_and_its_descendants_only() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj, Access::Read), T0).expect("grant");

    allowed(&g, &s(&fx.proj), Op::Read, T0);
    allowed(&g, &s(&fx.proj.join("src/main.rs")), Op::Read, T0);
    allowed(&g, "src/main.rs", Op::Read, T0); // relative to cwd = proj
    allowed(&g, &s(&fx.proj.join("src/new.rs")), Op::Read, T0); // not yet created

    // Parents and siblings are outside.
    for p in [
        fx.proj.join(".."),
        fx.home.clone(),
        fx.other.join("notes.txt"),
        fx.proj.join("src/../../proj-secrets"),
        fx.home.join("work/proj-secrets"), // shares a string prefix, not a component
    ] {
        let r = denied(&g, &s(&p), Op::Read, T0);
        assert!(matches!(r, DenialReason::NoGrant { .. }), "{p:?}: {r:?}");
    }
}

#[test]
fn a_shallow_grant_covers_direct_children_only() {
    let fx = fixture();
    let mut g = grants(&fx);
    let req = folder(&fx.proj, Access::Read).with_scope(GrantScope::Shallow);
    g.grant(req, T0).expect("grant");
    allowed(&g, &s(&fx.proj), Op::Read, T0);
    allowed(&g, &s(&fx.proj.join("src")), Op::Read, T0);
    denied(&g, &s(&fx.proj.join("src/main.rs")), Op::Read, T0);
}

// --------------------------------------------------------- read and write apart

#[test]
fn read_does_not_imply_write_and_write_does_not_imply_read() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj.join("src"), Access::Read), T0)
        .expect("grant");
    g.grant(folder(&fx.proj.join("docs"), Access::Write), T0)
        .expect("grant");

    allowed(&g, &s(&fx.proj.join("src/main.rs")), Op::Read, T0);
    denied(&g, &s(&fx.proj.join("src/main.rs")), Op::Write, T0);

    allowed(&g, &s(&fx.proj.join("docs/new.md")), Op::Write, T0);
    denied(&g, &s(&fx.proj.join("docs/new.md")), Op::Read, T0);
}

// ---------------------------------------------------------------- symlinks

#[test]
fn a_symlink_inside_a_grant_is_judged_by_where_it_lands() {
    let fx = fixture();
    symlink(&fx.other, fx.proj.join("out")).expect("symlink");
    symlink(fx.proj.join("src"), fx.other.join("in")).expect("symlink");
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj, Access::Write), T0).expect("grant");

    // A link out of the grant is outside the grant.
    denied(&g, &s(&fx.proj.join("out/notes.txt")), Op::Write, T0);
    denied(&g, &s(&fx.proj.join("out/new.txt")), Op::Write, T0);
    // A link from outside into the grant lands inside it.
    let landed = allowed(&g, &s(&fx.other.join("in/main.rs")), Op::Write, T0);
    assert_eq!(landed, fx.proj.join("src/main.rs"));
}

#[test]
fn dotdot_after_a_symlink_is_the_parent_of_the_target_not_of_the_link() {
    // `proj/out/..` is `home` (the parent of `other`), not `proj`. A check
    // that pops `..` lexically before resolving would call it `proj` and
    // allow `proj/out/../other/notes.txt` as `proj/other/notes.txt`.
    let fx = fixture();
    symlink(&fx.other, fx.proj.join("out")).expect("symlink");
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj, Access::Read), T0).expect("grant");
    denied(
        &g,
        &s(&fx.proj.join("out/../other/notes.txt")),
        Op::Read,
        T0,
    );
    denied(&g, "out/../other/notes.txt", Op::Read, T0);
}

#[test]
fn a_dangling_symlink_is_followed_to_its_target() {
    let fx = fixture();
    symlink(fx.other.join("created-later.txt"), fx.proj.join("dangle")).expect("symlink");
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj, Access::Write), T0).expect("grant");
    denied(&g, &s(&fx.proj.join("dangle")), Op::Write, T0);
}

#[test]
fn a_granted_root_swapped_for_a_symlink_later_grants_nothing_new() {
    let fx = fixture();
    let mut g = grants(&fx);
    let docs = fx.proj.join("docs");
    g.grant(folder(&docs, Access::Read), T0).expect("grant");
    std::fs::remove_dir(&docs).expect("rmdir");
    symlink(&fx.other, &docs).expect("symlink");
    denied(&g, &s(&docs.join("notes.txt")), Op::Read, T0);
}

#[test]
fn case_variants_resolve_to_the_on_disk_spelling_where_the_filesystem_folds_case() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj, Access::Read), T0).expect("grant");
    let upper = fx.proj.join("SRC/MAIN.RS");
    match g.check(s(&upper), Op::Read, T0) {
        // Case-insensitive volume (APFS default): the same file, reported
        // with its real spelling.
        Decision::Allowed { canonical, .. } => {
            assert_eq!(canonical.as_path(), fx.proj.join("src/main.rs"))
        }
        // Case-sensitive volume: a different (absent) name under the grant.
        // Allowed as written would also be fine; denied must not happen
        // for a reason other than the grant.
        Decision::Denied { reason } => panic!("unexpected denial {reason:?}"),
    }
}

// ----------------------------------------------------------- deny list wins

#[test]
fn the_deny_list_wins_over_a_grant_that_contains_it() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(folder(&fx.home, Access::Write), T0).expect("grant");
    for p in ["~/.ssh/id_ed25519", "~/.ssh/new_key", "~/.SSH/id_ed25519"] {
        let r = denied(&g, p, Op::Read, T0);
        assert!(matches!(r, DenialReason::DenyList(_)), "{p}: {r:?}");
        denied(&g, p, Op::Write, T0);
    }
    // And through a symlink planted inside the grant.
    symlink(fx.home.join(".ssh"), fx.proj.join("keys")).expect("symlink");
    let r = denied(&g, &s(&fx.proj.join("keys/id_ed25519")), Op::Read, T0);
    assert!(matches!(r, DenialReason::DenyList(_)), "{r:?}");
}

#[test]
fn a_grant_cannot_be_rooted_in_a_denied_location() {
    let fx = fixture();
    let mut g = grants(&fx);
    let e = g
        .grant(folder(&fx.home.join(".ssh"), Access::Read), T0)
        .expect_err("must refuse");
    assert!(matches!(e, GrantError::RootDenied(_)), "{e:?}");
}

#[test]
fn dotenv_is_readable_inside_a_folder_grant_but_not_under_full_access() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj, Access::Read), T0).expect("grant");
    g.grant(
        GrantRequest::full_access(&fx.home, 3600, MEMBER, "find my notes"),
        T0,
    )
    .expect("grant");
    allowed(&g, &s(&fx.proj.join(".env")), Op::Read, T0);
    allowed(&g, &s(&fx.other.join("notes.txt")), Op::Read, T0);
    let r = denied(&g, &s(&fx.other.join(".env")), Op::Read, T0);
    assert!(matches!(r, DenialReason::DenyList(_)), "{r:?}");
}

#[test]
fn a_write_only_grant_does_not_unlock_dotenv_for_reading() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj, Access::Write), T0).expect("grant");
    denied(&g, &s(&fx.proj.join(".env")), Op::Read, T0);
}

// --------------------------------------------------------------- expiry

#[test]
fn expiry_is_checked_at_use_time() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(folder(&fx.proj, Access::Read).with_ttl_secs(60), T0)
        .expect("grant");
    let p = s(&fx.proj.join("src/main.rs"));
    allowed(&g, &p, Op::Read, T0);
    allowed(&g, &p, Op::Read, T0 + 59);
    let r = denied(&g, &p, Op::Read, T0 + 60);
    assert!(matches!(r, DenialReason::NoGrant { .. }), "{r:?}");
    denied(&g, &p, Op::Read, T0 + 10_000);
}

#[test]
fn a_zero_ttl_is_refused() {
    let fx = fixture();
    let mut g = grants(&fx);
    let e = g
        .grant(folder(&fx.proj, Access::Read).with_ttl_secs(0), T0)
        .expect_err("refuse");
    assert!(matches!(e, GrantError::BadTtl { .. }), "{e:?}");
}

// --------------------------------------------------------------- revocation

#[test]
fn revocation_is_immediate_and_final() {
    let fx = fixture();
    let mut g = grants(&fx);
    let id = g.grant(folder(&fx.proj, Access::Write), T0).expect("grant");
    let p = s(&fx.proj.join("src/main.rs"));
    allowed(&g, &p, Op::Write, T0);
    g.revoke(&id, T0 + 1).expect("revoke");
    denied(&g, &p, Op::Write, T0 + 1);
    assert!(matches!(
        g.revoke(&id, T0 + 2),
        Err(GrantError::AlreadyRevoked(_))
    ));
    assert!(matches!(
        g.revoke("g-999", T0 + 2),
        Err(GrantError::UnknownGrant(_))
    ));
}

#[test]
fn revoking_one_grant_leaves_the_others() {
    let fx = fixture();
    let mut g = grants(&fx);
    let a = g.grant(folder(&fx.proj, Access::Read), T0).expect("grant");
    g.grant(folder(&fx.proj.join("src"), Access::Read), T0)
        .expect("grant");
    g.revoke(&a, T0).expect("revoke");
    allowed(&g, &s(&fx.proj.join("src/main.rs")), Op::Read, T0);
    denied(&g, &s(&fx.proj.join("docs")), Op::Read, T0);
}

// ------------------------------------------------------------- full access

#[test]
fn full_access_is_read_only() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(
        GrantRequest::full_access(&fx.home, 3600, MEMBER, "look around"),
        T0,
    )
    .expect("grant");
    allowed(&g, &s(&fx.other.join("notes.txt")), Op::Read, T0);
    let r = denied(&g, &s(&fx.other.join("notes.txt")), Op::Write, T0);
    assert!(matches!(r, DenialReason::NoGrant { .. }), "{r:?}");
}

#[test]
fn full_access_cannot_be_requested_for_writing() {
    let fx = fixture();
    let mut g = grants(&fx);
    let req = GrantRequest::full_access(&fx.home, 3600, MEMBER, "x").with_access(Access::Write);
    let e = g.grant(req, T0).expect_err("refuse");
    assert!(matches!(e, GrantError::FullAccessIsReadOnly), "{e:?}");
}

#[test]
fn full_access_expires_within_24_hours() {
    let fx = fixture();
    let mut g = grants(&fx);
    assert_eq!(FULL_ACCESS_MAX_TTL_SECS, 24 * 60 * 60);
    let e = g
        .grant(
            GrantRequest::full_access(&fx.home, FULL_ACCESS_MAX_TTL_SECS + 1, MEMBER, "x"),
            T0,
        )
        .expect_err("refuse");
    assert!(matches!(e, GrantError::BadTtl { .. }), "{e:?}");
    // No TTL at all is also refused for full access.
    let e = g
        .grant(
            GrantRequest::full_access(&fx.home, FULL_ACCESS_MAX_TTL_SECS, MEMBER, "x")
                .without_ttl(),
            T0,
        )
        .expect_err("refuse");
    assert!(matches!(e, GrantError::BadTtl { .. }), "{e:?}");

    g.grant(
        GrantRequest::full_access(&fx.home, FULL_ACCESS_MAX_TTL_SECS, MEMBER, "x"),
        T0,
    )
    .expect("grant");
    let p = s(&fx.other.join("notes.txt"));
    allowed(&g, &p, Op::Read, T0 + FULL_ACCESS_MAX_TTL_SECS - 1);
    denied(&g, &p, Op::Read, T0 + FULL_ACCESS_MAX_TTL_SECS);
}

// ------------------------------------------------------ request validation

#[test]
fn a_grant_needs_an_existing_folder_a_member_and_a_reason() {
    let fx = fixture();
    let mut g = grants(&fx);
    let e = g
        .grant(folder(&fx.proj.join("missing"), Access::Read), T0)
        .expect_err("missing");
    assert!(matches!(e, GrantError::RootNotADirectory(_)), "{e:?}");
    let e = g
        .grant(folder(&fx.proj.join("src/main.rs"), Access::Read), T0)
        .expect_err("file");
    assert!(matches!(e, GrantError::RootNotADirectory(_)), "{e:?}");
    let e = g
        .grant(
            GrantRequest::folder(&fx.proj, Access::Read, "  ", "reason"),
            T0,
        )
        .expect_err("member");
    assert!(matches!(e, GrantError::MissingGrantedBy), "{e:?}");
    let e = g
        .grant(GrantRequest::folder(&fx.proj, Access::Read, MEMBER, ""), T0)
        .expect_err("reason");
    assert!(matches!(e, GrantError::MissingReason), "{e:?}");
}

#[test]
fn write_access_to_the_filesystem_root_is_refused() {
    let fx = fixture();
    let mut g = grants(&fx);
    let e = g
        .grant(folder(Path::new("/"), Access::Write), T0)
        .expect_err("refuse");
    assert!(matches!(e, GrantError::WriteOnFilesystemRoot), "{e:?}");
}

#[test]
fn the_stored_root_is_canonical() {
    let fx = fixture();
    symlink(&fx.proj, fx.home.join("p")).expect("symlink");
    let mut g = grants(&fx);
    let id = g
        .grant(folder(&fx.home.join("p/./src/.."), Access::Read), T0)
        .expect("grant");
    let views = g.list(T0);
    let v = views.iter().find(|v| v.grant.id == id).expect("listed");
    assert_eq!(v.grant.root, fx.proj);
    assert_eq!(v.grant.kind, GrantKind::Folder);
}

// --------------------------------------------------------------- listing

#[test]
fn list_reports_status_and_the_full_access_countdown() {
    let fx = fixture();
    let mut g = grants(&fx);
    let a = g.grant(folder(&fx.proj, Access::Read), T0).expect("grant");
    let b = g
        .grant(GrantRequest::full_access(&fx.home, 3600, MEMBER, "x"), T0)
        .expect("grant");
    let c = g
        .grant(folder(&fx.other, Access::Write).with_ttl_secs(10), T0)
        .expect("grant");
    g.revoke(&a, T0 + 5).expect("revoke");

    let views = g.list(T0 + 100);
    let get = |id: &str| views.iter().find(|v| v.grant.id == id).expect("listed");
    assert_eq!(get(&a).status, GrantStatus::Revoked);
    assert_eq!(get(&b).status, GrantStatus::Active);
    assert_eq!(get(&b).remaining_secs, Some(3500));
    assert_eq!(get(&b).grant.kind, GrantKind::FullAccess);
    assert_eq!(get(&c).status, GrantStatus::Expired);
    assert_eq!(get(&c).remaining_secs, Some(0));
    assert_eq!(get(&b).grant.granted_by, MEMBER);
    assert_eq!(get(&b).grant.reason, "x");
}

#[test]
fn the_most_specific_grant_is_reported() {
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(GrantRequest::full_access(&fx.home, 3600, MEMBER, "x"), T0)
        .expect("grant");
    let inner = g
        .grant(folder(&fx.proj.join("src"), Access::Read), T0)
        .expect("grant");
    match g.check(s(&fx.proj.join("src/main.rs")), Op::Read, T0) {
        Decision::Allowed { grant_id, .. } => assert_eq!(grant_id, inner),
        d => panic!("{d:?}"),
    }
}

#[test]
fn a_shallow_folder_grant_does_not_unlock_dotenv_below_it_for_full_access() {
    // Found by TLC (FolderGrant, DotEnvOnlyViaFolderGrant): a shallow grant
    // over home made home a `.env` project root even though it does not
    // cover `home/other/.env`, and full access then covered the file.
    let fx = fixture();
    let mut g = grants(&fx);
    g.grant(
        folder(&fx.home, Access::Read).with_scope(GrantScope::Shallow),
        T0,
    )
    .expect("grant");
    g.grant(GrantRequest::full_access(&fx.home, 3600, MEMBER, "x"), T0)
        .expect("grant");
    let r = denied(&g, &s(&fx.other.join(".env")), Op::Read, T0);
    assert!(matches!(r, DenialReason::DenyList(_)), "{r:?}");
    allowed(&g, &s(&fx.other.join("notes.txt")), Op::Read, T0);
}
