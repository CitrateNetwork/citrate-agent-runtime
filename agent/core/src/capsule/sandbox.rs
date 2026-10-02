//! Capsule sandbox plan (HUP-S2.5, US-2.5 AC1).
//!
//! A capsule has no ambient filesystem or network. What it may touch is
//! decided per instantiation, from two inputs:
//!
//! * the signed manifest, which declares the ceiling
//!   (`[capability].filesystem` guest mount points with read / write / both,
//!   `[capability].network` and its `network_allow` socket list), and
//! * the member's live folder grants ([`citrate_agent_grants::FolderGrants`]),
//!   which decide which host folder, if any, backs each declared mount.
//!
//! [`SandboxPlan`] is the result. The wasmtime host context turns it into a
//! `WasiCtx` (see [`crate::capsule::wasm::HostCtx::apply_sandbox`]): one WASI
//! preopen per granted mount and a socket check that admits only the
//! allowlisted remote addresses. Inside a preopen, wasmtime-wasi resolves
//! every path relative to the preopened directory handle and refuses `..`
//! and symlinks that leave it, so a capsule cannot read outside its mount.
//!
//! ## Rules
//!
//! * **Ceiling, not grant.** A declared mount with no [`FsMount`] binding
//!   gets no preopen. A binding for an undeclared mount is refused.
//! * **Folder grants only, whole subtree.** A preopen exposes the whole
//!   folder below it, so only a live [`GrantKind::Folder`] grant with
//!   [`GrantScope::Subtree`] can back one. The time-boxed full-access grant
//!   and shallow grants are refused for capsules.
//! * **Write implies read here.** WASI preopens have no write-only mode, so
//!   a `write` or `both` mount needs a live read grant AND a live write grant
//!   covering the folder. Read never silently becomes write.
//! * **The deny list still wins.** Before a folder is preopened, every entry
//!   below it is checked with the same [`FolderGrants::check`] the file
//!   tools use. Any deny-listed entry (a credential store, a keychain, a
//!   wallet keystore, ...) refuses the whole mount, since the WASI layer
//!   cannot consult the deny list per open. The scan is bounded by
//!   [`MAX_MOUNT_SCAN_ENTRIES`]; a larger folder is refused, not
//!   partially checked.
//! * **Time is checked at use.** The plan is resolved for every
//!   instantiation (every capsule call), so a revoked or expired grant stops
//!   applying on the next call.
//! * **Network.** `none` and `broker-only` get no direct socket at all.
//!   `egress-allowed` may connect or send only to the exact `network_allow`
//!   addresses, and only to public internet addresses (loopback, private,
//!   link-local, shared and reserved ranges are refused at load and again
//!   per socket use); binds are limited to the implicit ephemeral bind a connect
//!   performs, listening and accepting are refused, and name lookup is off.
//!
//! ## Status
//!
//! Enforced on every `Capsule::instantiate*` path and in
//! `CapsuleDispatch::call_raw`. Without a [`SandboxProvider`] (the default
//! today), a capsule gets no preopens at all. Core does not yet pass the
//! member's grants to the agent sidecar, so no shipped path mounts a folder
//! yet; that wiring belongs with the Grants UI work package.

use crate::capsule::filesystem::{self, FilesystemAccess};
use crate::capsule::manifest::{Manifest, NetworkPolicy};
use crate::error::AgentError;
use citrate_agent_grants::{Decision, DenialReason, FolderGrants, GrantKind, GrantScope, Op};
use citrate_agent_guard::net::is_public_ip;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use wasmtime_wasi::sockets::SocketAddrUse;

/// Most entries scanned below one mount before it is refused. Placeholder
/// value, pending owner sign-off: large enough for a project folder, small
/// enough that a capsule call never stalls on a home-sized tree.
pub const MAX_MOUNT_SCAN_ENTRIES: usize = 10_000;

/// Access a preopen grants inside the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountPerms {
    ReadOnly,
    ReadWrite,
}

/// One WASI preopen: host folder (canonical) exposed at a guest path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preopen {
    pub host: PathBuf,
    pub guest: String,
    pub perms: MountPerms,
    /// The grants that authorized it (one per required operation).
    pub grant_ids: Vec<String>,
}

/// The socket policy for one instantiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPlan {
    /// No address is reachable (`none`, `broker-only`).
    DenyAll,
    /// Only these exact remote addresses (`egress-allowed`).
    Allow(Vec<SocketAddr>),
}

/// A host folder to back a declared guest mount point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsMount {
    /// Must equal a `[capability].filesystem` path of the capsule.
    pub guest: String,
    /// The member's folder; must be covered by live folder grants.
    pub host: PathBuf,
}

impl FsMount {
    pub fn new(guest: impl Into<String>, host: impl Into<PathBuf>) -> Self {
        Self {
            guest: guest.into(),
            host: host.into(),
        }
    }
}

/// What one capsule instantiation may touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    preopens: Vec<Preopen>,
    network: NetworkPlan,
}

impl SandboxPlan {
    /// Nothing: no preopens, no reachable address.
    pub fn deny_all() -> Self {
        Self {
            preopens: Vec::new(),
            network: NetworkPlan::DenyAll,
        }
    }

    /// The plan when no member grants are supplied: no preopens, and the
    /// manifest's signed socket allowlist.
    pub fn without_grants(manifest: &Manifest) -> Result<Self, AgentError> {
        Ok(Self {
            preopens: Vec::new(),
            network: network_plan(manifest)?,
        })
    }

    /// Resolve `mounts` for `manifest` against the member's `grants` at
    /// `now` (unix seconds). Any mount that is not fully authorized fails
    /// the whole plan with the reason, so the capsule never runs with less
    /// (or more) than the caller asked for.
    pub fn resolve(
        manifest: &Manifest,
        mounts: &[FsMount],
        grants: &FolderGrants,
        now: u64,
    ) -> Result<Self, AgentError> {
        Self::resolve_with_cap(manifest, mounts, grants, now, MAX_MOUNT_SCAN_ENTRIES)
    }

    fn resolve_with_cap(
        manifest: &Manifest,
        mounts: &[FsMount],
        grants: &FolderGrants,
        now: u64,
        scan_cap: usize,
    ) -> Result<Self, AgentError> {
        let name = &manifest.capsule.name;
        let declared = filesystem::parse_all(&manifest.capability.filesystem)?;
        let mut preopens: Vec<Preopen> = Vec::new();
        for mount in mounts {
            let refuse = |why: String| {
                AgentError::Capsule(format!(
                    "capsule {name:?} cannot mount {} at {:?}: {why}",
                    mount.host.display(),
                    mount.guest
                ))
            };
            let entry = declared
                .iter()
                .find(|e| e.path == Path::new(&mount.guest))
                .ok_or_else(|| {
                    refuse("the manifest declares no [capability].filesystem entry there".into())
                })?;
            if preopens.iter().any(|p| p.guest == mount.guest) {
                return Err(refuse("that guest path is already mounted".into()));
            }
            let (ops, perms): (&[Op], MountPerms) = match entry.access {
                FilesystemAccess::Read => (&[Op::Read], MountPerms::ReadOnly),
                // WASI preopens cannot be write-only: a writable mount is
                // also readable, so it needs both grants.
                FilesystemAccess::Write | FilesystemAccess::Both => {
                    (&[Op::Read, Op::Write], MountPerms::ReadWrite)
                }
            };
            let mut host: Option<PathBuf> = None;
            let mut grant_ids = Vec::new();
            for op in ops {
                let (canonical, grant_id) = match grants.check(&mount.host, *op, now) {
                    Decision::Allowed {
                        canonical,
                        grant_id,
                    } => (canonical.into_path_buf(), grant_id),
                    Decision::Denied { reason } => {
                        return Err(refuse(format!("{op:?} not granted: {reason}")))
                    }
                };
                let grant = grants
                    .state()
                    .grants
                    .iter()
                    .find(|g| g.id == grant_id)
                    .ok_or_else(|| refuse(format!("grant {grant_id} vanished during the check")))?;
                if grant.kind != GrantKind::Folder {
                    return Err(refuse(
                        "only a folder grant can back a capsule mount, not full access".into(),
                    ));
                }
                if grant.scope != GrantScope::Subtree {
                    return Err(refuse(
                        "a capsule mount exposes the whole folder, so it needs a whole-folder \
                         (subtree) grant, not a shallow one"
                            .into(),
                    ));
                }
                match &host {
                    None => host = Some(canonical),
                    Some(h) if *h == canonical => {}
                    Some(_) => {
                        return Err(refuse(
                            "the folder resolved differently between checks".into(),
                        ))
                    }
                }
                grant_ids.push(grant_id);
            }
            let host = host.ok_or_else(|| refuse("no operation was checked".into()))?;
            if !host.is_dir() {
                return Err(refuse("it is not a folder".into()));
            }
            scan_mount(&host, ops, grants, now, scan_cap).map_err(refuse)?;
            preopens.push(Preopen {
                host,
                guest: mount.guest.clone(),
                perms,
                grant_ids,
            });
        }
        Ok(Self {
            preopens,
            network: network_plan(manifest)?,
        })
    }

    pub fn preopens(&self) -> &[Preopen] {
        &self.preopens
    }

    pub fn network(&self) -> &NetworkPlan {
        &self.network
    }

    /// The socket decision for one use of `addr`. See [`socket_permitted`].
    pub fn permits_socket(&self, addr: SocketAddr, use_: SocketAddrUse) -> bool {
        match &self.network {
            NetworkPlan::DenyAll => false,
            NetworkPlan::Allow(list) => socket_permitted(list, addr, use_),
        }
    }
}

/// Walk `root` (never following symlinks) and require every entry to pass
/// the same grant check the file tools use, for every operation the mount
/// allows. A symlink whose target is merely outside the grant is tolerated
/// (WASI refuses to follow it out of the preopen); a deny-listed target is
/// not. A regular file with another hard link refuses the mount (Unix).
fn scan_mount(
    root: &Path,
    ops: &[Op],
    grants: &FolderGrants,
    now: u64,
    cap: usize,
) -> Result<(), String> {
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
            seen += 1;
            if seen > cap {
                return Err(format!(
                    "the folder has more than {cap} entries, too many to check for a capsule \
                     mount; grant a smaller folder"
                ));
            }
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
            for op in ops {
                match grants.check(&path, *op, now) {
                    Decision::Allowed { .. } => {}
                    Decision::Denied {
                        reason: DenialReason::NoGrant { .. } | DenialReason::Unresolvable(_),
                    } if file_type.is_symlink() => {}
                    Decision::Denied { reason } => {
                        return Err(format!("{} is off limits: {reason}", path.display()))
                    }
                }
            }
            // A hard link can name a file kept outside the grant (the deny list is
            // path-based and WASI opens the inode), so a folder holding one is not mounted.
            #[cfg(unix)]
            if file_type.is_file() {
                use std::os::unix::fs::MetadataExt;
                let meta = std::fs::symlink_metadata(&path)
                    .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
                if meta.nlink() > 1 {
                    return Err(format!(
                        "{} has another hard link, so it may be a file kept elsewhere; \
                         grant a folder without hard-linked files",
                        path.display()
                    ));
                }
            }
            if file_type.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

fn network_plan(manifest: &Manifest) -> Result<NetworkPlan, AgentError> {
    Ok(match manifest.capability.network {
        NetworkPolicy::None | NetworkPolicy::BrokerOnly => NetworkPlan::DenyAll,
        NetworkPolicy::EgressAllowed => {
            NetworkPlan::Allow(parse_network_allow(&manifest.capability.network_allow)?)
        }
    })
}

/// Parse `[capability].network_allow`: each entry an exact remote
/// `ip:port` (`[v6]:port`) on the public internet
/// ([`citrate_agent_guard::net::is_public_ip`]), not port 0.
pub fn parse_network_allow(entries: &[String]) -> Result<Vec<SocketAddr>, AgentError> {
    entries
        .iter()
        .map(|s| {
            let addr: SocketAddr = s.parse().map_err(|_| {
                AgentError::Capsule(format!(
                    "[capability].network_allow entry {s:?} must be an exact ip:port \
                     (host names are not resolved inside capsules)"
                ))
            })?;
            if addr.ip().is_unspecified() || addr.port() == 0 {
                return Err(AgentError::Capsule(format!(
                    "[capability].network_allow entry {s:?} must name one remote address and port"
                )));
            }
            // A manifest alone never reaches this machine, the local network or a metadata
            // service: only public addresses can be allowlisted.
            if !is_public_ip(addr.ip()) {
                return Err(AgentError::Capsule(format!(
                    "[capability].network_allow entry {s:?} is not a public internet address; \
                     capsules may not reach loopback, private, link-local or reserved addresses"
                )));
            }
            Ok(addr)
        })
        .collect()
}

/// The socket rule for an `egress-allowed` capsule: connect / send /
/// receive only with an allowlisted remote address; bind only the implicit
/// ephemeral bind a connect or send performs (unspecified address, port 0);
/// never listen or accept.
pub fn socket_permitted(allow: &[SocketAddr], addr: SocketAddr, use_: SocketAddrUse) -> bool {
    match use_ {
        SocketAddrUse::TcpConnect | SocketAddrUse::UdpSend | SocketAddrUse::UdpReceive => {
            is_public_ip(addr.ip()) && allow.contains(&addr)
        }
        SocketAddrUse::TcpBind | SocketAddrUse::UdpBind => {
            addr.ip().is_unspecified() && addr.port() == 0
        }
        _ => false,
    }
}

/// Supplies the sandbox plan for each capsule call. Read at call time so
/// grant changes apply on the next call.
pub trait SandboxProvider: Send + Sync {
    fn plan_for(&self, manifest: &Manifest) -> Result<SandboxPlan, AgentError>;
}

/// A [`SandboxProvider`] over the member's folder grants and per-capsule
/// mount bindings.
pub struct GrantsSandbox {
    grants: Arc<RwLock<FolderGrants>>,
    mounts: HashMap<String, Vec<FsMount>>,
}

impl GrantsSandbox {
    pub fn new(grants: Arc<RwLock<FolderGrants>>) -> Self {
        Self {
            grants,
            mounts: HashMap::new(),
        }
    }

    /// Bind `mount` for the capsule named `capsule`.
    pub fn mount(mut self, capsule: impl Into<String>, mount: FsMount) -> Self {
        self.mounts.entry(capsule.into()).or_default().push(mount);
        self
    }

    fn plan_at(&self, manifest: &Manifest, now: u64) -> Result<SandboxPlan, AgentError> {
        let mounts = self
            .mounts
            .get(&manifest.capsule.name)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let grants = self
            .grants
            .read()
            .map_err(|_| AgentError::Capsule("folder grants are unavailable".into()))?;
        SandboxPlan::resolve(manifest, mounts, &grants, now)
    }
}

impl SandboxProvider for GrantsSandbox {
    fn plan_for(&self, manifest: &Manifest) -> Result<SandboxPlan, AgentError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AgentError::Capsule("system clock is before 1970".into()))?
            .as_secs();
        self.plan_at(manifest, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::manifest::Manifest;
    use crate::capsule::wasm::HostCtx;
    use citrate_agent_grants::{Access, GrantRequest};
    use wasmtime_wasi::filesystem::WasiFilesystemView;
    use wasmtime_wasi::p2::bindings::filesystem::preopens::Host as _;
    use wasmtime_wasi::p2::bindings::filesystem::types::ErrorCode;
    use wasmtime_wasi::p2::bindings::sync::filesystem::types::{
        DescriptorFlags, HostDescriptor, OpenFlags, PathFlags,
    };

    const NOW: u64 = 1_800_000_000;

    fn manifest(network: &str, filesystem: &[&str]) -> Manifest {
        let fs = filesystem
            .iter()
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        Manifest::parse(&format!(
            r#"
[capsule]
name = "sandbox-test"
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
        .expect("test manifest parses")
    }

    /// A member home, a granted project folder with one file, and a secret
    /// file beside it (outside the grant).
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
                GrantRequest::folder(&w.project, *a, "0xmember", "capsule test"),
                NOW - 10,
            )
            .expect("grant");
        }
        g
    }

    fn sandboxed_host(plan: &SandboxPlan) -> HostCtx {
        let mut host = HostCtx::empty();
        host.apply_sandbox(plan).expect("sandbox applies");
        host
    }

    // ── plan resolution ──────────────────────────────────────────

    #[test]
    fn without_grants_a_declared_mount_gets_no_preopen() {
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let plan = SandboxPlan::without_grants(&m).expect("plan");
        assert!(plan.preopens().is_empty());
        assert_eq!(plan.network(), &NetworkPlan::DenyAll);
    }

    #[test]
    fn a_live_read_grant_backs_a_read_only_preopen() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[Access::Read]);
        let plan = SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW)
            .expect("mount allowed");
        assert_eq!(plan.preopens().len(), 1);
        let p = &plan.preopens()[0];
        assert_eq!(p.host, w.project);
        assert_eq!(p.guest, "/work");
        assert_eq!(p.perms, MountPerms::ReadOnly);
        assert_eq!(p.grant_ids, vec!["g-1".to_string()]);
    }

    #[test]
    fn a_mount_without_a_grant_is_refused_with_the_reason() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[]);
        let err = SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW)
            .expect_err("no grant, no mount");
        let msg = err.to_string();
        assert!(msg.contains("not granted"), "{msg}");
        assert!(msg.contains("sandbox-test"), "{msg}");
    }

    #[test]
    fn a_mount_the_manifest_does_not_declare_is_refused() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[Access::Read]);
        let err = SandboxPlan::resolve(&m, &[FsMount::new("/other", &w.project)], &g, NOW)
            .expect_err("undeclared mount");
        assert!(err.to_string().contains("declares no"), "{err}");
    }

    #[test]
    fn the_same_guest_path_cannot_be_mounted_twice() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[Access::Read]);
        let mounts = [
            FsMount::new("/work", &w.project),
            FsMount::new("/work", &w.project),
        ];
        let err = SandboxPlan::resolve(&m, &mounts, &g, NOW).expect_err("double mount");
        assert!(err.to_string().contains("already mounted"), "{err}");
    }

    #[test]
    fn a_write_mount_needs_both_read_and_write_grants() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["write:/work"]);
        let mount = [FsMount::new("/work", &w.project)];
        let write_only = grants(&w, &[Access::Write]);
        let err = SandboxPlan::resolve(&m, &mount, &write_only, NOW).expect_err("read missing");
        assert!(err.to_string().contains("Read not granted"), "{err}");
        let read_only = grants(&w, &[Access::Read]);
        let err = SandboxPlan::resolve(&m, &mount, &read_only, NOW).expect_err("write missing");
        assert!(err.to_string().contains("Write not granted"), "{err}");
        let both = grants(&w, &[Access::Read, Access::Write]);
        let plan = SandboxPlan::resolve(&m, &mount, &both, NOW).expect("both granted");
        assert_eq!(plan.preopens()[0].perms, MountPerms::ReadWrite);
        assert_eq!(plan.preopens()[0].grant_ids.len(), 2);
    }

    #[test]
    fn full_access_cannot_back_a_capsule_mount() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let mut g = FolderGrants::new(&w.home, &w.home);
        g.grant(
            GrantRequest::full_access(&w.home, 3600, "0xmember", "look around"),
            NOW - 10,
        )
        .expect("full access");
        let err = SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW)
            .expect_err("full access refused");
        assert!(err.to_string().contains("full access"), "{err}");
    }

    #[test]
    fn a_shallow_grant_cannot_back_a_capsule_mount() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let mut g = FolderGrants::new(&w.home, &w.home);
        g.grant(
            GrantRequest::folder(&w.project, Access::Read, "0xmember", "top level")
                .with_scope(GrantScope::Shallow),
            NOW - 10,
        )
        .expect("shallow grant");
        let err = SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW)
            .expect_err("shallow refused");
        assert!(err.to_string().contains("subtree"), "{err}");
    }

    #[test]
    fn an_expired_or_revoked_grant_stops_applying_at_the_next_resolve() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let mount = [FsMount::new("/work", &w.project)];
        let mut g = FolderGrants::new(&w.home, &w.home);
        g.grant(
            GrantRequest::folder(&w.project, Access::Read, "0xmember", "an hour")
                .with_ttl_secs(3600),
            NOW,
        )
        .expect("grant");
        SandboxPlan::resolve(&m, &mount, &g, NOW + 10).expect("live");
        SandboxPlan::resolve(&m, &mount, &g, NOW + 3600).expect_err("expired");
        let mut g = grants(&w, &[Access::Read]);
        g.revoke("g-1", NOW).expect("revoke");
        SandboxPlan::resolve(&m, &mount, &g, NOW + 1).expect_err("revoked");
    }

    #[test]
    fn a_deny_listed_entry_inside_the_folder_refuses_the_mount() {
        let w = world();
        std::fs::create_dir_all(w.project.join(".ssh")).expect("mkdir");
        std::fs::write(w.project.join(".ssh").join("id_ed25519"), b"key").expect("write");
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[Access::Read]);
        let err = SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW)
            .expect_err("deny list wins");
        assert!(err.to_string().contains(".ssh"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_deny_listed_place_refuses_the_mount() {
        let w = world();
        let secret = w.home.join(".gnupg");
        std::fs::create_dir_all(&secret).expect("mkdir");
        std::os::unix::fs::symlink(&secret, w.project.join("keys")).expect("symlink");
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[Access::Read]);
        let err = SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW)
            .expect_err("deny-listed symlink target");
        assert!(err.to_string().contains("off limits"), "{err}");
    }

    /// A hard link inside the folder can name a file kept outside it (the deny list is
    /// path-based, and WASI opens the inode), so a folder holding one is not mounted.
    #[cfg(unix)]
    #[test]
    fn a_hard_linked_file_inside_the_folder_refuses_the_mount() {
        let w = world();
        // `w.outside` is a file in the home folder, outside the grant.
        std::fs::hard_link(&w.outside, w.project.join("linked-private.txt")).expect("link");
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[Access::Read]);
        let err = SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW)
            .expect_err("hard link refuses the mount");
        assert!(err.to_string().contains("hard link"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_an_ordinary_outside_file_is_tolerated() {
        // WASI refuses to follow it out of the preopen (see the host test
        // below), so the mount is still safe to open.
        let w = world();
        std::os::unix::fs::symlink(&w.outside, w.project.join("escape")).expect("symlink");
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[Access::Read]);
        SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW)
            .expect("ordinary outside link tolerated");
    }

    #[test]
    fn a_folder_over_the_scan_cap_is_refused_not_partially_checked() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(&w, &[Access::Read]);
        let err =
            SandboxPlan::resolve_with_cap(&m, &[FsMount::new("/work", &w.project)], &g, NOW, 2)
                .expect_err("over the cap");
        assert!(err.to_string().contains("more than 2 entries"), "{err}");
    }

    #[test]
    fn grants_sandbox_resolves_bound_mounts_per_capsule() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = Arc::new(RwLock::new(grants(&w, &[Access::Read])));
        let provider = GrantsSandbox::new(Arc::clone(&g))
            .mount("sandbox-test", FsMount::new("/work", &w.project));
        assert_eq!(provider.plan_at(&m, NOW).expect("plan").preopens().len(), 1);
        let unbound = GrantsSandbox::new(g);
        assert!(unbound
            .plan_at(&m, NOW)
            .expect("plan")
            .preopens()
            .is_empty());
    }

    // ── network ──────────────────────────────────────────────────

    #[test]
    fn network_plan_follows_the_manifest() {
        let none = manifest(r#"network = "none""#, &[]);
        let broker = manifest(r#"network = "broker-only""#, &[]);
        let egress = manifest(
            "network = \"egress-allowed\"\nnetwork_allow = [\"1.1.1.1:443\"]",
            &[],
        );
        assert_eq!(
            SandboxPlan::without_grants(&none).expect("p").network(),
            &NetworkPlan::DenyAll
        );
        assert_eq!(
            SandboxPlan::without_grants(&broker).expect("p").network(),
            &NetworkPlan::DenyAll
        );
        let allowed: SocketAddr = "1.1.1.1:443".parse().expect("addr");
        assert_eq!(
            SandboxPlan::without_grants(&egress).expect("p").network(),
            &NetworkPlan::Allow(vec![allowed])
        );
    }

    #[test]
    fn socket_rule_admits_only_allowlisted_remotes_and_implicit_binds() {
        let ok: SocketAddr = "1.1.1.1:443".parse().expect("addr");
        let other: SocketAddr = "1.0.0.1:443".parse().expect("addr");
        let other_port: SocketAddr = "1.1.1.1:80".parse().expect("addr");
        let implicit: SocketAddr = "0.0.0.0:0".parse().expect("addr");
        let explicit_bind: SocketAddr = "0.0.0.0:8080".parse().expect("addr");
        let allow = [ok];
        assert!(socket_permitted(&allow, ok, SocketAddrUse::TcpConnect));
        assert!(socket_permitted(&allow, ok, SocketAddrUse::UdpSend));
        assert!(socket_permitted(&allow, ok, SocketAddrUse::UdpReceive));
        assert!(!socket_permitted(&allow, other, SocketAddrUse::TcpConnect));
        assert!(!socket_permitted(
            &allow,
            other_port,
            SocketAddrUse::TcpConnect
        ));
        assert!(!socket_permitted(&allow, other, SocketAddrUse::UdpSend));
        assert!(socket_permitted(&allow, implicit, SocketAddrUse::TcpBind));
        assert!(socket_permitted(&allow, implicit, SocketAddrUse::UdpBind));
        assert!(!socket_permitted(
            &allow,
            explicit_bind,
            SocketAddrUse::TcpBind
        ));
        assert!(!socket_permitted(&allow, ok, SocketAddrUse::TcpBind));
        assert!(!socket_permitted(
            &allow,
            implicit,
            SocketAddrUse::TcpListen
        ));
        assert!(!socket_permitted(&allow, ok, SocketAddrUse::TcpAccept));
        let deny = SandboxPlan::deny_all();
        assert!(!deny.permits_socket(ok, SocketAddrUse::TcpConnect));
        assert!(!deny.permits_socket(implicit, SocketAddrUse::TcpBind));
    }

    /// Even a plan that lists a non-public address (built by hand, not from a manifest) never
    /// lets a capsule reach it.
    #[test]
    fn socket_rule_never_admits_a_non_public_remote() {
        for raw in [
            "127.0.0.1:8545",
            "169.254.169.254:80",
            "10.0.0.5:443",
            "[::1]:443",
        ] {
            let addr: SocketAddr = raw.parse().expect("addr");
            let allow = [addr];
            for use_ in [
                SocketAddrUse::TcpConnect,
                SocketAddrUse::UdpSend,
                SocketAddrUse::UdpReceive,
            ] {
                assert!(!socket_permitted(&allow, addr, use_), "{raw} {use_:?}");
            }
        }
    }

    /// The socket rule is what the WASI host consults: on the real
    /// `apply_sandbox` context an egress capsule cannot connect to an
    /// address outside its allowlist, bind an explicit local address, or
    /// listen. Loopback only; nothing leaves the machine.
    #[test]
    fn the_wasi_socket_layer_enforces_the_allowlist() {
        use wasmtime_wasi::p2::bindings::sockets::instance_network::Host as _;
        use wasmtime_wasi::p2::bindings::sockets::network::{
            ErrorCode as NetErr, IpAddressFamily, IpSocketAddress,
        };
        use wasmtime_wasi::p2::bindings::sockets::tcp_create_socket::Host as _;
        use wasmtime_wasi::p2::bindings::sync::sockets::tcp::HostTcpSocket;
        use wasmtime_wasi::sockets::WasiSocketsView;

        let m = manifest(
            "network = \"egress-allowed\"\nnetwork_allow = [\"1.1.1.1:443\"]",
            &[],
        );
        let mut host = sandboxed_host(&SandboxPlan::without_grants(&m).expect("plan"));
        let code = |e: wasmtime_wasi::p2::SocketError| -> NetErr {
            e.downcast().expect("a socket error code, not a trap")
        };
        let addr = |s: &str| -> IpSocketAddress { s.parse::<SocketAddr>().expect("addr").into() };
        let mut net = host.sockets();

        // Connect to a remote that is not on the allowlist.
        let sock = net
            .create_tcp_socket(IpAddressFamily::Ipv4)
            .expect("tcp is on for an egress capsule");
        let network = net.instance_network().expect("network");
        let s = wasmtime::component::Resource::new_borrow(sock.rep());
        let n = wasmtime::component::Resource::new_borrow(network.rep());
        HostTcpSocket::start_connect(&mut net, s, n, addr("127.0.0.1:1")).expect("start");
        let s = wasmtime::component::Resource::new_borrow(sock.rep());
        let err = HostTcpSocket::finish_connect(&mut net, s).expect_err("not allowlisted");
        assert_eq!(code(err), NetErr::AccessDenied);

        // An explicit bind, and listening, are refused.
        let sock = net.create_tcp_socket(IpAddressFamily::Ipv4).expect("tcp");
        let s = wasmtime::component::Resource::new_borrow(sock.rep());
        let n = wasmtime::component::Resource::new_borrow(network.rep());
        let err = HostTcpSocket::start_bind(&mut net, s, n, addr("127.0.0.1:0"))
            .expect_err("explicit bind");
        assert_eq!(code(err), NetErr::AccessDenied);
        // WASI 0.2 listens only on a bound socket; the ephemeral bind is
        // the one bind the rule admits, and listening on it is refused.
        let sock = net.create_tcp_socket(IpAddressFamily::Ipv4).expect("tcp");
        let s = wasmtime::component::Resource::new_borrow(sock.rep());
        let n = wasmtime::component::Resource::new_borrow(network.rep());
        HostTcpSocket::start_bind(&mut net, s, n, addr("0.0.0.0:0")).expect("ephemeral bind");
        let s = wasmtime::component::Resource::new_borrow(sock.rep());
        HostTcpSocket::finish_bind(&mut net, s).expect("bound");
        let s = wasmtime::component::Resource::new_borrow(sock.rep());
        let err = HostTcpSocket::start_listen(&mut net, s).expect_err("listen");
        assert_eq!(code(err), NetErr::AccessDenied);

        // `none` gets no TCP socket at all.
        let mut host = sandboxed_host(&SandboxPlan::deny_all());
        let mut net = host.sockets();
        let err = net
            .create_tcp_socket(IpAddressFamily::Ipv4)
            .expect_err("no tcp for a none capsule");
        assert_eq!(code(err), NetErr::AccessDenied);
    }

    // ── the WASI host functions a capsule calls ──────────────────

    fn only_preopen(
        host: &mut HostCtx,
    ) -> wasmtime::component::Resource<
        wasmtime_wasi::p2::bindings::sync::filesystem::types::Descriptor,
    > {
        let mut dirs = host
            .filesystem()
            .get_directories()
            .expect("get_directories");
        assert_eq!(dirs.len(), 1, "exactly one preopen");
        let (fd, guest) = dirs.remove(0);
        assert_eq!(guest, "/work");
        fd
    }

    fn open(
        host: &mut HostCtx,
        fd: &wasmtime::component::Resource<
            wasmtime_wasi::p2::bindings::sync::filesystem::types::Descriptor,
        >,
        path: &str,
        flags: DescriptorFlags,
    ) -> Result<(), ErrorCode> {
        let fd = wasmtime::component::Resource::new_borrow(fd.rep());
        let mut fs = host.filesystem();
        match HostDescriptor::open_at(
            &mut fs,
            fd,
            PathFlags::SYMLINK_FOLLOW,
            path.to_string(),
            OpenFlags::empty(),
            flags,
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.downcast().expect("a WASI error code, not a trap")),
        }
    }

    fn read_plan(w: &World) -> SandboxPlan {
        let m = manifest(r#"network = "none""#, &["read:/work"]);
        let g = grants(w, &[Access::Read]);
        SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW).expect("plan")
    }

    #[test]
    fn no_plan_means_no_ambient_filesystem() {
        let mut host = HostCtx::empty();
        let dirs = host
            .filesystem()
            .get_directories()
            .expect("get_directories");
        assert!(
            dirs.is_empty(),
            "a capsule starts with no preopened directory"
        );
        let mut host = sandboxed_host(&SandboxPlan::deny_all());
        assert!(host
            .filesystem()
            .get_directories()
            .expect("dirs")
            .is_empty());
    }

    #[test]
    fn a_capsule_reads_inside_its_preopen() {
        let w = world();
        let mut host = sandboxed_host(&read_plan(&w));
        let fd = only_preopen(&mut host);
        open(&mut host, &fd, "notes.txt", DescriptorFlags::READ).expect("inside the mount");
        open(&mut host, &fd, "src/lib.txt", DescriptorFlags::READ).expect("nested inside");
    }

    #[test]
    fn a_capsule_reading_outside_its_preopen_fails() {
        let w = world();
        let mut host = sandboxed_host(&read_plan(&w));
        let fd = only_preopen(&mut host);
        for escape in ["../private.txt", "src/../../private.txt", "/etc/hosts"] {
            let err = open(&mut host, &fd, escape, DescriptorFlags::READ)
                .expect_err("outside the preopen");
            assert_eq!(err, ErrorCode::NotPermitted, "{escape}");
        }
        let outside = w.outside.to_string_lossy().into_owned();
        let err =
            open(&mut host, &fd, &outside, DescriptorFlags::READ).expect_err("absolute host path");
        assert_eq!(err, ErrorCode::NotPermitted);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_preopen_is_not_followed() {
        let w = world();
        std::os::unix::fs::symlink(&w.outside, w.project.join("escape")).expect("symlink");
        let mut host = sandboxed_host(&read_plan(&w));
        let fd = only_preopen(&mut host);
        let err =
            open(&mut host, &fd, "escape", DescriptorFlags::READ).expect_err("link leaves mount");
        assert_eq!(err, ErrorCode::NotPermitted);
    }

    #[test]
    fn a_read_only_mount_refuses_writes() {
        let w = world();
        let mut host = sandboxed_host(&read_plan(&w));
        let fd = only_preopen(&mut host);
        let err =
            open(&mut host, &fd, "notes.txt", DescriptorFlags::WRITE).expect_err("read-only mount");
        assert!(
            matches!(
                err,
                ErrorCode::NotPermitted | ErrorCode::ReadOnly | ErrorCode::Access
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_read_write_mount_allows_writes_inside_only() {
        let w = world();
        let m = manifest(r#"network = "none""#, &["both:/work"]);
        let g = grants(&w, &[Access::Read, Access::Write]);
        let plan =
            SandboxPlan::resolve(&m, &[FsMount::new("/work", &w.project)], &g, NOW).expect("plan");
        let mut host = sandboxed_host(&plan);
        let fd = only_preopen(&mut host);
        open(
            &mut host,
            &fd,
            "notes.txt",
            DescriptorFlags::READ | DescriptorFlags::WRITE,
        )
        .expect("write inside");
        let err = open(&mut host, &fd, "../private.txt", DescriptorFlags::WRITE)
            .expect_err("write outside");
        assert_eq!(err, ErrorCode::NotPermitted);
    }
}
