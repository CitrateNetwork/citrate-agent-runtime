//! HUP-S2.5 — the capsule sandbox of one agent session.
//!
//! A capsule called from a session runs under that session's own
//! [`SandboxProvider`], resolved again at every call:
//!
//! * **Folder mounts.** Core may bind a declared guest mount of a named capsule to a member
//!   folder (`capsuleSandbox.mounts` in `POST /sessions`). A binding only says *which* folder;
//!   whether the capsule gets it is decided by the session's live folder grants
//!   ([`SessionGrants`]) through [`SandboxPlan::resolve_with_egress`]: a whole-folder grant must
//!   cover it, write needs read and write grants, the deny list wins, and a grant revoked or
//!   replaced mid-session stops applying at the next call. Bindings therefore need a grant
//!   document; a session opened with bindings and no grants is refused.
//! * **Egress consent.** Core may record the member's consent for a named capsule to reach exact
//!   public `ip:port` addresses (`capsuleSandbox.egress`). The capsule reaches an address only
//!   when it is on both that consent and the capsule's signed `network_allow` list. A private,
//!   loopback or link-local address is refused here, as it is in the manifest.
//!
//! With no `capsuleSandbox` (the default, and what core sends today) a capsule gets no folder
//! and no address. The sidecar never creates a grant or a consent; it only applies what core
//! sent. Keyless: nothing here holds a key or signs (Rule 3).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use citrate_agent_core::capsule::manifest::Manifest;
use citrate_agent_core::capsule::sandbox::{
    parse_network_allow, FsMount, SandboxPlan, SandboxProvider,
};
use citrate_agent_core::error::AgentError;
use serde::Deserialize;

use crate::grants::SessionGrants;

/// Most mount bindings, and most egress consents, one session may carry. Placeholder value,
/// pending owner sign-off.
pub const MAX_CAPSULE_BINDINGS: usize = 32;
/// Longest capsule name or guest path accepted in a binding.
const MAX_FIELD_LEN: usize = 256;

/// `capsuleSandbox` in `POST /sessions`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapsuleSandboxDoc {
    #[serde(default)]
    pub mounts: Vec<MountBinding>,
    #[serde(default)]
    pub egress: Vec<EgressConsent>,
}

/// Bind the declared guest mount `guest` of capsule `capsule` to the member folder `host`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MountBinding {
    pub capsule: String,
    pub guest: String,
    pub host: PathBuf,
}

/// The member's consent for capsule `capsule` to reach the exact addresses in `allow`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressConsent {
    pub capsule: String,
    pub allow: Vec<String>,
}

/// One session's capsule sandbox: its grants (shared with the file tools, so a replace reaches
/// both at once), its mount bindings and its egress consent.
pub struct SessionSandbox {
    grants: Option<Arc<SessionGrants>>,
    mounts: HashMap<String, Vec<FsMount>>,
    egress: HashMap<String, Vec<SocketAddr>>,
}

impl std::fmt::Debug for SessionSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSandbox")
            .field("grants", &self.grants.is_some())
            .field("mounts", &self.mounts)
            .field("egress", &self.egress)
            .finish()
    }
}

fn check_name(capsule: &str) -> Result<(), String> {
    if capsule.is_empty() || capsule.len() > MAX_FIELD_LEN || capsule.chars().any(char::is_control)
    {
        return Err(format!(
            "a capsule binding needs a capsule name of 1 to {MAX_FIELD_LEN} printable characters"
        ));
    }
    Ok(())
}

impl SessionSandbox {
    /// Validate `doc` against the session's `grants`. Any invalid entry refuses the whole
    /// document, so a session never runs with part of what core asked for.
    pub fn new(
        doc: Option<CapsuleSandboxDoc>,
        grants: Option<Arc<SessionGrants>>,
    ) -> Result<Self, String> {
        let doc = doc.unwrap_or_default();
        if doc.mounts.len() > MAX_CAPSULE_BINDINGS || doc.egress.len() > MAX_CAPSULE_BINDINGS {
            return Err(format!(
                "capsuleSandbox takes at most {MAX_CAPSULE_BINDINGS} mounts and \
                 {MAX_CAPSULE_BINDINGS} egress entries"
            ));
        }
        if !doc.mounts.is_empty() && grants.is_none() {
            return Err(
                "capsule mounts need the member's folder grant document (send grants with the \
                 session)"
                    .into(),
            );
        }
        let mut mounts: HashMap<String, Vec<FsMount>> = HashMap::new();
        for m in doc.mounts {
            check_name(&m.capsule)?;
            if !m.guest.starts_with('/') || m.guest.len() > MAX_FIELD_LEN {
                return Err(format!(
                    "the guest path {:?} of a capsule mount must be absolute (start with '/')",
                    m.guest
                ));
            }
            if !m.host.is_absolute() {
                return Err(format!(
                    "the folder {} of a capsule mount must be an absolute path",
                    m.host.display()
                ));
            }
            mounts
                .entry(m.capsule)
                .or_default()
                .push(FsMount::new(m.guest, m.host));
        }
        let mut egress: HashMap<String, Vec<SocketAddr>> = HashMap::new();
        for e in doc.egress {
            check_name(&e.capsule)?;
            if e.allow.is_empty() {
                return Err(format!(
                    "the egress consent for {:?} names no address",
                    e.capsule
                ));
            }
            let addrs = parse_network_allow(&e.allow).map_err(|err| err.to_string())?;
            egress.entry(e.capsule).or_default().extend(addrs);
        }
        Ok(Self {
            grants,
            mounts,
            egress,
        })
    }
}

impl SandboxProvider for SessionSandbox {
    fn plan_for(&self, manifest: &Manifest) -> Result<SandboxPlan, AgentError> {
        let name = &manifest.capsule.name;
        let mounts = self.mounts.get(name).map(Vec::as_slice).unwrap_or(&[]);
        let consent = self.egress.get(name).map(Vec::as_slice).unwrap_or(&[]);
        match &self.grants {
            Some(g) => g
                .with_folder_grants(|fg, now| {
                    SandboxPlan::resolve_with_egress(manifest, mounts, fg, now, consent)
                })
                .map_err(AgentError::Capsule)?,
            // `new` refuses mounts without grants, so only egress can apply here.
            None => SandboxPlan::egress_only(manifest, consent),
        }
    }
}
