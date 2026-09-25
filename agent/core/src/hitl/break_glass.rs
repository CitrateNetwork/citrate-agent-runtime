//! Break-glass emergency approval path — RFC-CIT-AGENT-0001 §5.5.
//!
//! Verified by `.agentile/formal/specs/agent/BreakGlass.tla`
//! (CIT-AGENT-2 bounded PASS at 40M+ states, 0 violations). This
//! module is the runtime concretization of the spec's state
//! machine.
//!
//! Phases:
//!
//! ```text
//!   Pending ── invoke (SO sig) ──► Invoked ── 2 affirmations ──► Affirmed
//!                                    │
//!                                    └── 72h window expires ──► Unaffirmed ── surface() ──► Surfaced
//! ```
//!
//! Invariants enforced at runtime (matching TLA invariants):
//!   * `BreakGlassNotifiesAll`: invoke fills `notified` with all 5 roles.
//!   * `ITARBlocksBreakGlass`: ITAR-touching actions reject at invoke.
//!   * `OnlyEligibleInvokes`: only manifests with `break_glass_eligible = true` may invoke.
//!   * `AffirmedRequiresQuorum`: phase = Affirmed iff both Reviewer + ComplianceOfficer affirmed.
//!   * `SurfacedWasInvoked`: phase = Surfaced implies notified was filled (i.e. invoke happened).

use crate::capsule::manifest::{DataClass, Manifest, Role};
use crate::hitl::signing::{signer_is_authorized, verify_attestation, AttestedSignature, SignerRoster};
use crate::hitl::Signer;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 72-hour post-hoc affirmation window per RFC §5.5.
pub const AFFIRMATION_WINDOW: Duration = Duration::from_secs(72 * 60 * 60);

/// AR-B-026 — distinct signing domains for the two break-glass operations, so a
/// captured invoke attestation is not a valid affirm attestation (and vice
/// versa). The version suffix lets the preimage evolve (e.g. add a nonce/expiry)
/// without silently accepting old signatures.
///
/// PBA-L6b-013: v2 preimages also bind the action PAYLOAD (see
/// [`breakglass_preimage`]); v1 signatures (action_id only) no longer verify.
const BREAKGLASS_INVOKE_DOMAIN: &[u8] = b"CIT-BREAKGLASS-INVOKE-v2";
const BREAKGLASS_AFFIRM_DOMAIN: &[u8] = b"CIT-BREAKGLASS-AFFIRM-v2";

/// SHA-256 of the action payload a break-glass attestation covers.
pub fn breakglass_payload_hash(payload: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(payload).into()
}

/// Domain-separated attestation preimage:
/// `domain || 0x00 || sha256(payload) || action_id`.
///
/// PBA-L6b-013: the v1 preimage covered only `domain || action_id`, so an
/// affirmation said nothing about WHAT was done under that id. The payload
/// hash is fixed-length and precedes the variable-length action_id, so the
/// encoding stays unambiguous.
pub fn breakglass_preimage(domain: &[u8], action_id: &str, payload_hash: &[u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(domain.len() + 1 + 32 + action_id.len());
    p.extend_from_slice(domain);
    p.push(0x00);
    p.extend_from_slice(payload_hash);
    p.extend_from_slice(action_id.as_bytes());
    p
}

/// The exact bytes a SecurityOfficer signs to invoke break-glass on
/// `action_id` for `payload`.
pub fn invoke_preimage(action_id: &str, payload: &[u8]) -> Vec<u8> {
    breakglass_preimage(BREAKGLASS_INVOKE_DOMAIN, action_id, &breakglass_payload_hash(payload))
}

/// The exact bytes an affirmer signs; `payload` must be the payload the
/// invocation recorded.
pub fn affirm_preimage(action_id: &str, payload: &[u8]) -> Vec<u8> {
    breakglass_preimage(BREAKGLASS_AFFIRM_DOMAIN, action_id, &breakglass_payload_hash(payload))
}

/// The five-role lattice — the set of approvers notified on invoke.
fn all_approvers() -> BTreeSet<Role> {
    let mut s = BTreeSet::new();
    s.insert(Role::Operator);
    s.insert(Role::Reviewer);
    s.insert(Role::ComplianceOfficer);
    s.insert(Role::SecurityOfficer);
    s.insert(Role::Auditor);
    s
}

/// The post-hoc affirmation quorum per RFC §5.5: Reviewer + ComplianceOfficer.
/// SecurityOfficer is the invoker and can NOT self-affirm.
fn affirmation_quorum() -> BTreeSet<Role> {
    let mut s = BTreeSet::new();
    s.insert(Role::Reviewer);
    s.insert(Role::ComplianceOfficer);
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakGlassPhase {
    /// No break-glass invocation yet.
    Pending,
    /// Security Officer invoked break-glass; awaiting affirmation.
    Invoked,
    /// Reviewer + ComplianceOfficer affirmed within window.
    Affirmed,
    /// Window expired without quorum; awaiting doctor surface.
    Unaffirmed,
    /// Surfaced on a doctor report; sticky (won't transition further).
    Surfaced,
}

#[derive(Debug, Clone)]
pub struct BreakGlassEntry {
    pub action_id: String,
    pub phase: BreakGlassPhase,
    pub invoked_at: Option<Instant>,
    pub invoker: Option<Signer>,
    pub notified: BTreeSet<Role>,
    pub affirmations: HashMap<Role, Signer>,
    pub surface_count: u32,
    /// PBA-L6b-013: SHA-256 of the action payload the invocation covers.
    /// Every affirmation must sign over the same hash.
    pub payload_hash: Option<[u8; 32]>,
}

impl BreakGlassEntry {
    fn new(action_id: String) -> Self {
        Self {
            action_id,
            phase: BreakGlassPhase::Pending,
            invoked_at: None,
            invoker: None,
            notified: BTreeSet::new(),
            affirmations: HashMap::new(),
            surface_count: 0,
            payload_hash: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakGlassError {
    /// Invocation attempted by a non-SecurityOfficer signer.
    NotSecurityOfficer,
    /// Action touches ITAR-classified data; break-glass blocked per RFC §2.3.
    ItarBlocked,
    /// Manifest's `risk.break_glass_eligible` is false.
    NotEligible,
    /// Action already invoked (Invoked / Affirmed / Unaffirmed / Surfaced).
    AlreadyInvoked,
    /// Affirmation attempted but action isn't in `Invoked` phase.
    NotInvoked,
    /// Affirmer role is not Reviewer or ComplianceOfficer.
    NotAffirmationRole,
    /// Invoker (SecurityOfficer) tried to self-affirm.
    InvokerCannotAffirm,
    /// Same signer affirmed twice.
    DuplicateAffirmer,
    /// Affirmation arrived after the 72-hour window expired.
    AffirmationWindowExpired,
    /// Unknown action_id (no entry exists).
    UnknownActionId,
    /// RM-G.2 — the supplied attestation does not verify over the action_id
    /// (bad signature/pubkey/length, or signer.id ≠ pubkey fingerprint).
    AttestationInvalid(String),
    /// RM-G.2 — the signature verifies but the pubkey is not on the
    /// authorized-signer roster for the claimed role (or no roster is
    /// configured in a release build). A self-minted key cannot invoke or
    /// affirm break-glass.
    SignerNotAuthorized,
}

impl std::fmt::Display for BreakGlassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use BreakGlassError::*;
        match self {
            NotSecurityOfficer => write!(f, "only SecurityOfficer may invoke break-glass"),
            ItarBlocked => write!(f, "ITAR-classified action MUST NOT use break-glass (RFC §2.3)"),
            NotEligible => write!(
                f,
                "manifest's [risk].break_glass_eligible is false; capsule cannot invoke"
            ),
            AlreadyInvoked => write!(f, "action already invoked"),
            NotInvoked => write!(f, "action is not in Invoked phase"),
            NotAffirmationRole => write!(
                f,
                "affirmer role must be Reviewer or ComplianceOfficer per RFC §5.5"
            ),
            InvokerCannotAffirm => write!(f, "SecurityOfficer (invoker) cannot self-affirm"),
            DuplicateAffirmer => write!(f, "signer already affirmed"),
            AttestationInvalid(m) => write!(f, "break-glass attestation invalid: {m}"),
            SignerNotAuthorized => write!(
                f,
                "break-glass signer pubkey is not on the authorized-signer roster for the role"
            ),
            AffirmationWindowExpired => {
                write!(f, "affirmation arrived after 72-hour window")
            }
            UnknownActionId => write!(f, "no break-glass entry for that action_id"),
        }
    }
}

/// Per-action break-glass registry. The runtime holds one of these
/// per cit-agent process; production deployments persist the
/// underlying map to an audit-chain-backed store (CIT-AGENT-5).
pub struct BreakGlassRegistry {
    entries: Mutex<HashMap<String, BreakGlassEntry>>,
    // RM-G.2 — authorized-signer roster (shared with the quorum path).
    // When `None`, invoke/affirm fail closed in release builds.
    signer_roster: Option<Arc<dyn SignerRoster>>,
}

impl Default for BreakGlassRegistry {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            signer_roster: None,
        }
    }
}

impl BreakGlassRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the authorized-signer roster (RM-G.2). Production MUST set
    /// this; without it a release build refuses all invoke/affirm.
    pub fn with_signer_roster(mut self, roster: Arc<dyn SignerRoster>) -> Self {
        self.signer_roster = Some(roster);
        self
    }

    /// Verify a break-glass attestation over the domain-separated preimage
    /// `domain || 0x00 || action_id` and roster-authorize the signer for `role`.
    /// Returns the verified `Signer` on success.
    ///
    /// AR-B-026: the attestation preimage was the bare `action_id.as_bytes()` —
    /// no domain tag — so a captured INVOKE signature replayed verbatim as an
    /// AFFIRM (only the role check + InvokerCannotAffirm separated them). Binding
    /// a distinct domain to each operation makes an invoke signature invalid for
    /// affirm and vice-versa.
    fn authorize(
        &self,
        domain: &[u8],
        action_id: &str,
        payload_hash: &[u8; 32],
        attested: &AttestedSignature,
    ) -> Result<Signer, BreakGlassError> {
        verify_attestation(&breakglass_preimage(domain, action_id, payload_hash), attested)
            .map_err(|e| BreakGlassError::AttestationInvalid(e.to_string()))?;
        let dev_allowed = cfg!(test) || cfg!(feature = "insecure-dev-hitl");
        if !signer_is_authorized(
            self.signer_roster.as_deref(),
            &attested.pubkey,
            attested.signer.role,
            dev_allowed,
        ) {
            return Err(BreakGlassError::SignerNotAuthorized);
        }
        Ok(attested.signer.clone())
    }

    /// SecurityOfficer invokes break-glass on an action. Validates
    /// the ITAR / eligibility / role preconditions, then transitions
    /// Pending → Invoked and fills `notified` with all 5 approvers.
    ///
    /// PBA-L6b-013: `payload` is the action being authorised; the invoker
    /// signs [`invoke_preimage`]`(action_id, payload)` and every affirmer must
    /// sign over the same payload hash.
    pub fn invoke(
        &self,
        action_id: &str,
        payload: &[u8],
        attested: AttestedSignature,
        manifest: &Manifest,
        now: Instant,
    ) -> Result<(), BreakGlassError> {
        // RM-G.2: a caller-asserted role is not enough — require a verified
        // attestation over the action_id from a roster-authorized key.
        let payload_hash = breakglass_payload_hash(payload);
        let signer =
            self.authorize(BREAKGLASS_INVOKE_DOMAIN, action_id, &payload_hash, &attested)?;
        if signer.role != Role::SecurityOfficer {
            return Err(BreakGlassError::NotSecurityOfficer);
        }
        if !manifest.risk.break_glass_eligible {
            return Err(BreakGlassError::NotEligible);
        }
        if manifest_touches_itar(manifest) {
            return Err(BreakGlassError::ItarBlocked);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BreakGlassError::UnknownActionId)?;
        let entry = entries
            .entry(action_id.to_string())
            .or_insert_with(|| BreakGlassEntry::new(action_id.to_string()));
        if entry.phase != BreakGlassPhase::Pending {
            return Err(BreakGlassError::AlreadyInvoked);
        }
        entry.phase = BreakGlassPhase::Invoked;
        entry.invoked_at = Some(now);
        entry.invoker = Some(signer);
        entry.notified = all_approvers();
        entry.payload_hash = Some(payload_hash);
        Ok(())
    }

    /// Reviewer or ComplianceOfficer affirms a break-glass invocation.
    /// When both roles have affirmed within the window, the phase
    /// transitions to Affirmed.
    pub fn affirm(
        &self,
        action_id: &str,
        attested: AttestedSignature,
        now: Instant,
    ) -> Result<(), BreakGlassError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BreakGlassError::UnknownActionId)?;
        let entry = entries
            .get_mut(action_id)
            .ok_or(BreakGlassError::UnknownActionId)?;
        if entry.phase != BreakGlassPhase::Invoked {
            return Err(BreakGlassError::NotInvoked);
        }
        let payload_hash = entry.payload_hash.ok_or(BreakGlassError::NotInvoked)?;
        // RM-G.2: verified attestation + roster authorization required.
        // AR-B-026: affirm uses a DISTINCT domain from invoke, so an invoke
        // signature cannot be replayed here.
        // PBA-L6b-013: the affirmation must cover the payload the invocation
        // recorded, not just the action id.
        let signer =
            self.authorize(BREAKGLASS_AFFIRM_DOMAIN, action_id, &payload_hash, &attested)?;
        if !matches!(signer.role, Role::Reviewer | Role::ComplianceOfficer) {
            return Err(BreakGlassError::NotAffirmationRole);
        }
        if let Some(invoker) = &entry.invoker {
            if invoker.id == signer.id {
                return Err(BreakGlassError::InvokerCannotAffirm);
            }
        }
        if let Some(invoked_at) = entry.invoked_at {
            if now.duration_since(invoked_at) > AFFIRMATION_WINDOW {
                return Err(BreakGlassError::AffirmationWindowExpired);
            }
        }
        // PBA-L6b-013: two-person affirmation means two SIGNERS. The roster
        // lets one key hold several roles, so dedup by signer id as well as by
        // role (a second signer of an already-affirmed role adds nothing).
        if entry.affirmations.contains_key(&signer.role)
            || entry.affirmations.values().any(|s| s.id == signer.id)
        {
            return Err(BreakGlassError::DuplicateAffirmer);
        }
        entry.affirmations.insert(signer.role, signer);
        let signed_roles: BTreeSet<Role> = entry.affirmations.keys().copied().collect();
        if affirmation_quorum().is_subset(&signed_roles) {
            entry.phase = BreakGlassPhase::Affirmed;
        }
        Ok(())
    }

    /// Wall-clock tick: any Invoked entry whose 72-hour window has
    /// elapsed without quorum transitions to Unaffirmed.
    pub fn tick(&self, now: Instant) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        for entry in entries.values_mut() {
            if entry.phase == BreakGlassPhase::Invoked {
                if let Some(invoked_at) = entry.invoked_at {
                    if now.duration_since(invoked_at) >= AFFIRMATION_WINDOW {
                        entry.phase = BreakGlassPhase::Unaffirmed;
                    }
                }
            }
        }
    }

    /// Doctor surface: any Unaffirmed entry transitions to Surfaced
    /// and its surface_count increments. Surfaced is sticky — every
    /// subsequent `surface()` call increments the count on an already-
    /// Surfaced entry without re-transitioning.
    pub fn surface(&self) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        for entry in entries.values_mut() {
            match entry.phase {
                BreakGlassPhase::Unaffirmed => {
                    entry.phase = BreakGlassPhase::Surfaced;
                    entry.surface_count = entry.surface_count.saturating_add(1);
                }
                BreakGlassPhase::Surfaced => {
                    entry.surface_count = entry.surface_count.saturating_add(1);
                }
                _ => {}
            }
        }
    }

    /// Inspection accessor: snapshot of an action's current state.
    pub fn get(&self, action_id: &str) -> Option<BreakGlassEntry> {
        self.entries
            .lock()
            .ok()
            .and_then(|m| m.get(action_id).cloned())
    }
}

/// Returns `true` if the manifest's data_class section names ITAR
/// anywhere — reads, writes, or emits. Used by `invoke` to block
/// break-glass on ITAR-touching actions per RFC §2.3.
pub fn manifest_touches_itar(manifest: &Manifest) -> bool {
    let touches = |v: &[DataClass]| v.iter().any(|c| *c == DataClass::Itar);
    touches(&manifest.data_class.reads)
        || touches(&manifest.data_class.writes)
        || touches(&manifest.data_class.emits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::manifest::{
        CapabilitySet, CapsuleMetadata, DataClassDecl, NetworkPolicy, OverlayDecl,
        ProcedureDecl, ProvenanceDecl, RiskDecl, RiskTier, SigningDecl, SigningTier,
    };
    use crate::hitl::signing::{
        AttestedSignature, Ed25519FileSurface, SigningSurface, StaticSignerRoster,
    };

    /// RM-G.2 tripwire: with a roster configured, a break-glass invoke from a
    /// self-minted SecurityOfficer key (valid signature, NOT enrolled) is
    /// rejected; the enrolled key works. Pre-fix invoke trusted the
    /// caller-asserted role with zero signature/roster check.
    #[test]
    fn rm_g2_breakglass_requires_rostered_signer() {
        let good = attest("good-so", Role::SecurityOfficer, "act1");
        let reg = BreakGlassRegistry::new().with_signer_roster(std::sync::Arc::new(
            StaticSignerRoster::new().authorize(good.pubkey, Role::SecurityOfficer),
        ));
        let m = manifest(true, vec![], vec![], vec![]);

        // Self-minted SO key, NOT on the roster → rejected even with a valid sig.
        let evil = attest("evil-so", Role::SecurityOfficer, "act1");
        let err = reg
            .invoke("act1", P, evil, &m, Instant::now())
            .expect_err("unauthorized SO must be rejected");
        assert!(matches!(err, BreakGlassError::SignerNotAuthorized));

        // Enrolled SO key → invoke succeeds.
        reg.invoke("act1", P, good, &m, Instant::now())
            .expect("rostered SO invokes");
    }

    fn manifest(
        break_glass_eligible: bool,
        reads: Vec<DataClass>,
        writes: Vec<DataClass>,
        emits: Vec<DataClass>,
    ) -> Manifest {
        Manifest {
            capsule: CapsuleMetadata {
                name: "x".into(),
                version: "0.1.0".into(),
                content_hash: "sha256:".to_string() + &"0".repeat(64),
            },
            capability: CapabilitySet {
                network: NetworkPolicy::None,
                filesystem: vec![],
                chain_calls: vec![],
                subagent_spawn: false,
            },
            data_class: DataClassDecl {
                reads,
                writes,
                emits,
            },
            risk: RiskDecl {
                tier: RiskTier::High,
                required_roles: vec![Role::Reviewer, Role::ComplianceOfficer],
                break_glass_eligible,
            },
            overlay: OverlayDecl {
                certified: vec![],
                not_certified: vec![],
            },
            procedure: ProcedureDecl { gates: vec![] },
            provenance: ProvenanceDecl {
                publisher: "did:citrate:agent:0xab12".into(),
                build_reproducible: true,
                agentile_sprint: "test".into(),
                tla_spec: "".into(),
            },
            signing: SigningDecl {
                tier: SigningTier::Bundled,
            },
        }
    }

    /// The action payload every test invocation authorises.
    const P: &[u8] = b"test action payload";

    fn attest_domain(name: &str, role: Role, action_id: &str, domain: &[u8]) -> AttestedSignature {
        attest_payload(name, role, action_id, domain, P)
    }

    fn attest_payload(
        name: &str,
        role: Role,
        action_id: &str,
        domain: &[u8],
        payload: &[u8],
    ) -> AttestedSignature {
        let mut seed = [0u8; 32];
        let bytes = name.as_bytes();
        let n = bytes.len().min(32);
        seed[..n].copy_from_slice(&bytes[..n]);
        let s = Ed25519FileSurface::from_seed(seed, role);
        s.sign(&breakglass_preimage(domain, action_id, &breakglass_payload_hash(payload)))
            .expect("attest sign")
    }

    /// An INVOKE-domain attestation (AR-B-026).
    fn attest(name: &str, role: Role, action_id: &str) -> AttestedSignature {
        attest_domain(name, role, action_id, BREAKGLASS_INVOKE_DOMAIN)
    }

    /// An AFFIRM-domain attestation (AR-B-026).
    fn attest_affirm(name: &str, role: Role, action_id: &str) -> AttestedSignature {
        attest_domain(name, role, action_id, BREAKGLASS_AFFIRM_DOMAIN)
    }

    #[test]
    fn invoke_requires_security_officer() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        let err = reg
            .invoke("act1", P,
                attest("alice", Role::Reviewer, "act1"),
                &m,
                Instant::now(),
            )
            .expect_err("non-SO rejected");
        assert_eq!(err, BreakGlassError::NotSecurityOfficer);
    }

    #[test]
    fn invoke_blocks_itar_reads() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![DataClass::Itar], vec![], vec![]);
        let err = reg
            .invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, Instant::now())
            .expect_err("ITAR reads block");
        assert_eq!(err, BreakGlassError::ItarBlocked);
    }

    #[test]
    fn invoke_blocks_itar_writes() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![DataClass::Itar], vec![]);
        let err = reg
            .invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, Instant::now())
            .expect_err("ITAR writes block");
        assert_eq!(err, BreakGlassError::ItarBlocked);
    }

    #[test]
    fn invoke_blocks_itar_emits() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![DataClass::Itar]);
        let err = reg
            .invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, Instant::now())
            .expect_err("ITAR emits block");
        assert_eq!(err, BreakGlassError::ItarBlocked);
    }

    #[test]
    fn invoke_requires_eligible_manifest() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(false, vec![], vec![], vec![]);
        let err = reg
            .invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, Instant::now())
            .expect_err("not eligible");
        assert_eq!(err, BreakGlassError::NotEligible);
    }

    #[test]
    fn invoke_happy_path_notifies_all_approvers() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![DataClass::Cui], vec![], vec![]);
        reg.invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, Instant::now())
            .expect("invoke succeeds");
        let entry = reg.get("act1").expect("entry exists");
        assert_eq!(entry.phase, BreakGlassPhase::Invoked);
        assert_eq!(entry.notified.len(), 5);
        for r in [
            Role::Operator,
            Role::Reviewer,
            Role::ComplianceOfficer,
            Role::SecurityOfficer,
            Role::Auditor,
        ] {
            assert!(entry.notified.contains(&r));
        }
    }

    #[test]
    fn double_invoke_rejected() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        reg.invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, Instant::now())
            .expect("first");
        let err = reg
            .invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, Instant::now())
            .expect_err("second");
        assert_eq!(err, BreakGlassError::AlreadyInvoked);
    }

    #[test]
    fn affirm_quorum_transitions_to_affirmed() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        let t0 = Instant::now();
        reg.invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, t0)
            .expect("invoke");
        reg.affirm("act1", attest_affirm("rv", Role::Reviewer, "act1"), t0)
            .expect("rv affirms");
        assert_eq!(reg.get("act1").unwrap().phase, BreakGlassPhase::Invoked);
        reg.affirm("act1", attest_affirm("co", Role::ComplianceOfficer, "act1"), t0)
            .expect("co affirms");
        assert_eq!(reg.get("act1").unwrap().phase, BreakGlassPhase::Affirmed);
    }

    /// AR-B-026 (RC-8) — a captured INVOKE attestation must NOT be replayable as
    /// an AFFIRM. Previously this test replayed the SO's invoke attestation into
    /// affirm() and asserted only the role-side guard (`NotAffirmationRole`)
    /// stopped it — i.e. the SAME signature was accepted by both operations, the
    /// exact replay the finding flags. With domain separation the affirm
    /// verifier (AFFIRM domain) rejects the INVOKE-domain signature outright,
    /// before any role check.
    #[test]
    fn invoke_attestation_is_not_replayable_as_affirm() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        let so = attest("so", Role::SecurityOfficer, "act1");
        reg.invoke("act1", P, so.clone(), &m, Instant::now())
            .expect("invoke");
        // Replay the invoke attestation into affirm — must fail on the
        // attestation itself (domain mismatch), not merely the role guard.
        let err = reg
            .affirm("act1", so.clone(), Instant::now())
            .expect_err("invoke attestation must not verify as an affirm");
        assert!(
            matches!(err, BreakGlassError::AttestationInvalid(_)),
            "replayed invoke sig must be rejected as an invalid affirm attestation; got: {err:?}"
        );
    }

    #[test]
    fn two_reviewers_dont_complete_quorum() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        let t0 = Instant::now();
        reg.invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, t0)
            .expect("invoke");
        reg.affirm("act1", attest_affirm("rv1", Role::Reviewer, "act1"), t0)
            .expect("first rv");
        // Same role again — DuplicateAffirmer.
        let err = reg
            .affirm("act1", attest_affirm("rv2", Role::Reviewer, "act1"), t0)
            .expect_err("two reviewers blocked");
        assert_eq!(err, BreakGlassError::DuplicateAffirmer);
        // Phase still Invoked.
        assert_eq!(reg.get("act1").unwrap().phase, BreakGlassPhase::Invoked);
    }

    /// PBA-L6b-013 regression: one key enrolled for BOTH affirmation roles
    /// must not satisfy the two-person affirmation alone. Pre-fix the
    /// affirmation set was deduplicated by role, so the same signer affirmed
    /// once as Reviewer and once as ComplianceOfficer and the entry went to
    /// Affirmed.
    #[test]
    fn one_multi_role_key_cannot_affirm_twice_pba_l6b_013() {
        let rv = attest_affirm("dual", Role::Reviewer, "act1");
        let co = attest_affirm("dual", Role::ComplianceOfficer, "act1");
        assert_eq!(rv.signer.id, co.signer.id, "same key, two role claims");
        let so = attest("so", Role::SecurityOfficer, "act1");
        let reg = BreakGlassRegistry::new().with_signer_roster(std::sync::Arc::new(
            StaticSignerRoster::new()
                .authorize(so.pubkey, Role::SecurityOfficer)
                .authorize(rv.pubkey, Role::Reviewer)
                .authorize(rv.pubkey, Role::ComplianceOfficer),
        ));
        let m = manifest(true, vec![], vec![], vec![]);
        let t0 = Instant::now();
        reg.invoke("act1", P, so, &m, t0).expect("invoke");
        reg.affirm("act1", rv, t0).expect("first affirmation");
        let err = reg
            .affirm("act1", co, t0)
            .expect_err("the same signer must not affirm a second time under another role");
        assert_eq!(err, BreakGlassError::DuplicateAffirmer);
        assert_eq!(reg.get("act1").unwrap().phase, BreakGlassPhase::Invoked);
    }

    /// PBA-L6b-013: an affirmation must cover the payload the invocation
    /// recorded. A valid, rostered affirmation over a DIFFERENT payload for the
    /// same action id is rejected.
    #[test]
    fn affirmation_is_bound_to_the_invoked_payload_pba_l6b_013() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        let t0 = Instant::now();
        reg.invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, t0)
            .expect("invoke");
        let other = attest_payload("rv", Role::Reviewer, "act1", BREAKGLASS_AFFIRM_DOMAIN, b"other");
        let err = reg.affirm("act1", other, t0).expect_err("wrong payload");
        assert!(matches!(err, BreakGlassError::AttestationInvalid(_)), "{err:?}");
        // An invoke over one payload cannot be attested with another either.
        let reg2 = BreakGlassRegistry::new();
        let so_other =
            attest_payload("so", Role::SecurityOfficer, "act1", BREAKGLASS_INVOKE_DOMAIN, b"other");
        assert!(matches!(
            reg2.invoke("act1", P, so_other, &m, t0),
            Err(BreakGlassError::AttestationInvalid(_))
        ));
        // The public preimage helpers match what the registry verifies.
        assert_eq!(
            invoke_preimage("act1", P),
            breakglass_preimage(BREAKGLASS_INVOKE_DOMAIN, "act1", &breakglass_payload_hash(P))
        );
        assert_eq!(
            affirm_preimage("act1", P),
            breakglass_preimage(BREAKGLASS_AFFIRM_DOMAIN, "act1", &breakglass_payload_hash(P))
        );
        assert_eq!(reg.get("act1").unwrap().payload_hash, Some(breakglass_payload_hash(P)));
    }

    #[test]
    fn tick_unaffirms_after_window() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        let t0 = Instant::now();
        reg.invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, t0)
            .expect("invoke");
        // Tick at t0 + 71h — still Invoked.
        let t_pre = t0 + Duration::from_secs(71 * 3600);
        reg.tick(t_pre);
        assert_eq!(reg.get("act1").unwrap().phase, BreakGlassPhase::Invoked);
        // Tick at t0 + 73h — Unaffirmed.
        let t_post = t0 + Duration::from_secs(73 * 3600);
        reg.tick(t_post);
        assert_eq!(reg.get("act1").unwrap().phase, BreakGlassPhase::Unaffirmed);
    }

    #[test]
    fn affirmation_after_window_rejected() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        let t0 = Instant::now();
        reg.invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, t0)
            .expect("invoke");
        let t_late = t0 + Duration::from_secs(73 * 3600);
        let err = reg
            .affirm("act1", attest_affirm("rv", Role::Reviewer, "act1"), t_late)
            .expect_err("late affirm rejected");
        assert_eq!(err, BreakGlassError::AffirmationWindowExpired);
    }

    #[test]
    fn surface_transitions_unaffirmed_to_surfaced_sticky() {
        let reg = BreakGlassRegistry::new();
        let m = manifest(true, vec![], vec![], vec![]);
        let t0 = Instant::now();
        reg.invoke("act1", P, attest("so", Role::SecurityOfficer, "act1"), &m, t0)
            .expect("invoke");
        reg.tick(t0 + Duration::from_secs(73 * 3600));
        assert_eq!(reg.get("act1").unwrap().phase, BreakGlassPhase::Unaffirmed);

        reg.surface();
        let entry = reg.get("act1").unwrap();
        assert_eq!(entry.phase, BreakGlassPhase::Surfaced);
        assert_eq!(entry.surface_count, 1);

        // Re-surfacing increments the counter but doesn't unstick.
        reg.surface();
        reg.surface();
        let entry = reg.get("act1").unwrap();
        assert_eq!(entry.phase, BreakGlassPhase::Surfaced);
        assert_eq!(entry.surface_count, 3);
    }

    #[test]
    fn manifest_touches_itar_detects_each_field() {
        assert!(manifest_touches_itar(&manifest(
            true,
            vec![DataClass::Itar],
            vec![],
            vec![]
        )));
        assert!(manifest_touches_itar(&manifest(
            true,
            vec![],
            vec![DataClass::Itar],
            vec![]
        )));
        assert!(manifest_touches_itar(&manifest(
            true,
            vec![],
            vec![],
            vec![DataClass::Itar]
        )));
        assert!(!manifest_touches_itar(&manifest(
            true,
            vec![DataClass::Cui, DataClass::Phi],
            vec![DataClass::Public],
            vec![DataClass::Ferpa]
        )));
    }
}
