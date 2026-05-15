//! Hardware-attested signing surfaces — RFC-CIT-AGENT-0001 §5.6 +
//! planset `04_APPROVAL_MODEL.md` "Signing surfaces".
//!
//! CIT-AGENT-4b lands the abstraction (`SigningSurface` trait) +
//! one concrete impl (`Ed25519FileSurface`). The signer-identity
//! contract: a `Signer`'s `id` is the SHA-256 fingerprint of the
//! public key. This binds quorum-deduplication to cryptographic
//! identity, not to a synthetic string the caller can spoof.
//!
//! Real hardware integrations land in per-platform 4b-tails:
//!   * `webauthn-rs` / `ctap2` for FIDO2 / WebAuthn (YubiKey, Titan)
//!   * `pkcs11` for PIV / CAC smart cards (federal employees)
//!   * `keyring` for OS keychain (Win/Mac/Linux)

use crate::capsule::manifest::Role;
use crate::error::AgentError;
use crate::hitl::Signer;
use ed25519_dalek::{Signature as Ed25519Sig, Signer as Ed25519Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

/// A signature produced by a `SigningSurface`. Carries the payload-
/// agnostic bytes + the pubkey that signed; the verifier checks
/// `signature_bytes` against an externally-supplied payload.
#[derive(Debug, Clone)]
pub struct AttestedSignature {
    pub signer: Signer,
    /// Raw signature bytes. Ed25519 is 64 bytes; other schemes (P-256
    /// PIV, FIDO2 CBOR) MUST normalize to this shape via their
    /// implementing surface.
    pub signature_bytes: Vec<u8>,
    /// The public key whose private counterpart signed this payload.
    /// Used by the verifier to look up the right key without trusting
    /// the (caller-controlled) signer.id string.
    pub pubkey: [u8; 32],
}

/// Hardware-backed signing abstraction. Implementations:
///   * `Ed25519FileSurface` — dev / test (key in file)
///   * Future: `Fido2Surface`, `PivSurface`, `OsKeyringSurface`
pub trait SigningSurface: Send + Sync {
    /// Produce a signature over the canonical action payload. The
    /// surface MUST NOT mutate the payload; the verifier will hash
    /// the same bytes.
    fn sign(&self, payload: &[u8]) -> Result<AttestedSignature, AgentError>;

    /// The public key whose private counterpart this surface holds.
    /// Used for the signer-id fingerprint + verification.
    fn pubkey(&self) -> [u8; 32];

    /// The role this surface signs under. Maps directly to the
    /// `Signer.role` field of the produced AttestedSignature.
    fn role(&self) -> Role;
}

/// Derive the canonical signer ID from a public key. SHA-256 of the
/// pubkey, hex-encoded. Stable across runs; lets the queue dedup
/// signers cryptographically.
pub fn signer_id_from_pubkey(pubkey: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(pubkey);
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify an `AttestedSignature` against the payload it claims to
/// sign. Returns `Ok(())` on success; `AgentError::Other(msg)` on
/// any failure (bad pubkey, bad signature length, signature doesn't
/// verify under the claimed pubkey, payload mismatch).
pub fn verify_attestation(payload: &[u8], sig: &AttestedSignature) -> Result<(), AgentError> {
    let vk = VerifyingKey::from_bytes(&sig.pubkey)
        .map_err(|e| AgentError::Other(format!("attestation: bad pubkey: {e}")))?;
    if sig.signature_bytes.len() != Ed25519Sig::BYTE_SIZE {
        return Err(AgentError::Other(format!(
            "attestation: signature length {} != expected {}",
            sig.signature_bytes.len(),
            Ed25519Sig::BYTE_SIZE
        )));
    }
    let mut sig_arr = [0u8; Ed25519Sig::BYTE_SIZE];
    sig_arr.copy_from_slice(&sig.signature_bytes);
    let signature = Ed25519Sig::from_bytes(&sig_arr);
    use ed25519_dalek::Verifier;
    vk.verify(payload, &signature)
        .map_err(|e| AgentError::Other(format!("attestation: signature does not verify: {e}")))?;
    // Verify the signer.id matches the pubkey fingerprint — this is
    // the binding between the caller-supplied role assertion and the
    // hardware-attested key.
    let expected_id = signer_id_from_pubkey(&sig.pubkey);
    if sig.signer.id != expected_id {
        return Err(AgentError::Other(format!(
            "attestation: signer.id '{}' does not match pubkey fingerprint '{}'",
            sig.signer.id, expected_id
        )));
    }
    Ok(())
}

// ── Ed25519FileSurface (dev / test impl) ─────────────────────────

/// A `SigningSurface` backed by a 32-byte ed25519 seed loaded from a
/// file. Suitable for dev mode + tests. Production deployments MUST
/// use a hardware-attested surface (4b-fido / 4b-piv / 4b-keyring).
pub struct Ed25519FileSurface {
    signing_key: SigningKey,
    role: Role,
    pubkey: [u8; 32],
}

impl std::fmt::Debug for Ed25519FileSurface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never include signing_key in Debug output.
        f.debug_struct("Ed25519FileSurface")
            .field("role", &self.role)
            .field("pubkey_fingerprint", &signer_id_from_pubkey(&self.pubkey))
            .finish_non_exhaustive()
    }
}

impl Ed25519FileSurface {
    /// Build from a raw 32-byte seed. The test entry point.
    pub fn from_seed(seed: [u8; 32], role: Role) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            role,
            pubkey,
        }
    }

    /// Load a surface from a file containing exactly 32 bytes of
    /// seed material. Returns `AgentError::Other` on read or size
    /// failure.
    pub fn load(path: &Path, role: Role) -> Result<Self, AgentError> {
        let bytes = std::fs::read(path)
            .map_err(|e| AgentError::Other(format!("read seed file {path:?}: {e}")))?;
        if bytes.len() != 32 {
            return Err(AgentError::Other(format!(
                "seed file {path:?}: expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(seed, role))
    }

    /// The signer identity (role + pubkey-fingerprint) this surface
    /// produces. Useful for setting up proposers + quorum sets.
    pub fn signer(&self) -> Signer {
        Signer {
            id: signer_id_from_pubkey(&self.pubkey),
            role: self.role,
        }
    }
}

impl SigningSurface for Ed25519FileSurface {
    fn sign(&self, payload: &[u8]) -> Result<AttestedSignature, AgentError> {
        let sig = self.signing_key.sign(payload);
        Ok(AttestedSignature {
            signer: self.signer(),
            signature_bytes: sig.to_bytes().to_vec(),
            pubkey: self.pubkey,
        })
    }

    fn pubkey(&self) -> [u8; 32] {
        self.pubkey
    }

    fn role(&self) -> Role {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(role: Role, seed_byte: u8) -> Ed25519FileSurface {
        Ed25519FileSurface::from_seed([seed_byte; 32], role)
    }

    #[test]
    fn ed25519_file_surface_round_trip() {
        let s = surface(Role::Reviewer, 0xab);
        let payload = b"approve transfer 100 SALT to alice";
        let sig = s.sign(payload).expect("sign");
        verify_attestation(payload, &sig).expect("verifies");
    }

    #[test]
    fn mismatched_payload_rejects() {
        let s = surface(Role::Reviewer, 0xcd);
        let signed = s.sign(b"approve A").expect("sign");
        verify_attestation(b"approve B", &signed)
            .expect_err("different payload rejects");
    }

    #[test]
    fn mismatched_pubkey_rejects() {
        let s_a = surface(Role::Reviewer, 0x01);
        let s_b = surface(Role::Reviewer, 0x02);
        let payload = b"some action";
        let mut sig = s_a.sign(payload).expect("sign");
        // Tamper: substitute s_b's pubkey but keep s_a's signature.
        sig.pubkey = s_b.pubkey();
        sig.signer.id = signer_id_from_pubkey(&sig.pubkey);
        verify_attestation(payload, &sig)
            .expect_err("signature/pubkey mismatch rejects");
    }

    #[test]
    fn tampered_signature_rejects() {
        let s = surface(Role::ComplianceOfficer, 0xff);
        let mut sig = s.sign(b"x").expect("sign");
        // Flip one bit in the signature.
        sig.signature_bytes[0] ^= 0x80;
        verify_attestation(b"x", &sig).expect_err("tampered sig rejects");
    }

    #[test]
    fn signer_id_is_pubkey_fingerprint() {
        let s = surface(Role::SecurityOfficer, 0x42);
        let expected = signer_id_from_pubkey(&s.pubkey());
        assert_eq!(s.signer().id, expected);
    }

    #[test]
    fn role_round_trip() {
        let s = surface(Role::SecurityOfficer, 0x42);
        let sig = s.sign(b"x").expect("sign");
        assert_eq!(sig.signer.role, Role::SecurityOfficer);
        assert_eq!(s.role(), Role::SecurityOfficer);
    }

    #[test]
    fn signer_id_mismatch_rejects() {
        let s = surface(Role::Reviewer, 0x11);
        let mut sig = s.sign(b"x").expect("sign");
        // Tamper just the signer.id field — attestation MUST catch
        // this because the id MUST be the pubkey fingerprint.
        sig.signer.id = "attacker-spoofed-id".to_string();
        let err = verify_attestation(b"x", &sig).expect_err("id mismatch rejects");
        assert!(err.to_string().contains("signer.id"));
    }

    #[test]
    fn load_from_file_round_trip() {
        // Write a 32-byte seed to a tmp file and load it back.
        let tmpdir = std::env::temp_dir();
        let path = tmpdir.join("cit-agent-4b-test-seed");
        let seed = [0xaa; 32];
        std::fs::write(&path, seed).expect("write seed");
        let s = Ed25519FileSurface::load(&path, Role::Operator).expect("load");
        assert_eq!(s.role(), Role::Operator);
        let sig = s.sign(b"payload").expect("sign");
        verify_attestation(b"payload", &sig).expect("verifies");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_wrong_seed_length() {
        let tmpdir = std::env::temp_dir();
        let path = tmpdir.join("cit-agent-4b-test-bad-seed");
        std::fs::write(&path, b"too short").expect("write");
        let err = Ed25519FileSurface::load(&path, Role::Operator)
            .expect_err("wrong size rejects");
        assert!(err.to_string().contains("32 bytes"));
        let _ = std::fs::remove_file(&path);
    }
}
