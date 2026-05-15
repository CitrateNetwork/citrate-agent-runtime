//! Signing tier verification — RFC-CIT-AGENT-0001 §4.4.
//!
//! Per planset `03_CAPSULE_MODEL.md` "The three signing tiers":
//!
//! | Tier | Signed by | Verification |
//! |---|---|---|
//! | `bundled` | Citrate Network Inc. canonical publisher key (FIPS HSM) | Registry returns the canonical key; signature MUST verify under it. Mismatch → `CapsuleSigningTierMismatch`. |
//! | `managed` | Org's procurement-chain CA (OrganizationSBT's `signing_authority`) | Registry returns the org-CA key for the active OrganizationSBT; signature MUST verify under it. |
//! | `workspace` | Operator's local key (hardware-backed) | Registry returns `None`; the signature is verified separately by the workspace dual-approval flow. CIT-AGENT-3b stops short here. |
//!
//! Signature payload (RFC §4.4):
//!   `ed25519_sign(publisher_priv, sha256(content_hash_str))`
//!
//! The `content_hash_str` is the literal manifest field
//! (`"sha256:abcd...."`) — NOT the raw bytes. This keeps the wire
//! format stable across canonical-form changes to the bundle.

use crate::capsule::manifest::SigningTier;
use crate::error::AgentError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Publisher-key registry. Implemented by the harness with whatever
/// trust anchor is appropriate (compiled-in canonical key for bundled
/// tier, OrganizationSBT lookup for managed tier).
pub trait PublicKeyRegistry: Send + Sync {
    /// Return the publisher key authorized for the given signing tier.
    /// Returns `None` for `Workspace` — workspace-tier verification is
    /// handled by the dual-approval flow, not this trait.
    fn publisher_key_for(&self, tier: SigningTier) -> Option<&[u8; 32]>;
}

/// Static, compile-time-known registry. Useful for tests and for the
/// bundled-tier production deployment where the canonical key is
/// shipped in the harness binary.
pub struct StaticKeyRegistry {
    pub bundled: Option<[u8; 32]>,
    pub managed: Option<[u8; 32]>,
}

impl PublicKeyRegistry for StaticKeyRegistry {
    fn publisher_key_for(&self, tier: SigningTier) -> Option<&[u8; 32]> {
        match tier {
            SigningTier::Bundled => self.bundled.as_ref(),
            SigningTier::Managed => self.managed.as_ref(),
            SigningTier::Workspace => None,
        }
    }
}

/// Verify the publisher signature over the manifest's content_hash.
/// Returns `Ok(())` on success; an appropriate `AgentError` variant
/// on any failure.
pub fn verify_signature(
    content_hash: &str,
    signature_bytes: &[u8],
    declared_tier: SigningTier,
    registry: &dyn PublicKeyRegistry,
) -> Result<(), AgentError> {
    let pubkey_bytes = match registry.publisher_key_for(declared_tier) {
        Some(k) => k,
        None => {
            return Err(AgentError::CapsuleSigningTierMismatch(format!(
                "no trusted publisher key configured for tier {declared_tier:?}"
            )));
        }
    };
    let pubkey = VerifyingKey::from_bytes(pubkey_bytes).map_err(|e| {
        AgentError::CapsuleSignatureInvalid(format!("invalid publisher key in registry: {e}"))
    })?;
    if signature_bytes.len() != Signature::BYTE_SIZE {
        return Err(AgentError::CapsuleSignatureInvalid(format!(
            "signature length {} != expected {}",
            signature_bytes.len(),
            Signature::BYTE_SIZE
        )));
    }
    let mut sig_arr = [0u8; Signature::BYTE_SIZE];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    // Payload is sha256(content_hash_str) per RFC §4.4.
    let mut hasher = Sha256::new();
    hasher.update(content_hash.as_bytes());
    let payload = hasher.finalize();

    pubkey.verify(&payload, &signature).map_err(|e| {
        AgentError::CapsuleSignatureInvalid(format!(
            "signature does not verify under tier {declared_tier:?} key: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_content_hash(content_hash: &str, key: &SigningKey) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(content_hash.as_bytes());
        let payload = hasher.finalize();
        key.sign(&payload).to_bytes().to_vec()
    }

    fn key_pair() -> (SigningKey, [u8; 32]) {
        // Deterministic for tests — DO NOT use a fixed seed in
        // production; the canonical bundled key is HSM-resident.
        let seed = [0xab; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn verify_roundtrip_bundled() {
        let (sk, pk) = key_pair();
        let registry = StaticKeyRegistry {
            bundled: Some(pk),
            managed: None,
        };
        let content_hash = "sha256:abcdef0123456789".repeat(1) + &"0".repeat(50);
        let sig = sign_content_hash(&content_hash, &sk);
        verify_signature(&content_hash, &sig, SigningTier::Bundled, &registry)
            .expect("good signature verifies");
    }

    #[test]
    fn reject_signature_under_wrong_key() {
        let (sk, _pk) = key_pair();
        // Registry has a DIFFERENT key than the one used to sign.
        let other_pk = SigningKey::from_bytes(&[0xcd; 32]).verifying_key().to_bytes();
        let registry = StaticKeyRegistry {
            bundled: Some(other_pk),
            managed: None,
        };
        let content_hash = "sha256:".to_string() + &"0".repeat(64);
        let sig = sign_content_hash(&content_hash, &sk);
        let err = verify_signature(&content_hash, &sig, SigningTier::Bundled, &registry)
            .expect_err("wrong-key signature rejected");
        assert!(matches!(err, AgentError::CapsuleSignatureInvalid(_)));
    }

    #[test]
    fn reject_bundled_tier_when_no_key_configured() {
        let registry = StaticKeyRegistry {
            bundled: None,
            managed: None,
        };
        let content_hash = "sha256:".to_string() + &"0".repeat(64);
        let sig = vec![0u8; 64];
        let err = verify_signature(&content_hash, &sig, SigningTier::Bundled, &registry)
            .expect_err("missing key rejected as tier mismatch");
        assert!(matches!(err, AgentError::CapsuleSigningTierMismatch(_)));
    }

    #[test]
    fn workspace_tier_returns_tier_mismatch_for_now() {
        // CIT-AGENT-3b stops short of workspace-tier verification
        // (dual-approval flow lives in CIT-AGENT-4).
        let registry = StaticKeyRegistry {
            bundled: None,
            managed: None,
        };
        let content_hash = "sha256:".to_string() + &"0".repeat(64);
        let sig = vec![0u8; 64];
        let err = verify_signature(&content_hash, &sig, SigningTier::Workspace, &registry)
            .expect_err("workspace tier without per-call registry support rejects");
        assert!(matches!(err, AgentError::CapsuleSigningTierMismatch(_)));
    }

    #[test]
    fn reject_wrong_signature_length() {
        let (_sk, pk) = key_pair();
        let registry = StaticKeyRegistry {
            bundled: Some(pk),
            managed: None,
        };
        let content_hash = "sha256:".to_string() + &"0".repeat(64);
        // 32-byte signature is invalid (ed25519 sigs are 64 bytes).
        let sig = vec![0u8; 32];
        let err = verify_signature(&content_hash, &sig, SigningTier::Bundled, &registry)
            .expect_err("short signature rejected");
        assert!(matches!(err, AgentError::CapsuleSignatureInvalid(_)));
    }
}
