//! Single error enum for the cit-agent core library.
//!
//! Reference: RFC-CIT-AGENT-0001 §3.2. The error surface is expanded
//! per-subsystem in CIT-AGENT-2..7 as each module gains content.

use std::fmt;

#[derive(Debug)]
pub enum AgentError {
    /// Underlying RPC / chain client failure (recorder, anchor writes).
    Chain(String),
    /// HITL queue lifecycle (timeout, rejection, lock poisoning).
    Hitl(String),
    /// Audit-chain integrity failure (broken hash chain, signature
    /// verification failed, retention policy violation).
    Audit(String),
    /// Policy-bundle parse or signature failure.
    Policy(String),
    /// Capsule-archive verify / load / instantiate failure.
    Capsule(String),
    /// RFC §4.5 invariant 1 — signature does not verify against the
    /// trusted publisher key for the declared tier. CIT-AGENT-3b.
    CapsuleSignatureInvalid(String),
    /// RFC §4.5 invariant 1 (sub-case) — declared signing tier doesn't
    /// match the actual signature chain (e.g. `tier = "bundled"`
    /// signed by a non-canonical key). CIT-AGENT-3b.
    CapsuleSigningTierMismatch(String),
    /// RFC §4.5 invariant 2 — WIT imports don't match the manifest's
    /// declared capability set. CIT-AGENT-3b.
    CapsuleWitMismatch(String),
    /// Model-resolver discovery / load failure.
    Model(String),
    /// Doctor check failure surfaced as BLOCKER.
    Doctor(String),
    /// Wrap a general error from a dependency.
    Other(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Chain(m) => write!(f, "chain: {m}"),
            AgentError::Hitl(m) => write!(f, "hitl: {m}"),
            AgentError::Audit(m) => write!(f, "audit: {m}"),
            AgentError::Policy(m) => write!(f, "policy: {m}"),
            AgentError::Capsule(m) => write!(f, "capsule: {m}"),
            AgentError::CapsuleSignatureInvalid(m) => write!(f, "capsule signature invalid: {m}"),
            AgentError::CapsuleSigningTierMismatch(m) => {
                write!(f, "capsule signing tier mismatch: {m}")
            }
            AgentError::CapsuleWitMismatch(m) => write!(f, "capsule WIT mismatch: {m}"),
            AgentError::Model(m) => write!(f, "model: {m}"),
            AgentError::Doctor(m) => write!(f, "doctor: {m}"),
            AgentError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for AgentError {}
