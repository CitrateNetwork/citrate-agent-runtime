//! The two principals the command plane distinguishes. There is no third: you are
//! the owner or you are not, and "not" is the default (fail-closed).

/// Who the ingress guard decided an actor is. Authorization is binary and
/// fail-closed — anything that is not provably the owner is [`Principal::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The single configured `OWNER_DISCORD_ID`, authenticated by immutable user id.
    Owner,
    /// Everyone and everything else (the default).
    Other,
}
