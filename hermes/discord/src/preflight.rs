//! The `doctor` preflight (WP-S1.2): the daemon refuses to accept traffic until the
//! security-critical config is valid. A fail-closed guard that recognizes no one is
//! *safe* but useless — better to refuse to start and say exactly why.

use hermes_core::guard::OwnerAuth;

/// A reason the daemon must not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightError {
    /// `DISCORD_BOT_TOKEN` was empty/absent.
    MissingToken,
    /// `OWNER_DISCORD_ID` was unset or malformed — the command plane would serve no one.
    OwnerNotConfigured,
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::MissingToken => {
                write!(f, "DISCORD_BOT_TOKEN is empty — set it (source .env.hermes)")
            }
            PreflightError::OwnerNotConfigured => write!(
                f,
                "OWNER_DISCORD_ID is unset or invalid — refusing to start (fail-closed): \
                 with no owner configured the command plane would serve no one"
            ),
        }
    }
}

impl std::error::Error for PreflightError {}

/// Validate the security-critical config before connecting. Token must be present and an
/// owner must be configured; otherwise the daemon does not start.
pub fn preflight(token: &str, auth: &OwnerAuth) -> Result<(), PreflightError> {
    if token.trim().is_empty() {
        return Err(PreflightError::MissingToken);
    }
    if !auth.is_configured() {
        return Err(PreflightError::OwnerNotConfigured);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_token() {
        let auth = OwnerAuth::new(877642945996673126);
        assert_eq!(preflight("", &auth), Err(PreflightError::MissingToken));
        assert_eq!(preflight("   ", &auth), Err(PreflightError::MissingToken));
    }

    #[test]
    fn rejects_unconfigured_owner() {
        let auth = OwnerAuth::from_config(None);
        assert_eq!(preflight("a.valid.token", &auth), Err(PreflightError::OwnerNotConfigured));
        let bad = OwnerAuth::from_config(Some("not-a-number"));
        assert_eq!(preflight("a.valid.token", &bad), Err(PreflightError::OwnerNotConfigured));
    }

    #[test]
    fn accepts_valid_config() {
        let auth = OwnerAuth::from_config(Some("877642945996673126"));
        assert_eq!(preflight("a.valid.token", &auth), Ok(()));
    }
}
