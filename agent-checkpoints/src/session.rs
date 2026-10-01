//! Session identifiers. They name a directory and a git ref, so the alphabet is strict.

use std::fmt;

/// An agent session id: 1 to 64 of `A-Z a-z 0-9 _ -`, starting with a letter or digit.
/// Safe as a directory name and as the last component of `refs/citrate/checkpoints/<id>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    pub const MAX_LEN: usize = 64;

    pub fn new(s: &str) -> crate::Result<Self> {
        let ok_char = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
        let valid = !s.is_empty()
            && s.len() <= Self::MAX_LEN
            && s.chars().all(ok_char)
            && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
        if valid {
            Ok(Self(s.to_string()))
        } else {
            Err(crate::Error::InvalidSession(s.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
