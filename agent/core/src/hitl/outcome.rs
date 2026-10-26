//! C1-V3-R — an approved chain effect whose transaction was submitted but whose outcome is unknown.
//!
//! Data source (Rule 7): citrate-core's signature ceremony. When the member approved an effect and
//! core broadcast it but could not learn the result (C1-V3, `hermes_resolve_outcome_unknown`),
//! core releases the effect through the sidecar's approve route with
//! `{outcome: "submitted_outcome_unknown", txHash, message}`. The submitter is then told exactly
//! that message, never success, and an identical re-proposal must reference the earlier
//! transaction instead of being sent again unattended.

/// The wire value of `outcome` on the approve route for a submitted, unknown-outcome effect.
pub const OUTCOME_SUBMITTED_UNKNOWN: &str = "submitted_outcome_unknown";

/// The longest message accepted, in bytes. Core's words with a hash are about 100 bytes.
pub const MAX_OUTCOME_MESSAGE: usize = 280;

/// How many unknown-outcome call ids the queue remembers for re-proposals (oldest dropped first).
pub const REMEMBERED_UNKNOWN_OUTCOMES: usize = 256;

/// True for `0x` followed by exactly 64 hex digits.
pub fn is_tx_hash(s: &str) -> bool {
    s.strip_prefix("0x")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The words used when core sent an outcome without its own message (the same words core uses).
fn default_message(tx_hash: Option<&str>) -> String {
    match tx_hash {
        Some(h) => format!("submitted, outcome unknown, tx {h}, check before retrying"),
        None => "submitted, outcome unknown, check recent transactions before retrying".to_string(),
    }
}

/// A submitted transaction with no known outcome: its hash when core had one, and the message the
/// submitter (a capsule, through its tool result) must be given. Built only through [`Self::new`],
/// so every value is validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownOutcome {
    tx_hash: Option<String>,
    message: String,
}

impl UnknownOutcome {
    /// Validate core's fields. `tx_hash` must be `0x` + 64 hex digits when present. `message`
    /// (core's words; `None` composes the same words here) must be non-empty, at most
    /// [`MAX_OUTCOME_MESSAGE`] bytes, free of control characters, and must name the hash when
    /// there is one, so the submitter is always told which transaction to check.
    pub fn new(tx_hash: Option<&str>, message: Option<&str>) -> Result<Self, String> {
        if let Some(h) = tx_hash {
            if !is_tx_hash(h) {
                return Err("txHash must be 0x followed by 64 hex digits".to_string());
            }
        }
        let message = match message {
            Some(m) => m.to_string(),
            None => default_message(tx_hash),
        };
        if message.trim().is_empty() {
            return Err("message must not be empty".to_string());
        }
        if message.len() > MAX_OUTCOME_MESSAGE {
            return Err(format!(
                "message must be at most {MAX_OUTCOME_MESSAGE} bytes"
            ));
        }
        if message.chars().any(char::is_control) {
            return Err("message must not contain control characters".to_string());
        }
        if let Some(h) = tx_hash {
            if !message.contains(h) {
                return Err("message must name the transaction hash".to_string());
            }
        }
        Ok(Self {
            tx_hash: tx_hash.map(str::to_string),
            message,
        })
    }

    /// The submitted transaction's hash, when core had one.
    pub fn tx_hash(&self) -> Option<&str> {
        self.tx_hash.as_deref()
    }

    /// The words the submitter must be given, exactly as core sent them.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The decision record's outcome detail: "Submitted · outcome unknown (tx <hash>)".
    pub fn record_detail(&self) -> String {
        format!(
            "Submitted · outcome unknown (tx {})",
            self.tx_hash.as_deref().unwrap_or("not known")
        )
    }

    /// The note an identical re-proposal's approval card carries.
    pub fn reproposal_note(&self) -> String {
        format!(
            "an earlier identical request was submitted, outcome unknown (tx {}); check it before approving again",
            self.tx_hash.as_deref().unwrap_or("not known")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0x8f3c2a1b9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8";

    #[test]
    fn core_words_with_a_hash_are_accepted_verbatim() {
        let m = format!("submitted, outcome unknown, tx {HASH}, check before retrying");
        let u = UnknownOutcome::new(Some(HASH), Some(&m)).unwrap();
        assert_eq!(u.message(), m);
        assert_eq!(u.tx_hash(), Some(HASH));
        assert_eq!(
            u.record_detail(),
            format!("Submitted · outcome unknown (tx {HASH})")
        );
        assert!(u.reproposal_note().contains(HASH));
    }

    #[test]
    fn a_missing_message_gets_cores_words() {
        let u = UnknownOutcome::new(Some(HASH), None).unwrap();
        assert_eq!(
            u.message(),
            format!("submitted, outcome unknown, tx {HASH}, check before retrying")
        );
        let none = UnknownOutcome::new(None, None).unwrap();
        assert_eq!(
            none.message(),
            "submitted, outcome unknown, check recent transactions before retrying"
        );
        assert_eq!(
            none.record_detail(),
            "Submitted · outcome unknown (tx not known)"
        );
    }

    #[test]
    fn tx_hashes_are_0x_and_64_hex_digits() {
        assert!(is_tx_hash(HASH));
        assert!(is_tx_hash(&HASH.to_uppercase().replacen("0X", "0x", 1)));
        for bad in [
            "",
            "0x",
            &HASH[2..],
            &format!("{HASH}00"),
            &HASH.replace('a', "g"),
        ] {
            assert!(!is_tx_hash(bad), "{bad:?}");
            assert!(
                UnknownOutcome::new(Some(bad), Some("m")).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn messages_are_bounded_and_must_name_the_hash() {
        let ok = format!("submitted, outcome unknown, tx {HASH}, check before retrying");
        let long = format!("{ok}{}", "x".repeat(MAX_OUTCOME_MESSAGE));
        assert!(UnknownOutcome::new(Some(HASH), Some(&long)).is_err());
        let exact = format!("{ok}{}", "x".repeat(MAX_OUTCOME_MESSAGE - ok.len()));
        assert!(UnknownOutcome::new(Some(HASH), Some(&exact)).is_ok());
        assert!(UnknownOutcome::new(Some(HASH), Some("")).is_err());
        assert!(UnknownOutcome::new(Some(HASH), Some("   ")).is_err());
        assert!(UnknownOutcome::new(Some(HASH), Some(&format!("{ok}\n"))).is_err());
        assert!(UnknownOutcome::new(Some(HASH), Some("submitted, outcome unknown")).is_err());
        assert!(UnknownOutcome::new(None, Some("submitted, outcome unknown")).is_ok());
    }
}
