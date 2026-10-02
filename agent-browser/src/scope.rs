//! HUP-S5.6: attach-to-Chrome origin scoping.
//!
//! In attach mode Hermes works in a tab of the member's own Chrome, where the member is signed
//! in to things. So:
//! - Every origin needs the member's consent, given per origin and per attach session
//!   ([`OriginScope::allow`]). Consent is never inferred from a page or from the model.
//! - Origins in the sensitive-origins denylist (banking, email, health by default; the data file
//!   is `data/sensitive-origins.toml`) are excluded even with ordinary consent. The member can
//!   include one such origin only by asking for it explicitly (`include_sensitive`), and that
//!   covers that one origin, not its category.
//! - Only `http` and `https` pages have an origin here. `file:`, `chrome:`, `javascript:`,
//!   `data:` and the rest are never in scope.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The default denylist shipped with the crate.
pub const BUILTIN_DENYLIST: &str = include_str!("../data/sensitive-origins.toml");

/// A web origin: scheme, ASCII host, port. Only `http` and `https`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// Parse a URL (or a bare origin) into its origin. Refuses anything that is not an http(s)
    /// URL with a host.
    pub fn parse(input: &str) -> Result<Origin, String> {
        let u = url::Url::parse(input.trim()).map_err(|e| format!("not a web address: {e}"))?;
        let scheme = u.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "only http and https pages can be opened (this is a {scheme}: address)"
            ));
        }
        let host = match u.host() {
            Some(url::Host::Domain(d)) => d.trim_end_matches('.').to_ascii_lowercase(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => format!("[{ip}]"),
            None => return Err("the address has no host".to_string()),
        };
        if host.is_empty() {
            return Err("the address has no host".to_string());
        }
        let port = u
            .port_or_known_default()
            .ok_or_else(|| "the address has no port".to_string())?;
        Ok(Origin { scheme, host, port })
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host, lowercase ASCII (punycode for internationalised names).
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    fn is_ip(&self) -> bool {
        self.host.starts_with('[') || self.host.parse::<std::net::Ipv4Addr>().is_ok()
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default = matches!(
            (self.scheme.as_str(), self.port),
            ("http", 80) | ("https", 443)
        );
        if default {
            write!(f, "{}://{}", self.scheme, self.host)
        } else {
            write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

/// One category of the sensitive-origins denylist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Category {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DenylistFile {
    version: u32,
    #[serde(default)]
    category: Vec<Category>,
}

/// The sensitive-origins denylist (banking, email, health by default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denylist {
    categories: Vec<Category>,
}

impl Denylist {
    /// The shipped list. It is checked by the tests, so a parse failure here is a build defect;
    /// it still fails closed: an unreadable list becomes one catch-all category that marks every
    /// named host sensitive.
    pub fn builtin() -> Denylist {
        Denylist::parse(BUILTIN_DENYLIST).unwrap_or_else(|_| Denylist {
            categories: vec![Category {
                id: "unknown".to_string(),
                label: "Sensitive (the denylist could not be read)".to_string(),
                domains: Vec::new(),
                labels: vec!["*".to_string()],
            }],
        })
    }

    /// Parse a denylist file (TOML, `version = 1`).
    pub fn parse(text: &str) -> Result<Denylist, String> {
        let file: DenylistFile =
            toml::from_str(text).map_err(|e| format!("the denylist is not valid: {e}"))?;
        if file.version != 1 {
            return Err(format!(
                "denylist version {} is not supported (expected 1)",
                file.version
            ));
        }
        let mut categories = Vec::new();
        for mut c in file.category {
            if c.id.trim().is_empty() || c.label.trim().is_empty() {
                return Err("every denylist category needs an id and a label".to_string());
            }
            c.domains = c
                .domains
                .iter()
                .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect();
            c.labels = c
                .labels
                .iter()
                .map(|l| l.trim().to_ascii_lowercase())
                .filter(|l| !l.is_empty())
                .collect();
            categories.push(c);
        }
        Ok(Denylist { categories })
    }

    pub fn categories(&self) -> &[Category] {
        &self.categories
    }

    /// The category an origin falls in, if any. IP-address hosts never match.
    pub fn category_for(&self, origin: &Origin) -> Option<&Category> {
        if origin.is_ip() {
            return None;
        }
        let host = origin.host();
        let host_labels: Vec<&str> = host.split('.').collect();
        self.categories.iter().find(|c| {
            c.domains
                .iter()
                .any(|d| host == d || host.ends_with(&format!(".{d}")))
                || c.labels
                    .iter()
                    .any(|l| l == "*" || host_labels.iter().any(|h| h == l))
        })
    }
}

/// What the scope says about a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeDecision {
    Allowed,
    /// The member has not consented to this origin in this attach session.
    NeedsConsent {
        origin: String,
    },
    /// The origin is on the sensitive-origins denylist and was not explicitly included.
    Sensitive {
        origin: String,
        category: String,
    },
    /// Not an http(s) page.
    NotWeb {
        reason: String,
    },
}

/// Per-attach-session origin consent.
#[derive(Debug, Clone)]
pub struct OriginScope {
    denylist: Denylist,
    allowed: BTreeSet<Origin>,
}

impl OriginScope {
    pub fn new(denylist: Denylist) -> Self {
        OriginScope {
            denylist,
            allowed: BTreeSet::new(),
        }
    }

    pub fn denylist(&self) -> &Denylist {
        &self.denylist
    }

    /// Decide whether a URL may be read or acted on.
    pub fn check(&self, url: &str) -> ScopeDecision {
        let origin = match Origin::parse(url) {
            Ok(o) => o,
            Err(reason) => return ScopeDecision::NotWeb { reason },
        };
        if self.allowed.contains(&origin) {
            return ScopeDecision::Allowed;
        }
        if let Some(c) = self.denylist.category_for(&origin) {
            return ScopeDecision::Sensitive {
                origin: origin.to_string(),
                category: c.id.clone(),
            };
        }
        ScopeDecision::NeedsConsent {
            origin: origin.to_string(),
        }
    }

    /// The member consents to one origin. A sensitive origin also needs `include_sensitive`.
    /// Returns the normalised origin.
    pub fn allow(&mut self, url: &str, include_sensitive: bool) -> Result<String, String> {
        let origin = Origin::parse(url)?;
        if let Some(c) = self.denylist.category_for(&origin) {
            if !include_sensitive {
                return Err(format!(
                    "{origin} is in the excluded category \"{}\"; include it explicitly to allow it",
                    c.label
                ));
            }
        }
        let shown = origin.to_string();
        self.allowed.insert(origin);
        Ok(shown)
    }

    /// Take consent for one origin away. Returns the normalised origin.
    pub fn revoke(&mut self, url: &str) -> Result<String, String> {
        let origin = Origin::parse(url)?;
        let shown = origin.to_string();
        self.allowed.remove(&origin);
        Ok(shown)
    }

    /// Forget every consent (the attach session ended).
    pub fn reset(&mut self) {
        self.allowed.clear();
    }

    /// The consented origins, sorted.
    pub fn allowed(&self) -> Vec<String> {
        self.allowed.iter().map(|o| o.to_string()).collect()
    }
}
