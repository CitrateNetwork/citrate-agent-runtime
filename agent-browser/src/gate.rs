//! The request gate: which requests the browser may send.
//!
//! The worker turns on the DevTools `Fetch` domain for its tab, so the browser pauses requests
//! before they leave it and the worker answers each one (continue or fail):
//!
//! - **Managed** (Hermes's own headless browser): every request is paused. Only public internet
//!   addresses are reached ([`citrate_agent_guard::net::is_public_ip`]); loopback, private,
//!   link-local and reserved addresses and local names (`localhost`, `.local`, `.internal`, single
//!   labels) are refused, so a page, a redirect, a click or a page's own script cannot make the
//!   browser read a service on this machine or the local network. A page load on a named host is
//!   resolved first and refused when any address it resolves to is not public. A developer can
//!   allow named origins (for example a local test chain) with [`ALLOW_PRIVATE_ENV`].
//! - **Attached** (the member's own Chrome): every top-level page load is paused and refused unless
//!   its origin has the member's consent ([`crate::scope`]), so a redirect or a click from a
//!   consented origin never sends a request, with the member's cookies, to another origin.
//!
//! **Off the open web (HUP-S5.5).** When the component updater says the managed browser's security
//! updates are not current (core's `browserMayOpenWeb`, passed as [`OPEN_WEB_ENV`]`=0`), managed
//! mode closes further: no public address either. Only developer-allowed origins that are on this
//! machine (loopback, such as a site preview or an anvil fork) are reached ([`closed_verdict`]).
//!
//! What this pause cannot see (WebSocket handshakes, requests from workers and out-of-process
//! frames, a sub-resource host name that resolves to a local address, a name re-pointed after the
//! check) is held to the same rule in managed mode by the connection-level gate,
//! [`crate::egress`]. In attach mode those are the member's own browser's business: only
//! top-level page loads are scoped. Snapshots read only the main frame.

use std::net::{IpAddr, SocketAddr};

use citrate_agent_guard::net::{is_local_name, is_public_ip};
use serde_json::{json, Value};

use crate::scope::Origin;

/// Developer allow for the managed browser: a comma-separated list of origins it may open even
/// though they are local (for example `http://127.0.0.1:8545`). Unset = none. Pending owner
/// sign-off: the default (none) and whether members should ever see this as a setting.
pub const ALLOW_PRIVATE_ENV: &str = "CITRATE_BROWSER_ALLOW_PRIVATE";

/// HUP-S5.5: whether the managed browser may open the open web. Core sets it from the component
/// updater's freshness (`browserMayOpenWeb`) only when the managed Chromium is in use. Unset or
/// `1` = open (the behaviour before this rule); any other value = closed, so a garbled value
/// fails closed.
pub const OPEN_WEB_ENV: &str = "CITRATE_BROWSER_OPEN_WEB";

/// Read [`OPEN_WEB_ENV`]'s value: `None` (unset) and `"1"` are open, anything else is closed.
pub fn parse_open_web(raw: Option<&str>) -> bool {
    match raw {
        None => true,
        Some(v) => v.trim() == "1",
    }
}

/// What to do with one paused request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Send it.
    Continue,
    /// Fail it before it is sent, for this reason.
    Block(String),
    /// A page load on a named host: resolve the name, then decide with [`resolved_verdict`].
    Resolve { host: String, port: u16 },
}

/// Parse the developer allow list (comma or whitespace separated origins).
pub fn parse_allow_private(raw: &str) -> Result<Vec<Origin>, String> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Origin::parse(s).map_err(|e| format!("{ALLOW_PRIVATE_ENV}: {s:?}: {e}")))
        .collect()
}

/// The reason a local target is refused (shown to the model and the member).
pub fn local_refusal(origin: &str) -> String {
    format!(
        "{origin} is on this machine or the local network; Hermes's browser opens public web addresses only"
    )
}

/// Managed mode: may the browser send a request for `url`? `document` = a page load (top-level or
/// frame), which is worth resolving; other requests are judged by their host as written.
pub fn managed_verdict(url: &str, allow: &[Origin], document: bool) -> Verdict {
    let Ok(u) = url::Url::parse(url) else {
        return Verdict::Block("the request address could not be read".to_string());
    };
    if u.scheme() != "http" && u.scheme() != "https" {
        // data:, blob:, about: and the like never leave the browser as network requests here.
        return Verdict::Continue;
    }
    let Ok(origin) = Origin::parse(url) else {
        return Verdict::Block("the request address has no host".to_string());
    };
    if allow.contains(&origin) {
        return Verdict::Continue;
    }
    let ip = match u.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        Some(url::Host::Domain(_)) => None,
        None => return Verdict::Block("the request address has no host".to_string()),
    };
    match ip {
        Some(ip) if is_public_ip(ip) => Verdict::Continue,
        Some(_) => Verdict::Block(local_refusal(&origin.to_string())),
        None if is_local_name(origin.host()) => Verdict::Block(local_refusal(&origin.to_string())),
        None if document => Verdict::Resolve {
            host: origin.host().to_string(),
            port: origin.port(),
        },
        None => Verdict::Continue,
    }
}

/// The reason a target is refused while the managed browser is kept off the open web.
pub fn closed_refusal(origin: &str) -> String {
    format!(
        "{origin} is not opened: Hermes's browser is kept off the open web because its security updates are not current (the component updater has no current signed manifest). Pages on this machine that a developer allowed still open."
    )
}

/// Is `host` (as an [`Origin`] writes it) this machine: `localhost`, or a loopback IP literal
/// (an IPv4-mapped IPv6 address counts as the IPv4 address inside it)?
pub fn is_loopback_host(host: &str) -> bool {
    let h = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    if h.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => is_loopback_ip(ip),
        Err(_) => false,
    }
}

/// A loopback address, looking inside IPv4-mapped IPv6 addresses.
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// HUP-S5.5, managed mode while the browser is kept off the open web: only developer-allowed
/// origins on this machine are reached. Public addresses, the local network, and loopback
/// origins nobody allowed are all refused. Names are judged as written here (only `localhost`
/// can pass); the connection-level gate ([`crate::egress`]) checks what a name resolves to.
pub fn closed_verdict(url: &str, allow: &[Origin]) -> Verdict {
    let Ok(u) = url::Url::parse(url) else {
        return Verdict::Block("the request address could not be read".to_string());
    };
    if u.scheme() != "http" && u.scheme() != "https" {
        // data:, blob:, about: and the like never leave the browser as network requests here.
        return Verdict::Continue;
    }
    let Ok(origin) = Origin::parse(url) else {
        return Verdict::Block("the request address has no host".to_string());
    };
    if allow.contains(&origin) && is_loopback_host(origin.host()) {
        Verdict::Continue
    } else {
        Verdict::Block(closed_refusal(&origin.to_string()))
    }
}

/// The managed-mode verdict under the open-web rule: [`managed_verdict`] when the browser may
/// open the web, [`closed_verdict`] when it may not.
pub fn managed_verdict_for(url: &str, allow: &[Origin], document: bool, open_web: bool) -> Verdict {
    if open_web {
        managed_verdict(url, allow, document)
    } else {
        closed_verdict(url, allow)
    }
}

/// Decide a [`Verdict::Resolve`] from the addresses the name resolved to: every one must be
/// public (or an allowed origin's address and port). No address = refused.
pub fn resolved_verdict(addrs: &[SocketAddr], allow: &[Origin]) -> Verdict {
    if addrs.is_empty() {
        return Verdict::Block("the host name did not resolve".to_string());
    }
    let allowed_literal = |a: &SocketAddr| {
        allow.iter().any(|o| {
            o.port() == a.port()
                && o.host().trim_start_matches('[').trim_end_matches(']') == a.ip().to_string()
        })
    };
    if addrs
        .iter()
        .all(|a| is_public_ip(a.ip()) || allowed_literal(a))
    {
        Verdict::Continue
    } else {
        Verdict::Block(
            "the host name resolves to an address on this machine or the local network; Hermes's browser opens public web addresses only"
                .to_string(),
        )
    }
}

/// Resolve `host:port` (blocking) and decide.
pub fn resolve_and_decide(host: &str, port: u16, allow: &[Origin]) -> Verdict {
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(_) => Vec::new(),
    };
    resolved_verdict(&addrs, allow)
}

/// The `Fetch.enable` patterns: every request in managed mode, page loads in attach mode.
pub fn fetch_patterns(attached: bool) -> Value {
    if attached {
        json!([{"urlPattern": "*", "resourceType": "Document", "requestStage": "Request"}])
    } else {
        json!([{"urlPattern": "*", "requestStage": "Request"}])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_request_address_is_refused() {
        assert!(matches!(
            managed_verdict("http://", &[], true),
            Verdict::Block(_)
        ));
    }
}
