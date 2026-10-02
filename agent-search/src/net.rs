//! Target policy: which URLs `read_url` may fetch and which addresses it may connect to.

use crate::SearchError;
use reqwest::Url;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// The Jina Reader endpoint used when the member opts in without naming another.
pub const JINA_DEFAULT_ENDPOINT: &str = "https://r.jina.ai/";

pub use citrate_agent_guard::net::is_public_ip;

/// Parse an absolute http(s) URL with a host and no credentials.
pub(crate) fn parse_target(raw: &str) -> Result<Url, SearchError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(SearchError::InvalidUrl("empty".into()));
    }
    let url = Url::parse(raw).map_err(|_| SearchError::InvalidUrl("not an absolute URL".into()))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(SearchError::InvalidUrl(
            "only http and https URLs are read".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SearchError::InvalidUrl(
            "URLs with credentials are not read".into(),
        ));
    }
    if url.host().is_none() {
        return Err(SearchError::InvalidUrl("no host".into()));
    }
    Ok(url)
}

fn literal_ip(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        url::Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        url::Host::Domain(_) => None,
    }
}

fn allowed(ip: IpAddr, allow_private: &[IpAddr]) -> bool {
    is_public_ip(ip) || allow_private.contains(&ip)
}

/// Names that never denote a public host, whatever DNS says.
fn local_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h.ends_with(".home.arpa")
        || !h.contains('.')
}

/// Check a target without resolving it: literal addresses and local names only. Used for a target
/// that a third party (the opted-in reader) fetches, not this process.
pub(crate) fn check_target_static(url: &Url, allow_private: &[IpAddr]) -> Result<(), SearchError> {
    if let Some(ip) = literal_ip(url) {
        return if allowed(ip, allow_private) {
            Ok(())
        } else {
            Err(SearchError::Blocked(
                "the address is not on the public internet".into(),
            ))
        };
    }
    match url.host_str() {
        Some(h) if local_name(h) => Err(SearchError::Blocked(
            "the host name is local, not on the public internet".into(),
        )),
        Some(_) => Ok(()),
        None => Err(SearchError::InvalidUrl("no host".into())),
    }
}

/// Resolve a target and return the single address to connect to. Every resolved address must be
/// allowed (a name that maps to any non-public address is refused), so DNS answers cannot mix a
/// private address in.
pub(crate) fn resolve_checked(
    url: &Url,
    allow_private: &[IpAddr],
) -> Result<SocketAddr, SearchError> {
    let port = url
        .port_or_known_default()
        .ok_or_else(|| SearchError::InvalidUrl("no port".into()))?;
    if let Some(ip) = literal_ip(url) {
        return if allowed(ip, allow_private) {
            Ok(SocketAddr::new(ip, port))
        } else {
            Err(SearchError::Blocked(
                "the address is not on the public internet".into(),
            ))
        };
    }
    let host = url
        .host_str()
        .ok_or_else(|| SearchError::InvalidUrl("no host".into()))?;
    if local_name(host) {
        return Err(SearchError::Blocked(
            "the host name is local, not on the public internet".into(),
        ));
    }
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| SearchError::Network("the host name did not resolve".into()))?
        .collect();
    let first = *addrs
        .first()
        .ok_or_else(|| SearchError::Network("the host name did not resolve".into()))?;
    if addrs.iter().any(|a| !allowed(a.ip(), allow_private)) {
        return Err(SearchError::Blocked(
            "the host name resolves to an address that is not on the public internet".into(),
        ));
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_and_non_public_ranges() {
        for p in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
            assert!(is_public_ip(p.parse().unwrap()), "{p}");
        }
        for n in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.1.2.3",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "::1",
            "::",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "::127.0.0.1",
        ] {
            assert!(!is_public_ip(n.parse().unwrap()), "{n}");
        }
        assert!(is_public_ip("::ffff:1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("64:ff9b::808:808".parse().unwrap()));
        assert!(is_public_ip("100.128.0.1".parse().unwrap()));
    }

    /// 6to4 (2002::/16) and Teredo (2001::/32) carry an IPv4 address inside the IPv6 one; the
    /// embedded address decides, so a tunnelled loopback or private address is not public.
    #[test]
    fn tunnelled_ipv4_addresses_are_judged_by_the_embedded_address() {
        for n in [
            "2002:7f00:1::1",            // 6to4 of 127.0.0.1
            "2002:a00:1::",              // 6to4 of 10.0.0.1
            "2002:c0a8:101::1",          // 6to4 of 192.168.1.1
            "2002:a9fe:a9fe::1",         // 6to4 of 169.254.169.254
            "2001:0:4136:e378:8000:63bf:80ff:fffe", // Teredo, client 127.0.0.1
            "2001:0:4136:e378:8000:63bf:f5ff:fffe", // Teredo, client 10.0.0.1
            "2001:0:a00:1:8000:63bf:f7f7:f7f7",     // Teredo, server 10.0.0.1
        ] {
            assert!(!is_public_ip(n.parse().unwrap()), "{n}");
        }
        // Public on both ends stays public.
        assert!(is_public_ip("2002:101:101::1".parse().unwrap())); // 6to4 of 1.1.1.1
        assert!(is_public_ip(
            "2001:0:4136:e378:8000:63bf:f7f7:f7f7".parse().unwrap() // client 8.8.8.8
        ));
    }

    #[test]
    fn local_names_are_refused_without_dns() {
        for h in [
            "http://localhost/",
            "http://LOCALHOST./x",
            "http://printer.local/",
            "http://db.internal/",
            "http://intranet/",
            "http://a.localhost/",
        ] {
            let u = parse_target(h).unwrap();
            assert!(
                matches!(resolve_checked(&u, &[]), Err(SearchError::Blocked(_))),
                "{h}"
            );
            assert!(matches!(
                check_target_static(&u, &[]),
                Err(SearchError::Blocked(_))
            ));
        }
    }

    #[test]
    fn allowlisted_private_literals_pass() {
        let u = parse_target("http://127.0.0.1:9/").unwrap();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_checked(&u, &[lo]).unwrap(),
            "127.0.0.1:9".parse().unwrap()
        );
        assert!(resolve_checked(&u, &[]).is_err());
    }
}
