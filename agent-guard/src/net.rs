//! Address classes: which IP addresses are on the public internet.
//!
//! One predicate, [`is_public_ip`], shared by every agent surface that decides whether a network
//! target is reachable without the member's say-so: `read_url` (agent-search), the managed
//! browser (agent-browser) and capsule egress allowlists (agent/core). Loopback, private,
//! link-local, shared (CGNAT), documentation, benchmarking, multicast, broadcast and reserved
//! ranges are not public, and neither is an IPv6 address that only wraps one of them: IPv4-mapped
//! and IPv4-compatible forms, NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) and Teredo
//! (`2001::/32`, judged by both its server and its client address).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_public(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 shared address space
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // 240.0.0.0/4 reserved
}

fn v4_from(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

fn v6_public(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_public(v4);
    }
    let s = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 address.
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return v4_public(v4_from(s[6], s[7]));
    }
    // 6to4 (2002::/16): the next 32 bits are the IPv4 address the tunnel ends at.
    if s[0] == 0x2002 {
        return v4_public(v4_from(s[1], s[2]));
    }
    // Teredo (2001:0::/32): the server's IPv4 address, then the client's, bit-inverted.
    if s[0] == 0x2001 && s[1] == 0 {
        return v4_public(v4_from(s[2], s[3])) && v4_public(v4_from(!s[6], !s[7]));
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
        || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0))
    // ::/96 IPv4-compatible
}

/// True for an address on the public internet.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_public(v4),
        IpAddr::V6(v6) => v6_public(v6),
    }
}

/// Host names that never denote a public host, whatever DNS says: `localhost` and its
/// subdomains, `.local` (mDNS), `.internal`, `.home.arpa`, and single-label names.
pub fn is_local_name(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal")
        || h.ends_with(".home.arpa")
        || !h.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        match s.parse() {
            Ok(i) => i,
            Err(e) => panic!("{s}: {e}"),
        }
    }

    #[test]
    fn the_embedded_address_decides_for_every_wrapping() {
        for (wrapped, public) in [
            ("::ffff:127.0.0.1", false),
            ("::ffff:1.1.1.1", true),
            ("64:ff9b::a00:1", false),
            ("64:ff9b::808:808", true),
            ("2002:a9fe:a9fe::", false),
            ("2002:808:808::", true),
            ("2001:0:808:808:0:0:f5ff:fffe", false),
            // Teredo hides the real endpoint behind a relay: never public, whatever it carries.
            ("2001:0:808:808:0:0:f7f7:f7f7", false),
        ] {
            assert_eq!(is_public_ip(ip(wrapped)), public, "{wrapped}");
        }
    }

    /// Only global unicast is public: the 6to4 relay anycast block, IPv6 outside 2000::/3
    /// (reserved, discard-only, deprecated site-local) and the 3fff::/20 documentation block are not.
    #[test]
    fn reserved_and_relay_ranges_are_not_public() {
        for (addr, public) in [
            ("192.88.99.1", false),    // 6to4 relay anycast
            ("100::1", false),         // discard-only
            ("4000::1", false),        // reserved, outside 2000::/3
            ("8000::1", false),        // reserved
            ("3fff::1", false),        // documentation (RFC 9637)
            ("2001:2::1", false),      // benchmarking
            ("2001:10::1", false),     // ORCHID
            ("2606:4700::1111", true), // global unicast
            ("2a00:1450:4001::1", true),
        ] {
            assert_eq!(is_public_ip(ip(addr)), public, "{addr}");
        }
    }
}
