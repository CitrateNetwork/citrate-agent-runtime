//! Address classes: which IP addresses are on the public internet.
//!
//! One predicate, [`is_public_ip`], shared by every agent surface that decides whether a network
//! target is reachable without the member's say-so: `read_url` (agent-search), the managed
//! browser (agent-browser) and capsule egress allowlists (agent/core). Loopback, private,
//! link-local, shared (CGNAT), documentation, benchmarking, multicast, broadcast and reserved
//! ranges are not public, and neither is an IPv6 address that only wraps one of them: IPv4-mapped
//! and IPv4-compatible forms, NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) and Teredo
//! (`2001::/32`, never public: its endpoint sits behind a relay). Only IPv6 global unicast
//! (`2000::/3`) outside the documentation, benchmarking and ORCHID blocks is public.

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
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 6to4 relay anycast
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
    // Teredo (2001:0::/32): the real endpoint sits behind a relay, so it is never public.
    if s[0] == 0x2001 && s[1] == 0 {
        return false;
    }
    // Only global unicast (2000::/3) can be public; that leaves out unique local, link local,
    // site local, multicast, discard-only (100::/64), ::/96 and the reserved remainder.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        && !(s[0] == 0x3fff && (s[1] & 0xf000) == 0) // 3fff::/20 documentation
        && !(s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0) // 2001:2::/48 benchmarking
        && !(s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010) // 2001:10::/28 ORCHID
        && !(s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020) // 2001:20::/28 ORCHIDv2
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
