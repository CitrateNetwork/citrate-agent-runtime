//! The managed browser's network gate: every connection Hermes's own Chromium makes goes through
//! this loopback SOCKS5 relay, which connects only to public internet addresses
//! ([`citrate_agent_guard::net::is_public_ip`]) and to origins a developer allowed
//! ([`crate::gate::ALLOW_PRIVATE_ENV`]).
//!
//! The DevTools request pause ([`crate::gate`]) sees page requests only. This gate sits below it,
//! at the connection level, so it also covers what that pause misses: WebSocket handshakes,
//! requests from workers and out-of-process frames, and host names that resolve to a local
//! address. Names are resolved here (Chromium hands SOCKS5 proxies the host name), every address
//! a name resolves to must be public, and the relay connects to the address it checked, so a name
//! cannot be re-pointed at this machine between the check and the connection.
//!
//! **Off the open web (HUP-S5.5).** A gate started with `open_web = false` ([`EgressGate::start_with`])
//! relays to developer-allowed origins on this machine only: an allowed IP literal must be
//! loopback, and an allowed name must resolve to loopback addresses only. Public addresses are
//! refused like local ones.
//!
//! Only unauthenticated `CONNECT` (RFC 1928) is spoken. The relay listens on 127.0.0.1 only, and
//! reaches nothing a local process could not already reach, so it grants no new access.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use citrate_agent_guard::net::{is_local_name, is_public_ip};

use crate::gate::is_loopback_ip;
use crate::scope::Origin;

/// How long a client has to finish the SOCKS5 handshake, and how long a connection attempt to a
/// target may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Connections relayed at once; more are refused (a page cannot exhaust the sidecar's threads).
pub const MAX_RELAYS: usize = 256;

const REPLY_OK: u8 = 0;
const REPLY_FAILURE: u8 = 1;
const REPLY_NOT_ALLOWED: u8 = 2;
const REPLY_HOST_UNREACHABLE: u8 = 4;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;
const REPLY_ADDRESS_NOT_SUPPORTED: u8 = 8;

/// A running gate. Dropping it stops the listener; relays already open end with their peers.
pub struct EgressGate {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl EgressGate {
    /// Listen on a free loopback port and relay for `allow` (developer-allowed local origins),
    /// with the open web reachable.
    pub fn start(allow: Vec<Origin>) -> io::Result<EgressGate> {
        EgressGate::start_with(allow, true)
    }

    /// [`EgressGate::start`] under the open-web rule: with `open_web = false` only allowed
    /// origins on this machine are relayed (HUP-S5.5).
    pub fn start_with(allow: Vec<Origin>, open_web: bool) -> io::Result<EgressGate> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let allow = Arc::new(allow);
        let live = Arc::new(AtomicUsize::new(0));
        std::thread::Builder::new()
            .name("citrate-browser-egress".to_string())
            .spawn(move || {
                for conn in listener.incoming() {
                    if stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(client) = conn else { continue };
                    if live.fetch_add(1, Ordering::SeqCst) >= MAX_RELAYS {
                        live.fetch_sub(1, Ordering::SeqCst);
                        let _ = client.shutdown(Shutdown::Both);
                        continue;
                    }
                    let allow = allow.clone();
                    let done = live.clone();
                    let spawned = std::thread::Builder::new()
                        .name("citrate-browser-relay".to_string())
                        .spawn(move || {
                            let _ = serve(client, &allow, open_web);
                            done.fetch_sub(1, Ordering::SeqCst);
                        });
                    if spawned.is_err() {
                        live.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            })?;
        Ok(EgressGate { addr, stop })
    }

    /// The loopback address the gate listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The Chromium flags that send every connection through this gate: the proxy itself, no
    /// implicit loopback bypass, and no WebRTC UDP outside the proxy.
    pub fn browser_args(&self) -> Vec<String> {
        vec![
            format!("--proxy-server=socks5://{}", self.addr),
            "--proxy-bypass-list=<-loopback>".to_string(),
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
        ]
    }
}

impl Drop for EgressGate {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the stop flag.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

/// The target a client asked for.
enum Target {
    Ip(IpAddr),
    Name(String),
}

/// May the gate connect to `addr` for a request that named `host`? Allowed origins match by the
/// host as the browser wrote it (an IP literal or a name) and the port.
fn allowed_origin(allow: &[Origin], host: &str, port: u16) -> bool {
    let host = host.trim_end_matches('.');
    allow.iter().any(|o| {
        o.port() == port
            && o.host()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .eq_ignore_ascii_case(host)
    })
}

/// Resolve and judge a target: the addresses to try, or the SOCKS5 reply code refusing it.
fn decide(
    target: &Target,
    port: u16,
    allow: &[Origin],
    open_web: bool,
) -> Result<Vec<SocketAddr>, u8> {
    if !open_web {
        return decide_closed(target, port, allow);
    }
    match target {
        Target::Ip(ip) => {
            if allowed_origin(allow, &ip.to_string(), port) || is_public_ip(*ip) {
                Ok(vec![SocketAddr::new(*ip, port)])
            } else {
                Err(REPLY_NOT_ALLOWED)
            }
        }
        Target::Name(name) => {
            let allowed = allowed_origin(allow, name, port);
            if !allowed && is_local_name(name) {
                return Err(REPLY_NOT_ALLOWED);
            }
            use std::net::ToSocketAddrs;
            let addrs: Vec<SocketAddr> = (name.as_str(), port)
                .to_socket_addrs()
                .map_err(|_| REPLY_HOST_UNREACHABLE)?
                .collect();
            if addrs.is_empty() {
                return Err(REPLY_HOST_UNREACHABLE);
            }
            if !allowed && !addrs.iter().all(|a| is_public_ip(a.ip())) {
                return Err(REPLY_NOT_ALLOWED);
            }
            Ok(addrs)
        }
    }
}

/// Off the open web: an allowed origin on this machine, or nothing.
fn decide_closed(target: &Target, port: u16, allow: &[Origin]) -> Result<Vec<SocketAddr>, u8> {
    match target {
        Target::Ip(ip) => {
            if allowed_origin(allow, &ip.to_string(), port) && is_loopback_ip(*ip) {
                Ok(vec![SocketAddr::new(*ip, port)])
            } else {
                Err(REPLY_NOT_ALLOWED)
            }
        }
        Target::Name(name) => {
            if !allowed_origin(allow, name, port) {
                return Err(REPLY_NOT_ALLOWED);
            }
            use std::net::ToSocketAddrs;
            let addrs: Vec<SocketAddr> = (name.as_str(), port)
                .to_socket_addrs()
                .map_err(|_| REPLY_HOST_UNREACHABLE)?
                .collect();
            if addrs.is_empty() {
                return Err(REPLY_HOST_UNREACHABLE);
            }
            if !addrs.iter().all(|a| is_loopback_ip(a.ip())) {
                return Err(REPLY_NOT_ALLOWED);
            }
            Ok(addrs)
        }
    }
}

fn reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
}

/// One client connection: the SOCKS5 handshake, the decision, then the relay.
fn serve(mut client: TcpStream, allow: &[Origin], open_web: bool) -> io::Result<()> {
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut head = [0u8; 2];
    client.read_exact(&mut head)?;
    if head[0] != 5 {
        return client.shutdown(Shutdown::Both);
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff])?;
        return client.shutdown(Shutdown::Both);
    }
    client.write_all(&[5, 0])?;

    let mut req = [0u8; 4];
    client.read_exact(&mut req)?;
    if req[0] != 5 {
        return client.shutdown(Shutdown::Both);
    }
    if req[1] != 1 {
        reply(&mut client, REPLY_COMMAND_NOT_SUPPORTED)?;
        return client.shutdown(Shutdown::Both);
    }
    let target = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            client.read_exact(&mut b)?;
            Target::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        4 => {
            let mut b = [0u8; 16];
            client.read_exact(&mut b)?;
            Target::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name)?;
            match String::from_utf8(name) {
                Ok(n) if !n.is_empty() => match n.parse::<IpAddr>() {
                    Ok(ip) => Target::Ip(ip),
                    Err(_) => Target::Name(n),
                },
                _ => {
                    reply(&mut client, REPLY_ADDRESS_NOT_SUPPORTED)?;
                    return client.shutdown(Shutdown::Both);
                }
            }
        }
        _ => {
            reply(&mut client, REPLY_ADDRESS_NOT_SUPPORTED)?;
            return client.shutdown(Shutdown::Both);
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);

    let addrs = match decide(&target, port, allow, open_web) {
        Ok(a) => a,
        Err(code) => {
            reply(&mut client, code)?;
            return client.shutdown(Shutdown::Both);
        }
    };
    // Connect to an address that was checked, never to the name again.
    let upstream = addrs
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, CONNECT_TIMEOUT).ok());
    let Some(upstream) = upstream else {
        reply(&mut client, REPLY_FAILURE)?;
        return client.shutdown(Shutdown::Both);
    };
    reply(&mut client, REPLY_OK)?;
    client.set_read_timeout(None)?;
    relay(client, upstream)
}

/// Copy bytes both ways until either side closes.
fn relay(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let mut c_read = client.try_clone()?;
    let mut u_write = upstream.try_clone()?;
    let up = std::thread::Builder::new()
        .name("citrate-browser-relay-up".to_string())
        .spawn(move || {
            let _ = io::copy(&mut c_read, &mut u_write);
            let _ = u_write.shutdown(Shutdown::Write);
        })?;
    let mut u_read = upstream;
    let mut c_write = client;
    let _ = io::copy(&mut u_read, &mut c_write);
    let _ = c_write.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_origins_match_host_and_port_only() {
        let allow = crate::gate::parse_allow_private("http://127.0.0.1:8545, http://[::1]:9000")
            .expect("allow");
        assert!(allowed_origin(&allow, "127.0.0.1", 8545));
        assert!(allowed_origin(&allow, "::1", 9000));
        assert!(!allowed_origin(&allow, "127.0.0.1", 8546));
        assert!(!allowed_origin(&allow, "127.0.0.2", 8545));
    }

    #[test]
    fn public_literals_pass_and_local_ones_do_not() {
        let ok = decide(&Target::Ip("1.1.1.1".parse().expect("ip")), 443, &[], true);
        assert_eq!(ok, Ok(vec!["1.1.1.1:443".parse().expect("addr")]));
        for bad in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fd00::1"] {
            let ip: IpAddr = bad.parse().expect("ip");
            assert_eq!(
                decide(&Target::Ip(ip), 80, &[], true),
                Err(REPLY_NOT_ALLOWED),
                "{bad}"
            );
        }
    }

    #[test]
    fn off_the_open_web_only_allowed_loopback_targets_pass() {
        let allow = crate::gate::parse_allow_private(
            "http://127.0.0.1:8545, http://10.0.0.5:8545, http://1.1.1.1:443",
        )
        .expect("allow");
        let ip = |s: &str| Target::Ip(s.parse().expect("ip"));
        assert_eq!(
            decide(&ip("127.0.0.1"), 8545, &allow, false),
            Ok(vec!["127.0.0.1:8545".parse().expect("addr")]),
            "the allowed fork on loopback"
        );
        assert_eq!(
            decide(&ip("1.1.1.1"), 443, &[], false),
            Err(REPLY_NOT_ALLOWED),
            "a public address is refused"
        );
        assert_eq!(
            decide(&ip("1.1.1.1"), 443, &allow, false),
            Err(REPLY_NOT_ALLOWED),
            "even an allowed public origin is refused"
        );
        assert_eq!(
            decide(&ip("10.0.0.5"), 8545, &allow, false),
            Err(REPLY_NOT_ALLOWED),
            "an allowed origin on the local network is not this machine"
        );
        assert_eq!(
            decide(&ip("127.0.0.1"), 8546, &allow, false),
            Err(REPLY_NOT_ALLOWED),
            "loopback without an allow is refused"
        );
        assert_eq!(
            decide(&Target::Name("example.com".into()), 443, &allow, false),
            Err(REPLY_NOT_ALLOWED),
            "a public name is refused before it is resolved"
        );
    }
}
