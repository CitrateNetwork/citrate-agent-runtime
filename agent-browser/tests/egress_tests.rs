//! The managed browser's network gate ([`citrate_agent_browser::egress`]), driven the way Chromium
//! drives a SOCKS5 proxy: one connection per target, the target named by IP literal or by host
//! name (the gate resolves names itself). Local listeners stand in for services on this machine.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use citrate_agent_browser::egress::EgressGate;
use citrate_agent_browser::gate::parse_allow_private;

/// A loopback listener that counts accepted connections and echoes one line back.
fn echo_server() -> (SocketAddr, Arc<AtomicUsize>) {
    let l = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => panic!("bind: {e}"),
    };
    let addr = match l.local_addr() {
        Ok(a) => a,
        Err(e) => panic!("addr: {e}"),
    };
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            seen.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            });
        }
    });
    (addr, hits)
}

fn connect(gate: &EgressGate) -> TcpStream {
    let s = match TcpStream::connect(gate.addr()) {
        Ok(s) => s,
        Err(e) => panic!("connect to the gate: {e}"),
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    s
}

/// SOCKS5 greeting with "no authentication"; returns the method the gate chose.
fn greet(s: &mut TcpStream) -> [u8; 2] {
    s.write_all(&[5, 1, 0]).expect("greeting");
    let mut r = [0u8; 2];
    s.read_exact(&mut r).expect("method reply");
    r
}

/// A CONNECT request for `target` (ATYP 1/4 for IP literals, 3 for a name); returns the reply code.
fn request(s: &mut TcpStream, host: &str, port: u16) -> u8 {
    let mut req = vec![5, 1, 0];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            req.push(1);
            req.extend_from_slice(&v4.octets());
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            req.push(4);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            req.push(3);
            req.push(u8::try_from(host.len()).expect("short name"));
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).expect("request");
    let mut head = [0u8; 4];
    s.read_exact(&mut head).expect("reply head");
    assert_eq!(head[0], 5, "a SOCKS5 reply");
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        other => panic!("unexpected reply address type {other}"),
    };
    let mut tail = vec![0u8; rest];
    s.read_exact(&mut tail).expect("reply address");
    head[1]
}

const REFUSED_BY_RULESET: u8 = 2;

#[test]
fn a_local_address_is_refused_before_any_connection_is_made() {
    let (local, hits) = echo_server();
    let gate = EgressGate::start(Vec::new()).expect("gate");
    for host in ["127.0.0.1", "::1", "localhost", "printer.local"] {
        let mut s = connect(&gate);
        assert_eq!(greet(&mut s), [5, 0]);
        assert_eq!(
            request(&mut s, host, local.port()),
            REFUSED_BY_RULESET,
            "{host}"
        );
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "nothing reached the local service"
    );
}

#[test]
fn a_name_that_resolves_to_a_local_address_is_refused() {
    // `localhost.` resolves through the system resolver to loopback; the gate judges the address
    // it resolved, not the name, so a public-looking name pointed at this machine is refused too.
    let (local, hits) = echo_server();
    let gate = EgressGate::start(Vec::new()).expect("gate");
    let mut s = connect(&gate);
    greet(&mut s);
    assert_eq!(
        request(&mut s, "localhost.", local.port()),
        REFUSED_BY_RULESET
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn a_developer_allowed_origin_is_relayed_both_ways() {
    let (local, hits) = echo_server();
    let allow = parse_allow_private(&format!("http://{local}")).expect("allow");
    let gate = EgressGate::start(allow).expect("gate");
    let mut s = connect(&gate);
    greet(&mut s);
    assert_eq!(request(&mut s, "127.0.0.1", local.port()), 0, "succeeded");
    s.write_all(b"ping").expect("send through the gate");
    let mut back = [0u8; 4];
    s.read_exact(&mut back).expect("echo through the gate");
    assert_eq!(&back, b"ping");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // The allow is for that port only.
    let (other, other_hits) = echo_server();
    let mut s = connect(&gate);
    greet(&mut s);
    assert_eq!(
        request(&mut s, "127.0.0.1", other.port()),
        REFUSED_BY_RULESET
    );
    assert_eq!(other_hits.load(Ordering::SeqCst), 0);
}

#[test]
fn only_unauthenticated_connect_is_spoken() {
    let gate = EgressGate::start(Vec::new()).expect("gate");
    // A client offering only username/password authentication gets "no acceptable methods".
    let mut s = connect(&gate);
    s.write_all(&[5, 1, 2]).expect("greeting");
    let mut r = [0u8; 2];
    s.read_exact(&mut r).expect("reply");
    assert_eq!(r, [5, 0xff]);
    // BIND and UDP ASSOCIATE are not supported.
    for cmd in [2u8, 3] {
        let mut s = connect(&gate);
        greet(&mut s);
        s.write_all(&[5, cmd, 0, 1, 1, 1, 1, 1, 0, 80])
            .expect("request");
        let mut head = [0u8; 2];
        s.read_exact(&mut head).expect("reply");
        assert_eq!(head, [5, 7], "command {cmd} not supported");
    }
    // Not SOCKS5 at all: the connection is closed without a relay.
    let mut s = connect(&gate);
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").expect("write");
    let mut buf = [0u8; 8];
    let n = s.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "closed");
}

#[test]
fn the_browser_launch_flags_route_every_connection_through_the_gate() {
    let gate = EgressGate::start(Vec::new()).expect("gate");
    let args = gate.browser_args();
    assert!(args.contains(&format!("--proxy-server=socks5://{}", gate.addr())));
    // Chromium skips the proxy for loopback unless told not to.
    assert!(args.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
    // WebRTC may not send UDP around the proxy.
    assert!(args.contains(&"--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string()));
}

#[test]
fn dropping_the_gate_stops_it_listening() {
    let gate = EgressGate::start(Vec::new()).expect("gate");
    let addr = gate.addr();
    drop(gate);
    std::thread::sleep(Duration::from_millis(200));
    let refused = TcpStream::connect_timeout(&addr, Duration::from_secs(1))
        .map(|mut s| {
            // A late accept may still happen; the gate must not answer it.
            let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = s.write_all(&[5, 1, 0]);
            let mut r = [0u8; 2];
            s.read_exact(&mut r).is_err()
        })
        .unwrap_or(true);
    assert!(refused, "a dropped gate does not relay");
}
