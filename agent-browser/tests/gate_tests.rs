//! The request gate: which requests the browser may send.
//!
//! - Managed mode (Hermes's own headless browser): only public web addresses, so a page, a
//!   redirect or a click can never make the browser read a service on this machine or the local
//!   network. A developer can allow named origins (for example a local test chain).
//! - Attach mode (the member's own Chrome): a top-level page load to an origin without the
//!   member's consent is stopped before the request leaves the browser, so the member's cookies
//!   are never sent there.

use citrate_agent_browser::gate::{
    closed_verdict, fetch_patterns, is_loopback_host, managed_verdict, managed_verdict_for,
    parse_allow_private, parse_open_web, resolved_verdict, Verdict,
};
use citrate_agent_browser::scope::Origin;

fn origin(s: &str) -> Origin {
    match Origin::parse(s) {
        Ok(o) => o,
        Err(e) => panic!("{s}: {e}"),
    }
}

#[test]
fn managed_mode_blocks_local_and_private_targets() {
    for url in [
        "http://127.0.0.1:8545/",
        "http://127.0.0.1/",
        "http://[::1]:11434/v1/models",
        "http://10.0.0.5/admin",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://[fd00::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://localhost:8080/",
        "http://api.localhost/",
        "http://printer.local/",
        "http://db.internal/",
        "http://router/",
    ] {
        for document in [true, false] {
            assert!(
                matches!(managed_verdict(url, &[], document), Verdict::Block(_)),
                "{url} (document: {document})"
            );
        }
    }
}

#[test]
fn managed_mode_lets_public_addresses_through() {
    for url in ["https://1.1.1.1/", "https://[2606:4700::1111]/"] {
        assert_eq!(managed_verdict(url, &[], true), Verdict::Continue, "{url}");
    }
    // Sub-resources on a named host continue; a page load on a named host is resolved first.
    assert_eq!(
        managed_verdict("https://example.com/app.js", &[], false),
        Verdict::Continue
    );
    assert_eq!(
        managed_verdict("https://example.com/", &[], true),
        Verdict::Resolve {
            host: "example.com".to_string(),
            port: 443
        }
    );
    // Not a network request the gate judges.
    for url in [
        "data:text/plain,hi",
        "about:blank",
        "blob:https://example.com/x",
    ] {
        assert_eq!(managed_verdict(url, &[], true), Verdict::Continue, "{url}");
    }
}

#[test]
fn a_developer_allowed_origin_is_reachable_and_nothing_else_on_that_host() {
    let allow =
        parse_allow_private("http://127.0.0.1:8545, http://localhost:3000").expect("parses");
    assert_eq!(allow.len(), 2);
    assert_eq!(
        managed_verdict("http://127.0.0.1:8545/rpc", &allow, true),
        Verdict::Continue
    );
    assert_eq!(
        managed_verdict("http://localhost:3000/", &allow, true),
        Verdict::Continue
    );
    assert!(matches!(
        managed_verdict("http://127.0.0.1:8546/", &allow, true),
        Verdict::Block(_)
    ));
    assert!(matches!(
        managed_verdict("https://127.0.0.1:8545/", &allow, true),
        Verdict::Block(_)
    ));
    assert_eq!(
        parse_allow_private("").expect("empty"),
        Vec::<Origin>::new()
    );
    assert!(parse_allow_private("file:///etc").is_err());
    assert_eq!(allow[0], origin("http://127.0.0.1:8545"));
}

#[test]
fn a_name_that_resolves_to_a_local_address_is_blocked() {
    assert!(matches!(
        resolved_verdict(&["127.0.0.1:443".parse().expect("addr")], &[]),
        Verdict::Block(_)
    ));
    assert!(matches!(
        resolved_verdict(
            &[
                "93.184.216.34:443".parse().expect("addr"),
                "10.0.0.1:443".parse().expect("addr"),
            ],
            &[]
        ),
        Verdict::Block(_)
    ));
    assert!(matches!(resolved_verdict(&[], &[]), Verdict::Block(_)));
    assert_eq!(
        resolved_verdict(&["93.184.216.34:443".parse().expect("addr")], &[]),
        Verdict::Continue
    );
}

#[test]
fn managed_mode_pauses_every_request_and_attach_mode_every_page_load() {
    let managed = fetch_patterns(false);
    assert_eq!(managed.as_array().map(Vec::len), Some(1));
    assert_eq!(managed[0]["urlPattern"], "*");
    assert_eq!(managed[0]["requestStage"], "Request");
    assert!(managed[0].get("resourceType").is_none());
    let attached = fetch_patterns(true);
    assert_eq!(attached[0]["resourceType"], "Document");
    assert_eq!(attached[0]["requestStage"], "Request");
}

// ---- HUP-S5.5: off the open web (browserMayOpenWeb = false) -----------------------------------

#[test]
fn the_open_web_switch_is_open_unless_core_says_otherwise_and_fails_closed() {
    assert!(parse_open_web(None), "unset: the behaviour before the rule");
    assert!(parse_open_web(Some("1")));
    assert!(parse_open_web(Some(" 1 ")));
    for closed in ["0", "", "true", "yes", "01", "off"] {
        assert!(!parse_open_web(Some(closed)), "{closed:?} is closed");
    }
}

#[test]
fn off_the_open_web_no_public_address_is_reached() {
    for url in [
        "https://example.com/",
        "https://1.1.1.1/",
        "http://[2606:4700:4700::1111]/",
        "https://cdn.example.com/app.js",
        "http://10.0.0.5/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8545/",
        "http://localhost:3000/",
    ] {
        assert!(
            matches!(closed_verdict(url, &[]), Verdict::Block(ref why) if why.contains("off the open web")),
            "{url}"
        );
    }
}

#[test]
fn off_the_open_web_only_allowed_origins_on_this_machine_open() {
    let allow = parse_allow_private(
        "http://127.0.0.1:8545, http://localhost:3000, http://[::1]:9000, http://10.0.0.5:8545, https://example.com",
    )
    .expect("allow");
    for url in [
        "http://127.0.0.1:8545/rpc",
        "http://localhost:3000/",
        "http://[::1]:9000/",
    ] {
        assert_eq!(closed_verdict(url, &allow), Verdict::Continue, "{url}");
    }
    for url in [
        "http://10.0.0.5:8545/",
        "https://example.com/",
        "http://127.0.0.1:8546/",
    ] {
        assert!(
            matches!(closed_verdict(url, &allow), Verdict::Block(_)),
            "{url} is not an allowed origin on this machine"
        );
    }
    // Non-network schemes stay inside the browser.
    assert_eq!(closed_verdict("about:blank", &[]), Verdict::Continue);
    assert!(matches!(closed_verdict("http://", &[]), Verdict::Block(_)));
}

#[test]
fn the_open_web_rule_picks_the_verdict() {
    assert_eq!(
        managed_verdict_for("https://1.1.1.1/", &[], true, true),
        Verdict::Continue,
        "open: a public address is reached as before"
    );
    assert!(matches!(
        managed_verdict_for("https://1.1.1.1/", &[], true, false),
        Verdict::Block(_)
    ));
    assert!(
        matches!(
            managed_verdict_for("https://example.com/", &[], true, false),
            Verdict::Block(_)
        ),
        "closed: a name is refused, never resolved"
    );
}

#[test]
fn loopback_hosts_are_recognised_as_written() {
    for h in [
        "localhost",
        "LOCALHOST",
        "localhost.",
        "127.0.0.1",
        "127.8.9.10",
        "[::1]",
        "[::ffff:127.0.0.1]",
    ] {
        assert!(is_loopback_host(h), "{h}");
    }
    for h in [
        "localhost.example.com",
        "10.0.0.1",
        "[::ffff:10.0.0.1]",
        "1.1.1.1",
        "example.com",
        "[fd00::1]",
    ] {
        assert!(!is_loopback_host(h), "{h}");
    }
}
