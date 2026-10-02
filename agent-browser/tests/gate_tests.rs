//! The request gate: which requests the browser may send.
//!
//! - Managed mode (Hermes's own headless browser): only public web addresses, so a page, a
//!   redirect or a click can never make the browser read a service on this machine or the local
//!   network. A developer can allow named origins (for example a local test chain).
//! - Attach mode (the member's own Chrome): a top-level page load to an origin without the
//!   member's consent is stopped before the request leaves the browser, so the member's cookies
//!   are never sent there.

use citrate_agent_browser::gate::{
    fetch_patterns, managed_verdict, parse_allow_private, resolved_verdict, Verdict,
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
    for url in ["data:text/plain,hi", "about:blank", "blob:https://example.com/x"] {
        assert_eq!(managed_verdict(url, &[], true), Verdict::Continue, "{url}");
    }
}

#[test]
fn a_developer_allowed_origin_is_reachable_and_nothing_else_on_that_host() {
    let allow = parse_allow_private("http://127.0.0.1:8545, http://localhost:3000").expect("parses");
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
    assert_eq!(parse_allow_private("").expect("empty"), Vec::<Origin>::new());
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
