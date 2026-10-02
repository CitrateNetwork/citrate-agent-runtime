//! HUP-S5.6: attach-to-Chrome origin scoping. Every origin needs the member's consent in attach
//! mode; banking, email and health origins are excluded by default and need a separate,
//! explicit per-origin choice; only http(s) pages are ever in scope.

use citrate_agent_browser::scope::{Denylist, Origin, OriginScope, ScopeDecision};

#[test]
fn origins_normalize_scheme_host_and_default_port() {
    let o = Origin::parse("HTTPS://Example.COM:443/path?q=1#x").expect("parses");
    assert_eq!(o.to_string(), "https://example.com");
    let o = Origin::parse("http://example.com:8080/").expect("parses");
    assert_eq!(o.to_string(), "http://example.com:8080");
    // A unicode host is compared in its ASCII form.
    let o = Origin::parse("https://bücher.example/").expect("parses");
    assert_eq!(o.host(), "xn--bcher-kva.example");
}

#[test]
fn only_web_pages_have_an_origin() {
    for bad in [
        "file:///etc/passwd",
        "chrome://settings",
        "javascript:alert(1)",
        "data:text/html,hi",
        "about:blank",
        "ftp://example.com",
        "not a url",
        "",
        "https://",
    ] {
        assert!(
            Origin::parse(bad).is_err(),
            "{bad} must not parse as a web origin"
        );
    }
}

#[test]
fn the_builtin_denylist_loads_and_has_the_three_categories() {
    let d = Denylist::builtin();
    let ids: Vec<_> = d.categories().iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, vec!["banking", "email", "health"]);
    for c in d.categories() {
        assert!(!c.label.is_empty());
    }
}

#[test]
fn banking_email_and_health_origins_are_recognised() {
    let d = Denylist::builtin();
    let cat = |u: &str| {
        d.category_for(&Origin::parse(u).expect("parses"))
            .map(|c| c.id.clone())
    };
    assert_eq!(cat("https://www.chase.com/"), Some("banking".into()));
    assert_eq!(
        cat("https://secure.chase.com/login"),
        Some("banking".into())
    );
    assert_eq!(cat("https://anything.bank/"), Some("banking".into()));
    assert_eq!(
        cat("https://onlinebanking.example-cu.org/"),
        Some("banking".into())
    );
    assert_eq!(
        cat("https://mail.google.com/mail/u/0"),
        Some("email".into())
    );
    assert_eq!(cat("https://outlook.live.com/"), Some("email".into()));
    assert_eq!(
        cat("https://mychart.somehospital.org/"),
        Some("health".into())
    );
    assert_eq!(cat("https://www.healthcare.gov/"), Some("health".into()));
}

#[test]
fn lookalikes_and_ordinary_sites_are_not_sensitive() {
    let d = Denylist::builtin();
    for u in [
        "https://example.com/",
        "https://notchase.com/",
        "https://chase.com.example.org/",
        "https://docs.citrate.ai/",
        "https://bankrate-news.example/",
        "https://mailchimp-like.example/",
        "http://127.0.0.1:8080/",
    ] {
        let o = Origin::parse(u).expect("parses");
        assert!(
            d.category_for(&o).is_none(),
            "{u} must not be treated as sensitive"
        );
    }
}

#[test]
fn a_custom_denylist_parses_and_bad_files_are_refused() {
    let d = Denylist::parse(
        r#"version = 1
[[category]]
id = "custom"
label = "Custom"
domains = ["Example.org"]
labels = []
"#,
    )
    .expect("parses");
    let o = Origin::parse("https://a.example.org").expect("parses");
    assert_eq!(d.category_for(&o).map(|c| c.id.as_str()), Some("custom"));
    assert!(Denylist::parse("version = 2\n").is_err(), "unknown version");
    assert!(Denylist::parse("not toml [").is_err());
    assert!(
        Denylist::parse("version = 1\n[[category]]\nid=\"\"\nlabel=\"x\"\ndomains=[]\nlabels=[]\n")
            .is_err(),
        "a category needs an id"
    );
}

#[test]
fn attach_mode_needs_consent_for_every_origin() {
    let scope = OriginScope::new(Denylist::builtin());
    match scope.check("https://example.com/page") {
        ScopeDecision::NeedsConsent { origin } => assert_eq!(origin, "https://example.com"),
        other => panic!("expected NeedsConsent, got {other:?}"),
    }
}

#[test]
fn consent_is_per_origin() {
    let mut scope = OriginScope::new(Denylist::builtin());
    scope.allow("https://example.com", false).expect("allowed");
    assert_eq!(
        scope.check("https://example.com/a/b"),
        ScopeDecision::Allowed
    );
    // Another port, scheme or subdomain is another origin.
    assert!(matches!(
        scope.check("http://example.com/"),
        ScopeDecision::NeedsConsent { .. }
    ));
    assert!(matches!(
        scope.check("https://www.example.com/"),
        ScopeDecision::NeedsConsent { .. }
    ));
    assert!(matches!(
        scope.check("https://example.com:8443/"),
        ScopeDecision::NeedsConsent { .. }
    ));
}

#[test]
fn sensitive_origins_are_excluded_even_with_plain_consent() {
    let mut scope = OriginScope::new(Denylist::builtin());
    let err = scope
        .allow("https://www.chase.com", false)
        .expect_err("plain consent is not enough for a sensitive origin");
    assert!(err.contains("Banking"), "{err}");
    match scope.check("https://www.chase.com/") {
        ScopeDecision::Sensitive { origin, category } => {
            assert_eq!(origin, "https://www.chase.com");
            assert_eq!(category, "banking");
        }
        other => panic!("expected Sensitive, got {other:?}"),
    }
}

#[test]
fn a_member_can_include_one_sensitive_origin_explicitly() {
    let mut scope = OriginScope::new(Denylist::builtin());
    scope
        .allow("https://www.chase.com", true)
        .expect("explicitly included");
    assert_eq!(
        scope.check("https://www.chase.com/x"),
        ScopeDecision::Allowed
    );
    // Including one does not include the rest of its category.
    assert!(matches!(
        scope.check("https://secure.chase.com/"),
        ScopeDecision::Sensitive { .. }
    ));
}

#[test]
fn non_web_urls_are_never_in_scope() {
    let mut scope = OriginScope::new(Denylist::builtin());
    scope.allow("https://example.com", false).expect("allowed");
    for u in [
        "file:///etc/hosts",
        "chrome://settings",
        "javascript:void(0)",
        "data:,x",
    ] {
        assert!(
            matches!(scope.check(u), ScopeDecision::NotWeb { .. }),
            "{u} must be refused"
        );
    }
    assert!(scope.allow("file:///", false).is_err());
}

#[test]
fn revoke_and_reset_take_consent_away() {
    let mut scope = OriginScope::new(Denylist::builtin());
    scope.allow("https://a.example", false).expect("allowed");
    scope.allow("https://b.example", false).expect("allowed");
    scope.revoke("https://a.example/anything").expect("revoked");
    assert!(matches!(
        scope.check("https://a.example/"),
        ScopeDecision::NeedsConsent { .. }
    ));
    assert_eq!(scope.check("https://b.example/"), ScopeDecision::Allowed);
    assert_eq!(scope.allowed(), vec!["https://b.example".to_string()]);
    scope.reset();
    assert!(scope.allowed().is_empty());
    assert!(matches!(
        scope.check("https://b.example/"),
        ScopeDecision::NeedsConsent { .. }
    ));
}
