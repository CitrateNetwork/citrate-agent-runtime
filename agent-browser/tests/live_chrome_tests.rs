//! HUP-S5.1 + S5.6 against a real headless Chromium (Chrome, Chromium, Edge or Brave found on
//! this machine). Each test skips, and says so, when none is installed. Pages come from a local
//! test server on 127.0.0.1; nothing here touches the internet.
//!
//! `CITRATE_RECORD_FIXTURES=1` re-records `fixtures/ax-login-form.json` from the real browser.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use citrate_agent_browser::cdp::{Cdp, EventHandler};
use citrate_agent_browser::chromium::{attach_ws_url, ManagedChrome};
use citrate_agent_browser::service::Action;
use citrate_agent_browser::signin::{SignInAnswer, SignInKind};
use citrate_agent_browser::{BrowserError, BrowserService};
use serde_json::json;

fn wait_for<T>(mut f: impl FnMut() -> Option<T>, secs: u64) -> Option<T> {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if let Some(v) = f() {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn cdp_layer_talks_to_a_real_chrome_and_records_the_ax_fixture() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = common::serve();
    let chrome = ManagedChrome::launch(
        &exe,
        (1280, 800),
        &common::test_args(),
        Duration::from_secs(20),
    )
    .expect("launches");
    assert!(chrome.ws_url().starts_with("ws://127.0.0.1:"));
    let handler: EventHandler = Arc::new(|_| None);
    let cdp = Cdp::connect(chrome.ws_url(), handler, Duration::from_secs(15)).expect("connects");
    let version = cdp
        .call("Browser.getVersion", json!({}), None)
        .expect("version");
    assert!(
        version["product"]
            .as_str()
            .unwrap_or_default()
            .contains('/'),
        "{version}"
    );
    // An unknown method is an error result, not a hang.
    let err = cdp
        .call("No.suchMethod", json!({}), None)
        .expect_err("unknown method");
    assert!(err.contains("No.suchMethod"), "{err}");

    let t = cdp
        .call("Target.createTarget", json!({"url": "about:blank"}), None)
        .expect("tab");
    let target = t["targetId"].as_str().expect("target id").to_string();
    let a = cdp
        .call(
            "Target.attachToTarget",
            json!({"targetId": target, "flatten": true}),
            None,
        )
        .expect("attach");
    let s = a["sessionId"].as_str().expect("session").to_string();
    cdp.call("Page.enable", json!({}), Some(&s)).expect("page");
    cdp.call(
        "Page.navigate",
        json!({"url": format!("{base}/login")}),
        Some(&s),
    )
    .expect("navigate");
    let ready = wait_for(
        || {
            let v = cdp
                .call(
                    "Runtime.evaluate",
                    json!({"expression": "document.readyState", "returnByValue": true}),
                    Some(&s),
                )
                .ok()?;
            (v["result"]["value"] == "complete").then_some(())
        },
        10,
    );
    assert!(ready.is_some(), "the page loaded");
    let tree = cdp
        .call("Accessibility.getFullAXTree", json!({}), Some(&s))
        .expect("ax tree");
    assert!(tree["nodes"].as_array().map(|n| n.len()).unwrap_or(0) > 5);
    if std::env::var("CITRATE_RECORD_FIXTURES").as_deref() == Ok("1") {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ax-login-form.json");
        let pretty = serde_json::to_string_pretty(&json!({"nodes": tree["nodes"]})).expect("json");
        std::fs::write(path, pretty + "\n").expect("records");
    }
    cdp.close();
    assert!(cdp.is_closed());
    assert!(cdp.call("Browser.getVersion", json!({}), None).is_err());
}

#[test]
fn managed_browser_navigates_snapshots_types_clicks_and_streams_frames() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = common::serve();
    let svc = BrowserService::new(common::config_allowing(exe, &base));
    assert_eq!(svc.status().mode, "off");

    let page = svc.navigate(&format!("{base}/login")).expect("navigates");
    assert_eq!(page.title, "Example login");
    assert_eq!(svc.status().mode, "managed");

    let (_, snap) = svc.snapshot().expect("snapshot");
    let email = snap
        .refs
        .iter()
        .find(|r| r.role == "textbox")
        .expect("a textbox")
        .clone();
    assert_eq!(email.name, "Email");
    let go = snap
        .refs
        .iter()
        .find(|r| r.role == "button" && r.name == "Continue")
        .expect("the Continue button")
        .clone();
    let later = snap
        .refs
        .iter()
        .find(|r| r.name == "Later")
        .expect("Later")
        .clone();
    assert!(later.disabled);
    assert!(
        svc.act(&later.r#ref, &Action::Click).is_err(),
        "a disabled element is refused"
    );

    svc.act(
        &email.r#ref,
        &Action::Type {
            text: "me@example.com".into(),
            clear: true,
            submit: false,
        },
    )
    .expect("types");
    let done = svc.act(&go.r#ref, &Action::Click).expect("clicks");
    assert!(done.contains("/next?email=me%40example.com"), "{done}");

    // The click navigated, so the old refs are gone.
    let stale = svc.act(&go.r#ref, &Action::Click).expect_err("stale ref");
    assert!(matches!(stale, BrowserError::StaleRef(_)), "{stale:?}");
    let (_, next) = svc.snapshot().expect("snapshot");
    assert!(
        next.text.contains("Signed in as me@example.com"),
        "{}",
        next.text
    );

    // The screencast streams JPEG frames with the viewport size and an outline of the last act.
    let frame = wait_for(|| svc.frame(0).filter(|f| !f.data.is_empty()), 10).expect("a frame");
    assert_eq!(frame.mime, "image/jpeg");
    assert!(frame.viewport_width > 0.0 && frame.viewport_height > 0.0);
    assert!(!frame.withheld);
    let (_, bytes) = svc.screenshot().expect("screenshot");
    assert!(bytes > 1000);
    assert!(
        svc.frame(frame.version).is_some(),
        "the screenshot is a newer view"
    );

    // Non-web addresses are refused.
    for bad in [
        "file:///etc/hosts",
        "chrome://settings",
        "javascript:alert(1)",
    ] {
        assert!(
            matches!(svc.navigate(bad), Err(BrowserError::NotWeb(_))),
            "{bad}"
        );
    }
}

#[test]
fn stop_latches_until_resume_and_denies_waiting_actions() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = common::serve();
    let svc = Arc::new(BrowserService::new(common::config_allowing(exe, &base)));
    svc.navigate(&format!("{base}/login")).expect("navigates");

    // An action waiting for the member is denied by Stop.
    let waiter = {
        let svc = svc.clone();
        std::thread::spawn(move || svc.request_approval("browser_act", "Click", "test", &|| false))
    };
    assert!(wait_for(|| svc.pending_action(), 5).is_some());
    svc.stop();
    let d = waiter.join().expect("joins");
    assert!(
        matches!(d, citrate_agent_browser::approvals::Decision::Denied(_)),
        "{d:?}"
    );

    assert!(svc.status().stopped);
    assert_eq!(svc.status().mode, "off");
    assert_eq!(
        svc.navigate(&format!("{base}/login")),
        Err(BrowserError::Stopped)
    );
    assert_eq!(svc.snapshot().map(|_| ()), Err(BrowserError::Stopped));
    svc.resume();
    svc.navigate(&format!("{base}/login"))
        .expect("works again after resume");
}

#[test]
fn attach_needs_consent_per_session_and_per_origin() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let (base, log) = common::serve_logged();
    // Stand-in for the member's own Chrome, started with remote debugging on a known port.
    let port = common::free_port();
    let mut members_chrome = MembersChrome::start(&exe, port);
    assert!(
        wait_for(|| attach_ws_url(port, Duration::from_secs(1)).ok(), 20).is_some(),
        "the stand-in Chrome listens on {port}"
    );

    let svc = BrowserService::new(common::config(exe));
    // No consent, nothing contacted.
    assert!(svc.attach(port, false).is_err());
    assert_eq!(svc.status().mode, "off");
    svc.attach(port, true).expect("attaches with consent");
    let st = svc.status();
    assert_eq!(st.mode, "attached");
    assert_eq!(st.attach_port, Some(port));
    assert!(st.consented_origins.is_empty());

    // Every origin needs consent.
    let login = format!("{base}/login");
    match svc.navigate(&login) {
        Err(BrowserError::NeedsConsent { origin }) => assert_eq!(origin, base),
        other => panic!("expected NeedsConsent, got {other:?}"),
    }
    assert_eq!(
        svc.status().consent_needed.map(|c| c.origin),
        Some(base.clone())
    );
    // Sensitive origins are refused before anything is loaded.
    match svc.navigate("https://www.chase.com/") {
        Err(BrowserError::Sensitive { category, .. }) => assert_eq!(category, "banking"),
        other => panic!("expected Sensitive, got {other:?}"),
    }

    svc.allow_origin(&base, false).expect("member consents");
    svc.navigate(&login).expect("navigates once consented");
    let (_, snap) = svc.snapshot().expect("snapshot");
    assert!(snap.refs.iter().any(|r| r.name == "Continue"));
    let frame = wait_for(|| svc.frame(0).filter(|f| !f.data.is_empty()), 10).expect("a frame");
    assert!(!frame.withheld);

    // Revoking consent stops reads and actions at once.
    let go = snap
        .refs
        .iter()
        .find(|r| r.name == "Continue")
        .cloned()
        .expect("the Continue button");
    svc.revoke_origin(&base).expect("revokes");
    assert!(matches!(
        svc.snapshot(),
        Err(BrowserError::NeedsConsent { .. })
    ));
    assert!(
        matches!(
            svc.act(&go.r#ref, &Action::Click),
            Err(BrowserError::NeedsConsent { .. })
        ),
        "no click on an origin whose consent was revoked"
    );

    // A consented origin that redirects to one without consent: the landing page is refused.
    // The redirected request is stopped before it is sent, so the member's cookies for the
    // target never leave the browser.
    let redirector = common::serve_redirect(format!("{base}/login?via=redirect"));
    svc.allow_origin(&redirector, false)
        .expect("consents to the redirector only");
    match svc.navigate(&format!("{redirector}/go")) {
        Err(BrowserError::NeedsConsent { origin }) => assert_eq!(origin, base),
        other => panic!("expected NeedsConsent for the redirect target, got {other:?}"),
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        common::hits(&log, "/login?via=redirect"),
        0,
        "the origin without consent never received the redirected request"
    );
    // The tab is left on the browser's own error page, which is never read either.
    assert!(matches!(
        svc.snapshot(),
        Err(BrowserError::NeedsConsent { .. }) | Err(BrowserError::NotWeb(_))
    ));

    // Detach forgets consent and leaves the member's Chrome running.
    svc.allow_origin(&base, false).expect("consents again");
    svc.detach();
    let st = svc.status();
    assert_eq!(st.mode, "off");
    assert!(st.consented_origins.is_empty());
    assert!(
        members_chrome.is_running(),
        "detach never closes the member's browser"
    );
}

/// A Chrome started the way a member would for attach mode: its own profile, a fixed
/// remote-debugging port. Killed when dropped.
struct MembersChrome {
    child: std::process::Child,
    profile: std::path::PathBuf,
}

impl MembersChrome {
    fn start(exe: &std::path::Path, port: u16) -> Self {
        let profile = std::env::temp_dir().join(format!("citrate-browser-test-members-{port}"));
        let _ = std::fs::create_dir_all(&profile);
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "--headless=new".to_string(),
            format!("--remote-debugging-port={port}"),
            format!("--user-data-dir={}", profile.display()),
            "--no-first-run".to_string(),
            "--no-default-browser-check".to_string(),
            "--use-mock-keychain".to_string(),
        ])
        .args(common::test_args())
        .arg("about:blank")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
        let child = cmd.spawn().expect("starts the stand-in Chrome");
        MembersChrome { child, profile }
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for MembersChrome {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

#[test]
fn managed_browser_opens_local_addresses_only_when_a_developer_allows_them() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let (base, log) = common::serve_logged();
    let svc = BrowserService::new(common::config(exe.clone()));
    match svc.navigate(&format!("{base}/login")) {
        Err(BrowserError::NotWeb(why)) => assert!(why.contains("public"), "{why}"),
        other => panic!("expected a refusal for a local address, got {other:?}"),
    }
    for local in [
        "http://localhost:9/",
        "http://169.254.169.254/latest/meta-data/",
    ] {
        assert!(
            matches!(svc.navigate(local), Err(BrowserError::NotWeb(_))),
            "{local}"
        );
    }
    assert_eq!(
        common::hits(&log, "/"),
        0,
        "nothing reached the local server"
    );

    let allowed = BrowserService::new(common::config_allowing(exe, &base));
    let page = allowed
        .navigate(&format!("{base}/login"))
        .expect("an allowed origin opens");
    assert_eq!(page.title, "Example login");
}

#[test]
fn a_page_cannot_make_the_managed_browser_reach_another_local_service() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = common::serve();
    let (other, other_log) = common::serve_logged();
    let svc = BrowserService::new(common::config_allowing(exe, &base));
    // The allowed page fetches from another local origin on its own.
    svc.navigate(&format!("{base}/fetcher?u={other}/secret"))
        .expect("the allowed page opens");
    let done = wait_for(
        || {
            svc.snapshot()
                .ok()
                .map(|(_, s)| s.text)
                .filter(|t| !t.contains("waiting"))
        },
        10,
    )
    .expect("the page's request settles");
    assert!(done.contains("failed"), "{done}");
    assert_eq!(
        common::hits(&other_log, "/secret"),
        0,
        "the other local service never received the request"
    );
    // A click or script navigation to a local address is stopped too.
    match svc.navigate(&format!("{other}/secret")) {
        Err(BrowserError::NotWeb(_)) => {}
        other_result => panic!("expected a refusal, got {other_result:?}"),
    }
    assert_eq!(common::hits(&other_log, "/secret"), 0);
}

/// A page's own WebSocket is a request too: an allowed page cannot open one to another local
/// service (the DevTools request pause does not cover WebSocket handshakes, so they are stopped
/// separately).
#[test]
fn a_page_cannot_open_a_websocket_to_another_local_service() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = common::serve();
    let (other, other_log) = common::serve_logged();
    let ws = other.replacen("http://", "ws://", 1);
    let svc = BrowserService::new(common::config_allowing(exe, &base));
    svc.navigate(&format!("{base}/wsopener?u={ws}/ws"))
        .expect("the allowed page opens");
    let done = wait_for(
        || {
            svc.snapshot()
                .ok()
                .map(|(_, s)| s.text)
                .filter(|t| !t.contains("waiting"))
        },
        10,
    )
    .expect("the socket settles");
    assert!(!done.contains("opened"), "{done}");
    assert_eq!(
        common::hits(&other_log, "/ws"),
        0,
        "the other local service never received the handshake"
    );
    // The developer-allowed origin's own WebSocket still reaches it.
    let (base2, base2_log) = common::serve_logged();
    let ws2 = base2.replacen("http://", "ws://", 1);
    let svc2 = BrowserService::new(common::config_allowing(
        common::chromium().expect("checked above"),
        &base2,
    ));
    svc2.navigate(&format!("{base2}/wsopener?u={ws2}/ws"))
        .expect("the allowed page opens");
    let reached = wait_for(|| (common::hits(&base2_log, "/ws") > 0).then_some(()), 10);
    assert!(
        reached.is_some(),
        "an allowed origin's WebSocket is not blocked"
    );
}

/// HUP-S2.3: the managed browser's sign-in bridge, end to end in a real Chromium. The page's top
/// frame gets a provider; its wallet methods wait for an answer from outside (core); the answer
/// reaches the page; an embedded frame cannot reach the bridge at all.
#[test]
fn the_managed_browser_bridges_a_dapp_sign_in_and_hides_the_binding() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = common::serve();
    let svc = BrowserService::new(common::config_allowing(exe, &base));
    svc.navigate(&format!("{base}/dapp")).expect("navigates");
    let st = svc.status();
    assert_eq!(st.mode, "managed");
    assert!(
        st.devtools_port.is_some(),
        "core needs the DevTools port to attest"
    );
    assert!(st.target_id.is_some());

    let (_, snap) = svc.snapshot().expect("snapshot");
    assert!(
        snap.text.contains("provider yes, binding undefined"),
        "the top frame has a provider and no raw binding: {}",
        snap.text
    );
    let frame_line = wait_for(
        || {
            let (_, s) = svc.snapshot().ok()?;
            s.text.contains("frame: binding").then_some(s.text)
        },
        10,
    )
    .expect("the frame reported");
    assert!(
        frame_line.contains("frame: binding undefined, provider no"),
        "an embedded frame sees neither: {frame_line}"
    );

    let (_, snap) = svc.snapshot().expect("snapshot");
    let go = snap
        .refs
        .iter()
        .find(|r| r.name == "Sign in")
        .expect("the Sign in button")
        .clone();
    svc.act(&go.r#ref, &Action::Click).expect("clicks");

    let accounts = wait_for(|| svc.sign_in_requests().into_iter().next(), 10)
        .expect("an accounts request waits");
    assert_eq!(accounts.kind, SignInKind::Accounts);
    assert!(accounts.top_frame);
    assert_eq!(
        accounts.raise_origin, base,
        "Chrome's origin for the asking context"
    );
    let addr = "0x00000000000000000000000000000000000000a1".to_string();
    svc.answer_sign_in(&accounts.id, &SignInAnswer::Accounts(vec![addr.clone()]))
        .expect("delivered");

    let sign = wait_for(
        || {
            svc.sign_in_requests()
                .into_iter()
                .find(|r| r.kind == SignInKind::PersonalSign)
        },
        10,
    )
    .expect("a personal_sign request waits");
    assert_eq!(sign.message_hex.as_deref(), Some("6869"));
    assert_eq!(sign.address.as_deref(), Some(addr.as_str()));
    let sig = format!("0x{}", "ab".repeat(65));
    svc.answer_sign_in(&sign.id, &SignInAnswer::Signature(sig))
        .expect("delivered");
    let done = wait_for(
        || {
            let (_, s) = svc.snapshot().ok()?;
            s.text.contains("signed 0xabab").then_some(())
        },
        10,
    );
    assert!(done.is_some(), "the page received the signature");
    assert!(
        svc.read_origins().contains(&base),
        "the page's origin is remembered as read"
    );
}

#[test]
fn a_refused_sign_in_reaches_the_page_as_an_eip1193_error() {
    let Some(exe) = common::chromium() else {
        return;
    };
    let base = common::serve();
    let svc = BrowserService::new(common::config_allowing(exe, &base));
    svc.navigate(&format!("{base}/dapp")).expect("navigates");
    let (_, snap) = svc.snapshot().expect("snapshot");
    let go = snap
        .refs
        .iter()
        .find(|r| r.name == "Sign in")
        .expect("the Sign in button")
        .clone();
    svc.act(&go.r#ref, &Action::Click).expect("clicks");
    let r = wait_for(|| svc.sign_in_requests().into_iter().next(), 10).expect("waits");
    svc.answer_sign_in(
        &r.id,
        &SignInAnswer::Refused {
            code: 4100,
            message: "this site has no sign-in budget".into(),
        },
    )
    .expect("delivered");
    let done = wait_for(
        || {
            let (_, s) = svc.snapshot().ok()?;
            s.text.contains("refused 4100").then_some(())
        },
        10,
    );
    assert!(done.is_some());
}
