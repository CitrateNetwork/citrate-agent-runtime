//! HUP-S5.1 + S5.6: the browser worker.
//!
//! One browser per sidecar, in one of two modes:
//! - **Managed** (default): a headless Chromium this worker launches on first use with a fresh
//!   temporary profile (see [`crate::chromium`]). Any http(s) page may be opened.
//! - **Attached**: a tab this worker opens in the member's own Chrome, reached over loopback
//!   DevTools after the member consents for this session. Every origin needs the member's
//!   per-origin consent, sensitive origins are excluded by default ([`crate::scope`]), and
//!   screencast frames of an origin without consent are withheld. The worker only ever drives
//!   the tab it opened.
//!
//! The member's Stop ([`BrowserService::stop`]) closes the connection at once (an in-flight step
//! fails), denies any action waiting for a decision, tears the browser down, and latches: no
//! browser tool runs again until the member resumes.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::approvals::{ActionApprovals, Decision, PendingAction};
use crate::cdp::{Cdp, CdpEvent, EventHandler, Reply};
use crate::chromium::{self, ChromiumStatus, ManagedChrome};
use crate::frames::{FrameBuffer, FrameView, Highlight};
use crate::scope::{Denylist, Origin, OriginScope, ScopeDecision};
use crate::snapshot::{build_snapshot, Snapshot, SnapshotLimits};

/// The env var that turns the browser tools on in the sidecar (`1`; default off).
pub const BROWSER_ENV: &str = "CITRATE_HERMES_BROWSER";

/// Worker settings.
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// The managed Chromium (installed by the S5.5 component updater), if configured.
    pub managed_path: Option<PathBuf>,
    /// Where to look for a system Chromium.
    pub candidates: Vec<PathBuf>,
    /// Extra launch flags (tests only; production passes none).
    pub extra_args: Vec<String>,
    pub viewport: (u32, u32),
    pub command_timeout: Duration,
    pub navigation_timeout: Duration,
    pub launch_timeout: Duration,
    /// How long an action waits for the member before it is denied. The 120 s default is a
    /// conservative placeholder, pending owner sign-off.
    pub approval_timeout: Duration,
    pub denylist: Denylist,
    pub snapshot_limits: SnapshotLimits,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        BrowserConfig {
            managed_path: None,
            candidates: chromium::system_candidates(),
            extra_args: Vec::new(),
            viewport: (1280, 800),
            command_timeout: Duration::from_secs(15),
            navigation_timeout: Duration::from_secs(20),
            launch_timeout: Duration::from_secs(20),
            approval_timeout: Duration::from_secs(120),
            denylist: Denylist::builtin(),
            snapshot_limits: SnapshotLimits::default(),
        }
    }
}

impl BrowserConfig {
    /// `Some` only when `CITRATE_HERMES_BROWSER=1`. The managed Chromium path comes from
    /// `CITRATE_BROWSER_CHROMIUM` when set.
    pub fn from_env() -> Option<BrowserConfig> {
        if std::env::var(BROWSER_ENV).ok().as_deref().map(str::trim) != Some("1") {
            return None;
        }
        let managed_path = std::env::var_os(chromium::MANAGED_CHROMIUM_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Some(BrowserConfig {
            managed_path,
            ..BrowserConfig::default()
        })
    }
}

/// Why a browser step did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserError {
    NotInstalled { searched: Vec<String> },
    Stopped,
    NotAttached,
    NeedsConsent { origin: String },
    Sensitive { origin: String, category: String },
    NotWeb(String),
    StaleRef(String),
    Failed(String),
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserError::NotInstalled { searched } => write!(
                f,
                "no Chromium is installed (checked {} places); the managed browser is installed by the component updater",
                searched.len()
            ),
            BrowserError::Stopped => write!(f, "the member stopped the browser"),
            BrowserError::NotAttached => write!(f, "the browser is not attached"),
            BrowserError::NeedsConsent { origin } => write!(
                f,
                "{origin} needs the member's consent before Hermes can use it in their Chrome"
            ),
            BrowserError::Sensitive { origin, category } => write!(
                f,
                "{origin} is in an excluded category ({category}); Hermes does not use it unless the member includes it explicitly"
            ),
            BrowserError::NotWeb(why) => write!(f, "{why}"),
            BrowserError::StaleRef(why) => write!(f, "{why}"),
            BrowserError::Failed(why) => write!(f, "{why}"),
        }
    }
}

type Result<T> = std::result::Result<T, BrowserError>;

/// An origin the member is being asked about (attach mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentNeeded {
    pub origin: String,
    /// The excluded category, when the origin is sensitive.
    pub category: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CategoryView {
    pub id: String,
    pub label: String,
}

/// What the app shows about the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    pub enabled: bool,
    pub chromium: ChromiumStatus,
    /// `off`, `managed` or `attached`.
    pub mode: String,
    pub attach_port: Option<u16>,
    pub stopped: bool,
    pub url: String,
    pub consented_origins: Vec<String>,
    pub excluded_categories: Vec<CategoryView>,
    pub consent_needed: Option<ConsentNeeded>,
    pub pending_action: Option<PendingAction>,
}

/// A page the worker is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageInfo {
    pub url: String,
    pub title: String,
}

/// One action on a ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Click,
    Type {
        text: String,
        clear: bool,
        submit: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Managed,
    Attached(u16),
}

#[derive(Default)]
struct Shared {
    frames: FrameBuffer,
    scope: Mutex<Option<OriginScope>>,
    url: Mutex<String>,
    attached: AtomicBool,
    session: Mutex<Option<String>>,
    target: Mutex<Option<String>>,
    consent_needed: Mutex<Option<ConsentNeeded>>,
    mode: Mutex<Option<Mode>>,
    /// Bumped whenever the refs the member could have been shown stop being current: a new
    /// snapshot, or the main frame moving to another address (including same-document moves).
    /// An approved action runs only if this is unchanged since the member was asked.
    page_version: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

impl Shared {
    fn url(&self) -> String {
        lock(&self.url).clone()
    }

    fn frames_allowed(&self, url: &str) -> bool {
        if !self.attached.load(Ordering::SeqCst) {
            return true;
        }
        lock(&self.scope)
            .as_ref()
            .map(|s| s.check(url) == ScopeDecision::Allowed)
            .unwrap_or(false)
    }

    fn on_event(&self, ev: &CdpEvent) -> Option<Reply> {
        let ours = lock(&self.session).clone();
        if ev.session_id.is_none() || ev.session_id != ours {
            return None;
        }
        match ev.method.as_str() {
            "Page.frameNavigated" => {
                let frame = &ev.params["frame"];
                if frame["parentId"].is_null() {
                    if let Some(u) = frame["url"].as_str() {
                        *lock(&self.url) = u.to_string();
                    }
                    self.page_version.fetch_add(1, Ordering::SeqCst);
                }
                None
            }
            "Page.navigatedWithinDocument" => {
                let main = lock(&self.target).clone();
                if ev.params["frameId"].as_str() == main.as_deref() {
                    if let Some(u) = ev.params["url"].as_str() {
                        *lock(&self.url) = u.to_string();
                    }
                    self.page_version.fetch_add(1, Ordering::SeqCst);
                }
                None
            }
            "Page.screencastFrame" => {
                let url = self.url();
                if self.frames_allowed(&url) {
                    let meta = &ev.params["metadata"];
                    let vw = meta["deviceWidth"].as_f64().unwrap_or(0.0);
                    let vh = meta["deviceHeight"].as_f64().unwrap_or(0.0);
                    let data = ev.params["data"].as_str().unwrap_or_default().to_string();
                    self.frames.push("image/jpeg", data, (vw, vh), &url);
                } else {
                    self.frames.withhold(&url);
                }
                Some(Reply {
                    method: "Page.screencastFrameAck".to_string(),
                    params: json!({"sessionId": ev.params["sessionId"].clone()}),
                    session_id: ev.session_id.clone(),
                })
            }
            _ => None,
        }
    }
}

struct Live {
    mode: Mode,
    cdp: Arc<Cdp>,
    session: String,
    _chrome: Option<ManagedChrome>,
    snapshot: Option<Snapshot>,
}

/// The browser worker.
pub struct BrowserService {
    cfg: BrowserConfig,
    shared: Arc<Shared>,
    live: Mutex<Option<Live>>,
    /// The live connection, reachable without the `live` lock so Stop never waits on a step.
    handle: Mutex<Option<Arc<Cdp>>>,
    stopped: AtomicBool,
    approvals: ActionApprovals,
}

impl BrowserService {
    pub fn new(cfg: BrowserConfig) -> Self {
        let shared = Arc::new(Shared::default());
        *lock(&shared.scope) = Some(OriginScope::new(cfg.denylist.clone()));
        BrowserService {
            cfg,
            shared,
            live: Mutex::new(None),
            handle: Mutex::new(None),
            stopped: AtomicBool::new(false),
            approvals: ActionApprovals::default(),
        }
    }

    pub fn config(&self) -> &BrowserConfig {
        &self.cfg
    }

    /// Where the browser would come from right now.
    pub fn chromium(&self) -> ChromiumStatus {
        chromium::discover(self.cfg.managed_path.as_deref(), &self.cfg.candidates)
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    pub fn status(&self) -> BrowserStatus {
        let mode = *lock(&self.shared.mode);
        let scope = lock(&self.shared.scope);
        BrowserStatus {
            enabled: true,
            chromium: self.chromium(),
            mode: match mode {
                None => "off",
                Some(Mode::Managed) => "managed",
                Some(Mode::Attached(_)) => "attached",
            }
            .to_string(),
            attach_port: match mode {
                Some(Mode::Attached(p)) => Some(p),
                _ => None,
            },
            stopped: self.is_stopped(),
            url: self.shared.url(),
            consented_origins: scope.as_ref().map(|s| s.allowed()).unwrap_or_default(),
            excluded_categories: scope
                .as_ref()
                .map(|s| {
                    s.denylist()
                        .categories()
                        .iter()
                        .map(|c| CategoryView {
                            id: c.id.clone(),
                            label: c.label.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            consent_needed: lock(&self.shared.consent_needed).clone(),
            pending_action: self.approvals.pending(),
        }
    }

    /// The screencast view when newer than `after`.
    pub fn frame(&self, after: u64) -> Option<FrameView> {
        self.shared.frames.newer_than(after)
    }

    // --- member controls ----------------------------------------------------------------------

    /// The member's Stop: fail the in-flight step, deny any waiting action, tear down, latch.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.approvals.deny_all();
        self.teardown();
    }

    /// Clear the Stop latch (the member resumes).
    pub fn resume(&self) {
        self.stopped.store(false, Ordering::SeqCst);
    }

    /// Attach to the member's Chrome on loopback `port`. `consent` must be the member's explicit
    /// consent for this session; without it nothing is contacted.
    pub fn attach(&self, port: u16, consent: bool) -> Result<PageInfo> {
        if !consent {
            return Err(BrowserError::Failed(
                "attaching to Chrome needs the member's explicit consent for this session"
                    .to_string(),
            ));
        }
        self.teardown();
        self.stopped.store(false, Ordering::SeqCst);
        let ws =
            chromium::attach_ws_url(port, Duration::from_secs(5)).map_err(BrowserError::Failed)?;
        let mut live = lock(&self.live);
        let l = self.connect(&ws, Mode::Attached(port), None)?;
        *live = Some(l);
        Ok(PageInfo {
            url: self.shared.url(),
            title: String::new(),
        })
    }

    /// Leave the member's Chrome: close the tab this worker opened, forget every consent.
    pub fn detach(&self) {
        self.teardown();
    }

    /// The member consents to one origin (attach mode). A sensitive origin also needs
    /// `include_sensitive`.
    pub fn allow_origin(
        &self,
        origin: &str,
        include_sensitive: bool,
    ) -> std::result::Result<String, String> {
        let mut scope = lock(&self.shared.scope);
        let s = scope
            .as_mut()
            .ok_or_else(|| "internal: no origin scope".to_string())?;
        let shown = s.allow(origin, include_sensitive)?;
        let mut need = lock(&self.shared.consent_needed);
        if need.as_ref().map(|n| n.origin == shown).unwrap_or(false) {
            *need = None;
        }
        Ok(shown)
    }

    pub fn revoke_origin(&self, origin: &str) -> std::result::Result<String, String> {
        let mut scope = lock(&self.shared.scope);
        let s = scope
            .as_mut()
            .ok_or_else(|| "internal: no origin scope".to_string())?;
        s.revoke(origin)
    }

    /// The action waiting for the member, if any.
    pub fn pending_action(&self) -> Option<PendingAction> {
        self.approvals.pending()
    }

    pub fn decide(&self, id: &str, allow: bool) -> std::result::Result<(), String> {
        self.approvals.decide(id, allow)
    }

    /// Ask the member about one action and wait (see [`crate::approvals`]).
    pub fn request_approval(
        &self,
        tool: &str,
        summary: &str,
        reason: &str,
        session_stopped: &dyn Fn() -> bool,
    ) -> Decision {
        if self.is_stopped() {
            return Decision::Denied("the member stopped the browser".to_string());
        }
        let stopped = || session_stopped() || self.is_stopped();
        self.approvals
            .request(tool, summary, reason, self.cfg.approval_timeout, &stopped)
    }

    // --- tool operations ----------------------------------------------------------------------

    /// Open an http(s) address in the worker's tab.
    pub fn navigate(&self, url: &str) -> Result<PageInfo> {
        Origin::parse(url).map_err(BrowserError::NotWeb)?;
        let mut guard = self.ensure_live()?;
        let live = guard
            .as_mut()
            .ok_or_else(|| BrowserError::Failed("internal: no browser".to_string()))?;
        if matches!(live.mode, Mode::Attached(_)) {
            self.check_scope_url(url)?;
        }
        let r = self.call(live, "Page.navigate", json!({"url": url}))?;
        if let Some(err) = r["errorText"].as_str().filter(|e| !e.is_empty()) {
            return Err(BrowserError::Failed(format!(
                "the page did not load: {err}"
            )));
        }
        self.wait_ready(live, self.cfg.navigation_timeout);
        live.snapshot = None;
        let now = self.current_url(live)?;
        if matches!(live.mode, Mode::Attached(_)) {
            self.check_scope_url(&now)?;
        }
        let title = self.title(live);
        Ok(PageInfo { url: now, title })
    }

    /// A ref-indexed accessibility snapshot of the current page.
    pub fn snapshot(&self) -> Result<(PageInfo, Snapshot)> {
        let mut guard = self.ensure_live()?;
        let live = guard
            .as_mut()
            .ok_or_else(|| BrowserError::Failed("internal: no browser".to_string()))?;
        let url = self.current_url(live)?;
        if matches!(live.mode, Mode::Attached(_)) {
            self.check_scope_url(&url)?;
        }
        let _ = self.call(live, "Accessibility.enable", json!({}));
        let r = self.call(live, "Accessibility.getFullAXTree", json!({}))?;
        let nodes = r["nodes"].as_array().cloned().unwrap_or_default();
        let snap = build_snapshot(&nodes, self.cfg.snapshot_limits);
        live.snapshot = Some(snap.clone());
        self.shared.page_version.fetch_add(1, Ordering::SeqCst);
        let title = self.title(live);
        Ok((PageInfo { url, title }, snap))
    }

    /// The `role "name"` of a ref in the latest snapshot (for approval prompts).
    pub fn describe_ref(&self, r: &str) -> Option<String> {
        let guard = lock(&self.live);
        let e = guard.as_ref()?.snapshot.as_ref()?.find(r)?.clone();
        Some(format!("{} \"{}\"", e.role, e.name))
    }

    /// Outline a ref in the screencast while the member decides. Best effort.
    pub fn preview_ref(&self, r: &str) {
        let mut guard = lock(&self.live);
        let Some(live) = guard.as_mut() else {
            return;
        };
        let Some(entry) = live.snapshot.as_ref().and_then(|s| s.find(r)).cloned() else {
            return;
        };
        if let Ok((x, y, w, h)) = self.element_box(live, entry.backend_node_id) {
            self.shared.frames.set_highlight(Some(Highlight {
                r#ref: entry.r#ref.clone(),
                label: format!("{} \"{}\"", entry.role, entry.name),
                x,
                y,
                width: w,
                height: h,
                state: "pending".to_string(),
            }));
        }
    }

    /// Remove the outline.
    pub fn clear_highlight(&self) {
        self.shared.frames.set_highlight(None);
    }

    /// Which page and snapshot the refs refer to right now. Read it when asking the member about
    /// an action and pass it to [`BrowserService::act_if_unchanged`], so the allowed action runs
    /// only on what the member was shown.
    pub fn page_version(&self) -> u64 {
        self.shared.page_version.load(Ordering::SeqCst)
    }

    /// Click or type into an element by its ref from the latest snapshot.
    pub fn act(&self, r: &str, action: &Action) -> Result<String> {
        self.act_at(r, action, None)
    }

    /// [`BrowserService::act`], refused if the page or snapshot changed since `version` (from
    /// [`BrowserService::page_version`]): a new snapshot, or the page moved to another address.
    pub fn act_if_unchanged(&self, r: &str, action: &Action, version: u64) -> Result<String> {
        self.act_at(r, action, Some(version))
    }

    fn act_at(&self, r: &str, action: &Action, version: Option<u64>) -> Result<String> {
        let mut guard = self.ensure_live()?;
        let live = guard
            .as_mut()
            .ok_or_else(|| BrowserError::Failed("internal: no browser".to_string()))?;
        let before = self.current_url(live)?;
        if matches!(live.mode, Mode::Attached(_)) {
            self.check_scope_url(&before)?;
        }
        let entry = live
            .snapshot
            .as_ref()
            .ok_or_else(|| {
                BrowserError::StaleRef(
                    "take a browser_snapshot first; refs come from it".to_string(),
                )
            })?
            .find(r)
            .cloned()
            .ok_or_else(|| {
                BrowserError::StaleRef(format!(
                    "there is no element [{r}] in the latest snapshot; take a new browser_snapshot"
                ))
            })?;
        if version.is_some_and(|v| v != self.page_version()) {
            return Err(BrowserError::StaleRef(
                "the page changed while the member was deciding, so nothing was done; take a new browser_snapshot".to_string(),
            ));
        }
        if entry.disabled {
            return Err(BrowserError::Failed(format!(
                "[{r}] {} \"{}\" is disabled",
                entry.role, entry.name
            )));
        }
        let (x, y, w, h) = self.element_box(live, entry.backend_node_id)?;
        self.shared.frames.set_highlight(Some(Highlight {
            r#ref: entry.r#ref.clone(),
            label: format!("{} \"{}\"", entry.role, entry.name),
            x,
            y,
            width: w,
            height: h,
            state: "acted".to_string(),
        }));
        let (cx, cy) = (x + w / 2.0, y + h / 2.0);
        let done = match action {
            Action::Click => {
                for (kind, extra) in [
                    ("mouseMoved", json!({})),
                    ("mousePressed", json!({"button": "left", "clickCount": 1})),
                    ("mouseReleased", json!({"button": "left", "clickCount": 1})),
                ] {
                    let mut p = json!({"type": kind, "x": cx, "y": cy});
                    if let (Some(p), Some(e)) = (p.as_object_mut(), extra.as_object()) {
                        p.extend(e.clone());
                    }
                    self.call(live, "Input.dispatchMouseEvent", p)?;
                }
                format!("Clicked [{r}] {} \"{}\".", entry.role, entry.name)
            }
            Action::Type {
                text,
                clear,
                submit,
            } => {
                self.call(
                    live,
                    "DOM.focus",
                    json!({"backendNodeId": entry.backend_node_id}),
                )?;
                if *clear {
                    let obj = self.call(
                        live,
                        "DOM.resolveNode",
                        json!({"backendNodeId": entry.backend_node_id}),
                    )?;
                    if let Some(id) = obj["object"]["objectId"].as_str() {
                        self.call(
                            live,
                            "Runtime.callFunctionOn",
                            json!({
                                "objectId": id,
                                "functionDeclaration": "function(){ if ('value' in this) { this.value = ''; this.dispatchEvent(new Event('input', {bubbles: true})); } else if (this.isContentEditable) { this.textContent = ''; } }",
                            }),
                        )?;
                    }
                }
                self.call(live, "Input.insertText", json!({"text": text}))?;
                if *submit {
                    for kind in ["keyDown", "keyUp"] {
                        let mut p = json!({
                            "type": kind,
                            "key": "Enter",
                            "code": "Enter",
                            "windowsVirtualKeyCode": 13,
                            "nativeVirtualKeyCode": 13,
                        });
                        if kind == "keyDown" {
                            p["text"] = json!("\r");
                        }
                        self.call(live, "Input.dispatchKeyEvent", p)?;
                    }
                }
                format!(
                    "Typed {} characters into [{r}] {} \"{}\"{}.",
                    text.chars().count(),
                    entry.role,
                    entry.name,
                    if *submit { " and pressed Enter" } else { "" }
                )
            }
        };
        std::thread::sleep(Duration::from_millis(250));
        self.wait_ready(live, Duration::from_secs(5));
        let after = self.current_url(live)?;
        if after != before {
            live.snapshot = None;
        }
        Ok(format!("{done} The page is now {after}."))
    }

    /// Capture the current page into the screencast (the model gets a short receipt, not pixels).
    pub fn screenshot(&self) -> Result<(PageInfo, usize)> {
        let mut guard = self.ensure_live()?;
        let live = guard
            .as_mut()
            .ok_or_else(|| BrowserError::Failed("internal: no browser".to_string()))?;
        let url = self.current_url(live)?;
        if matches!(live.mode, Mode::Attached(_)) {
            self.check_scope_url(&url)?;
        }
        let shot = self.call(
            live,
            "Page.captureScreenshot",
            json!({"format": "jpeg", "quality": 70}),
        )?;
        let data = shot["data"].as_str().unwrap_or_default().to_string();
        let bytes = data.len() / 4 * 3;
        let metrics = self.call(live, "Page.getLayoutMetrics", json!({}))?;
        let vp = &metrics["cssVisualViewport"];
        let size = (
            vp["clientWidth"].as_f64().unwrap_or(0.0),
            vp["clientHeight"].as_f64().unwrap_or(0.0),
        );
        self.shared.frames.push("image/jpeg", data, size, &url);
        let title = self.title(live);
        Ok((PageInfo { url, title }, bytes))
    }

    // --- internals ----------------------------------------------------------------------------

    fn call(&self, live: &Live, method: &str, params: Value) -> Result<Value> {
        if self.is_stopped() {
            return Err(BrowserError::Stopped);
        }
        live.cdp
            .call(method, params, Some(&live.session))
            .map_err(|e| {
                if self.is_stopped() {
                    BrowserError::Stopped
                } else {
                    BrowserError::Failed(e)
                }
            })
    }

    fn check_scope_url(&self, url: &str) -> Result<()> {
        let decision = lock(&self.shared.scope)
            .as_ref()
            .map(|s| s.check(url))
            .unwrap_or(ScopeDecision::NotWeb {
                reason: "internal: no origin scope".to_string(),
            });
        match decision {
            ScopeDecision::Allowed => Ok(()),
            ScopeDecision::NeedsConsent { origin } => {
                *lock(&self.shared.consent_needed) = Some(ConsentNeeded {
                    origin: origin.clone(),
                    category: None,
                });
                Err(BrowserError::NeedsConsent { origin })
            }
            ScopeDecision::Sensitive { origin, category } => {
                *lock(&self.shared.consent_needed) = Some(ConsentNeeded {
                    origin: origin.clone(),
                    category: Some(category.clone()),
                });
                Err(BrowserError::Sensitive { origin, category })
            }
            ScopeDecision::NotWeb { reason } => Err(BrowserError::NotWeb(reason)),
        }
    }

    fn current_url(&self, live: &Live) -> Result<String> {
        let tree = self.call(live, "Page.getFrameTree", json!({}))?;
        let url = tree["frameTree"]["frame"]["url"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        *lock(&self.shared.url) = url.clone();
        Ok(url)
    }

    fn title(&self, live: &Live) -> String {
        self.call(
            live,
            "Runtime.evaluate",
            json!({"expression": "document.title", "returnByValue": true}),
        )
        .ok()
        .and_then(|v| v["result"]["value"].as_str().map(str::to_string))
        .unwrap_or_default()
    }

    fn wait_ready(&self, live: &Live, timeout: Duration) {
        let end = Instant::now() + timeout;
        while Instant::now() < end && !self.is_stopped() {
            let state = self
                .call(
                    live,
                    "Runtime.evaluate",
                    json!({"expression": "document.readyState", "returnByValue": true}),
                )
                .ok()
                .and_then(|v| v["result"]["value"].as_str().map(str::to_string));
            if state.as_deref() == Some("complete") {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn element_box(&self, live: &Live, backend: i64) -> Result<(f64, f64, f64, f64)> {
        let _ = self.call(
            live,
            "DOM.scrollIntoViewIfNeeded",
            json!({"backendNodeId": backend}),
        );
        let m = self.call(live, "DOM.getBoxModel", json!({"backendNodeId": backend}))?;
        let quad: Vec<f64> = m["model"]["border"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_f64()).collect())
            .unwrap_or_default();
        if quad.len() != 8 {
            return Err(BrowserError::Failed(
                "the element has no box on the page (it may be hidden)".to_string(),
            ));
        }
        let xs = [quad[0], quad[2], quad[4], quad[6]];
        let ys = [quad[1], quad[3], quad[5], quad[7]];
        let (x0, x1) = (
            xs.iter().cloned().fold(f64::INFINITY, f64::min),
            xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        );
        let (y0, y1) = (
            ys.iter().cloned().fold(f64::INFINITY, f64::min),
            ys.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        );
        if !(x1 > x0 && y1 > y0) {
            return Err(BrowserError::Failed(
                "the element has no size on the page".to_string(),
            ));
        }
        Ok((x0, y0, x1 - x0, y1 - y0))
    }

    /// The live browser, launching the managed one when there is none.
    fn ensure_live(&self) -> Result<MutexGuard<'_, Option<Live>>> {
        if self.is_stopped() {
            return Err(BrowserError::Stopped);
        }
        let mut guard = lock(&self.live);
        if let Some(l) = guard.as_ref() {
            if !l.cdp.is_closed() {
                return Ok(guard);
            }
            let attached = matches!(l.mode, Mode::Attached(_));
            *guard = None;
            drop(guard);
            self.teardown();
            if attached {
                return Err(BrowserError::Failed(
                    "the connection to Chrome was lost; attach again".to_string(),
                ));
            }
            guard = lock(&self.live);
        }
        let exe = match self.chromium() {
            ChromiumStatus::NotInstalled { searched } => {
                return Err(BrowserError::NotInstalled { searched })
            }
            s => s
                .path()
                .ok_or_else(|| BrowserError::Failed("internal: no browser path".to_string()))?,
        };
        let chrome = ManagedChrome::launch(
            &exe,
            self.cfg.viewport,
            &self.cfg.extra_args,
            self.cfg.launch_timeout,
        )
        .map_err(BrowserError::Failed)?;
        let ws = chrome.ws_url().to_string();
        let live = self.connect(&ws, Mode::Managed, Some(chrome))?;
        *guard = Some(live);
        Ok(guard)
    }

    fn connect(&self, ws: &str, mode: Mode, chrome: Option<ManagedChrome>) -> Result<Live> {
        let shared = self.shared.clone();
        let handler: EventHandler = Arc::new(move |ev: &CdpEvent| shared.on_event(ev));
        let cdp = Arc::new(
            Cdp::connect(ws, handler, self.cfg.command_timeout).map_err(BrowserError::Failed)?,
        );
        let created = cdp
            .call("Target.createTarget", json!({"url": "about:blank"}), None)
            .map_err(BrowserError::Failed)?;
        let target = created["targetId"]
            .as_str()
            .ok_or_else(|| BrowserError::Failed("the browser did not open a tab".to_string()))?
            .to_string();
        let attached = cdp
            .call(
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
                None,
            )
            .map_err(BrowserError::Failed)?;
        let session = attached["sessionId"]
            .as_str()
            .ok_or_else(|| {
                BrowserError::Failed("the browser did not attach to the tab".to_string())
            })?
            .to_string();
        *lock(&self.shared.session) = Some(session.clone());
        *lock(&self.shared.target) = Some(target);
        *lock(&self.shared.url) = "about:blank".to_string();
        let is_attached = matches!(mode, Mode::Attached(_));
        self.shared.attached.store(is_attached, Ordering::SeqCst);
        if is_attached {
            if let Some(s) = lock(&self.shared.scope).as_mut() {
                s.reset();
            }
        }
        *lock(&self.shared.mode) = Some(mode);
        *lock(&self.handle) = Some(cdp.clone());
        let live = Live {
            mode,
            cdp,
            session,
            _chrome: chrome,
            snapshot: None,
        };
        self.call(&live, "Page.enable", json!({}))?;
        let (w, h) = self.cfg.viewport;
        self.call(
            &live,
            "Page.startScreencast",
            json!({"format": "jpeg", "quality": 60, "maxWidth": w, "maxHeight": h, "everyNthFrame": 1}),
        )?;
        Ok(live)
    }

    /// Close everything: the connection first (so a running step fails fast), then the tab this
    /// worker opened in an attached Chrome, then the managed browser. Forgets attach consent.
    fn teardown(&self) {
        let handle = lock(&self.handle).take();
        let target = lock(&self.shared.target).take();
        let was_attached = self.shared.attached.swap(false, Ordering::SeqCst);
        if let Some(cdp) = &handle {
            if was_attached {
                if let Some(t) = &target {
                    let _ = cdp.call_with_timeout(
                        "Target.closeTarget",
                        json!({"targetId": t}),
                        None,
                        Duration::from_secs(2),
                    );
                }
            }
            cdp.close();
        }
        self.approvals.deny_all();
        let old = lock(&self.live).take();
        drop(old);
        *lock(&self.shared.session) = None;
        *lock(&self.shared.mode) = None;
        *lock(&self.shared.consent_needed) = None;
        *lock(&self.shared.url) = String::new();
        if was_attached {
            if let Some(s) = lock(&self.shared.scope).as_mut() {
                s.reset();
            }
        }
        self.shared.frames.clear();
    }
}

impl Drop for BrowserService {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_event(session: &str) -> CdpEvent {
        // Shape recorded from Chrome 154 (`Page.screencastFrame`, flat session).
        CdpEvent {
            method: "Page.screencastFrame".to_string(),
            params: json!({
                "data": "/9j/4AAQSkZJRg==",
                "metadata": {"deviceWidth": 1280, "deviceHeight": 800, "offsetTop": 0,
                              "pageScaleFactor": 1, "scrollOffsetX": 0, "scrollOffsetY": 0,
                              "timestamp": 1.0},
                "sessionId": 7,
            }),
            session_id: Some(session.to_string()),
        }
    }

    fn shared_attached(url: &str) -> Shared {
        let s = Shared::default();
        *lock(&s.scope) = Some(OriginScope::new(Denylist::builtin()));
        *lock(&s.session) = Some("S1".to_string());
        *lock(&s.url) = url.to_string();
        s.attached.store(true, Ordering::SeqCst);
        s
    }

    #[test]
    fn every_frame_is_acked_with_its_screencast_session() {
        let s = shared_attached("https://example.com/");
        let reply = s.on_event(&frame_event("S1")).expect("an ack");
        assert_eq!(reply.method, "Page.screencastFrameAck");
        assert_eq!(reply.params["sessionId"], 7);
        assert_eq!(reply.session_id.as_deref(), Some("S1"));
    }

    #[test]
    fn attach_mode_withholds_frames_of_origins_without_consent() {
        let s = shared_attached("https://example.com/");
        s.on_event(&frame_event("S1"));
        let v = s.frames.newer_than(0).expect("a view");
        assert!(v.withheld);
        assert!(v.data.is_empty(), "no pixels of an origin without consent");
        if let Some(sc) = lock(&s.scope).as_mut() {
            sc.allow("https://example.com", false).expect("consent");
        }
        s.on_event(&frame_event("S1"));
        let v = s.frames.newer_than(v.version).expect("a newer view");
        assert!(!v.withheld);
        assert_eq!(v.data, "/9j/4AAQSkZJRg==");
        assert_eq!((v.viewport_width, v.viewport_height), (1280.0, 800.0));
    }

    #[test]
    fn managed_mode_shows_every_frame() {
        let s = shared_attached("https://example.com/");
        s.attached.store(false, Ordering::SeqCst);
        s.on_event(&frame_event("S1"));
        assert!(!s.frames.newer_than(0).expect("a view").withheld);
    }

    #[test]
    fn events_of_other_sessions_are_ignored() {
        let s = shared_attached("https://example.com/");
        assert!(s.on_event(&frame_event("OTHER")).is_none());
        assert!(s.frames.newer_than(0).is_none());
    }

    #[test]
    fn main_frame_navigation_tracks_the_url_and_subframes_do_not() {
        let s = shared_attached("about:blank");
        *lock(&s.target) = Some("T1".to_string());
        let nav = |params: Value, method: &str| CdpEvent {
            method: method.to_string(),
            params,
            session_id: Some("S1".to_string()),
        };
        s.on_event(&nav(
            json!({"frame": {"id": "T1", "url": "https://a.example/"}}),
            "Page.frameNavigated",
        ));
        assert_eq!(s.url(), "https://a.example/");
        s.on_event(&nav(
            json!({"frame": {"id": "F2", "parentId": "T1", "url": "https://ads.example/"}}),
            "Page.frameNavigated",
        ));
        assert_eq!(s.url(), "https://a.example/");
        s.on_event(&nav(
            json!({"frameId": "T1", "url": "https://a.example/#x"}),
            "Page.navigatedWithinDocument",
        ));
        assert_eq!(s.url(), "https://a.example/#x");
    }

    #[test]
    fn attach_without_consent_contacts_nothing() {
        let svc = BrowserService::new(BrowserConfig {
            candidates: Vec::new(),
            ..BrowserConfig::default()
        });
        // Port 1 would be refused anyway; consent is checked first.
        let err = svc.attach(9222, false).expect_err("refused");
        assert!(err.to_string().contains("consent"), "{err}");
        assert_eq!(svc.status().mode, "off");
    }

    #[test]
    fn with_no_chromium_the_tools_say_not_installed() {
        let svc = BrowserService::new(BrowserConfig {
            managed_path: Some(PathBuf::from("/nonexistent/citrate/chromium")),
            candidates: vec![PathBuf::from("/nonexistent/chrome")],
            ..BrowserConfig::default()
        });
        match svc.chromium() {
            ChromiumStatus::NotInstalled { searched } => assert_eq!(searched.len(), 2),
            other => panic!("expected NotInstalled, got {other:?}"),
        }
        match svc.navigate("https://example.com/") {
            Err(BrowserError::NotInstalled { .. }) => {}
            other => panic!("expected NotInstalled, got {other:?}"),
        }
        assert!(svc.status().chromium == svc.chromium());
    }
}
