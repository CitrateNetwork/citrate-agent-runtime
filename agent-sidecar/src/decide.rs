//! HUP-S5.3: the `decide()` System-1 slot over HTTP (`POST /decide`), with per-backend metering
//! (`GET /decide/stats`, `POST /decide/outcomes`).
//!
//! The local backend is the default: the caller names its loopback llama-server (or https gateway)
//! the same way it opens a session, and the choice is grammar-constrained there. The TypeSafe Jev
//! backend is off unless the member opts in:
//!
//! | env                            | meaning                                                         |
//! |--------------------------------|-----------------------------------------------------------------|
//! | `CITRATE_HERMES_JEV`           | `1` turns the Jev backend on (still per origin)                  |
//! | `CITRATE_HERMES_JEV_KEY_FILE`  | file holding the TypeSafe API key (required for Jev)            |
//! | `CITRATE_HERMES_JEV_ORIGINS`   | comma-separated origins Jev may decide for                      |
//! | `CITRATE_HERMES_JEV_NON_WEB`   | `1` also allows decisions with no web origin                     |
//! | `CITRATE_HERMES_JEV_ENDPOINT`  | decisions endpoint (https), default TypeSafe's System One URL   |
//! | `CITRATE_HERMES_JEV_MODEL`     | model name, default `jev-latest`                                 |
//! | `CITRATE_HERMES_DECIDE_LOG`    | JSONL file for decision metering (optional)                     |
//!
//! Every Jev decision returns an `egress` notice (destination and bytes sent) and is counted in
//! the metering. Nothing here signs or holds a wallet key (Rule 3).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use citrate_agent_loop::decide::{
    BackendKind, BackendPref, DecideError, DecidePolicy, DecideRequest, DecideTransport, Decider,
    Decision, DecisionRecord, JevBackend, LocalGrammarBackend,
};
use citrate_agent_metering::{DecisionLine, DecisionLog, DecisionReport, TaskRecord};
use serde::{Deserialize, Serialize};

use crate::sessions::{validate_endpoint, LlmEndpoint};

pub const JEV_ENV: &str = "CITRATE_HERMES_JEV";
pub const JEV_KEY_FILE_ENV: &str = "CITRATE_HERMES_JEV_KEY_FILE";
pub const JEV_ORIGINS_ENV: &str = "CITRATE_HERMES_JEV_ORIGINS";
pub const JEV_NON_WEB_ENV: &str = "CITRATE_HERMES_JEV_NON_WEB";
pub const JEV_ENDPOINT_ENV: &str = "CITRATE_HERMES_JEV_ENDPOINT";
pub const JEV_MODEL_ENV: &str = "CITRATE_HERMES_JEV_MODEL";
pub const DECIDE_LOG_ENV: &str = "CITRATE_HERMES_DECIDE_LOG";
/// TypeSafe's System One decisions endpoint (as used by the `system1-agents` adapter).
pub const JEV_DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
pub const JEV_DEFAULT_MODEL: &str = "jev-latest";
/// Local decisions get the model's own budget; Jev answers in about a second when it is up.
const LOCAL_TIMEOUT: Duration = Duration::from_secs(60);
const JEV_TIMEOUT: Duration = Duration::from_secs(5);
/// Lines kept in memory for `/decide/stats`.
const STATS_CAP: usize = 10_000;

/// A blocking JSON POST transport. The client is built per call (on the blocking pool) so no
/// runtime is created or dropped inside an async handler. Errors never carry the URL or bearer.
pub struct HttpDecideTransport {
    url: String,
    bearer: String,
    timeout: Duration,
    destination: String,
}

impl HttpDecideTransport {
    pub fn new(url: &str, bearer: &str, timeout: Duration) -> Self {
        HttpDecideTransport {
            url: url.to_string(),
            bearer: bearer.to_string(),
            timeout,
            destination: url.to_string(),
        }
    }

    /// For an OpenAI-compatible base URL (`…/v1`): POSTs to `…/v1/chat/completions`.
    pub fn chat_completions(base_url: &str, bearer: &str, timeout: Duration) -> Self {
        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        Self::new(&url, bearer, timeout)
    }
}

impl DecideTransport for HttpDecideTransport {
    fn post_json(&self, body: &serde_json::Value) -> Result<String, String> {
        let http = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5).min(self.timeout))
            .timeout(self.timeout)
            .build()
            .map_err(|_| "HTTP client unavailable".to_string())?;
        let mut rb = http.post(&self.url).json(body);
        if !self.bearer.is_empty() {
            rb = rb.bearer_auth(&self.bearer);
        }
        let resp = rb.send().map_err(|e| {
            if e.is_timeout() {
                "timed out".to_string()
            } else if e.is_connect() {
                "could not connect".to_string()
            } else {
                "request failed".to_string()
            }
        })?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|_| "could not read the response".to_string())?;
        if !status.is_success() {
            return Err(format!("HTTP {}", status.as_u16()));
        }
        Ok(text)
    }

    fn destination(&self) -> String {
        self.destination.clone()
    }
}

/// The opted-in Jev connection (the key never leaves this struct except as a bearer header).
#[derive(Clone)]
pub struct JevSettings {
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
}

impl std::fmt::Debug for JevSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JevSettings")
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

/// What the environment configures.
#[derive(Debug, Clone, Default)]
pub struct DecideSettings {
    pub policy: DecidePolicy,
    pub jev: Option<JevSettings>,
    pub log: Option<PathBuf>,
}

/// Parse the decide settings. `notes` collects operator-facing lines (never a key).
pub fn decide_settings_from_vars(
    get: impl Fn(&str) -> Option<String>,
    notes: &mut Vec<String>,
) -> DecideSettings {
    let log = get(DECIDE_LOG_ENV)
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    if get(JEV_ENV).as_deref() != Some("1") {
        return DecideSettings {
            log,
            ..DecideSettings::default()
        };
    }
    let endpoint = get(JEV_ENDPOINT_ENV)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| JEV_DEFAULT_ENDPOINT.to_string());
    if !endpoint.starts_with("https://") {
        notes.push("the Jev endpoint must use https; Jev stays off".into());
        return DecideSettings {
            log,
            ..DecideSettings::default()
        };
    }
    let key = get(JEV_KEY_FILE_ENV)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty());
    let Some(api_key) = key else {
        notes.push("Jev is on but no readable key file is configured; Jev stays off".into());
        return DecideSettings {
            log,
            ..DecideSettings::default()
        };
    };
    let origins: Vec<String> = get(JEV_ORIGINS_ENV)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let non_web = get(JEV_NON_WEB_ENV).as_deref() == Some("1");
    notes.push(format!(
        "Jev decisions are opted in for {} origin(s){}; each one sends data to {endpoint}",
        origins.len(),
        if non_web {
            " and for non-web decisions"
        } else {
            ""
        }
    ));
    DecideSettings {
        policy: DecidePolicy {
            jev_enabled: true,
            jev_origins: origins,
            jev_non_web: non_web,
        },
        jev: Some(JevSettings {
            endpoint,
            api_key,
            model: get(JEV_MODEL_ENV)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| JEV_DEFAULT_MODEL.to_string()),
        }),
        log,
    }
}

/// `POST /decide` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecideHttpReq {
    /// The local model endpoint (as for a session). Absent = no local backend for this call.
    #[serde(default)]
    pub llm: Option<LlmEndpoint>,
    #[serde(default)]
    pub model: Option<String>,
    pub request: DecideRequest,
    #[serde(default)]
    pub backend: BackendPref,
}

/// `POST /decide/outcomes` body: one task attempted with one backend.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeReq {
    pub backend: BackendKind,
    pub suite: String,
    pub task_id: String,
    pub success: bool,
}

/// `GET /decide/stats` body.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecideStatus {
    pub jev_enabled: bool,
    pub jev_origins: usize,
    pub jev_non_web: bool,
    pub logging: bool,
    pub report: DecisionReport,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The slot plus its metering.
pub struct DecideService {
    settings: DecideSettings,
    log: Option<DecisionLog>,
    lines: Mutex<VecDeque<DecisionLine>>,
}

impl Default for DecideService {
    fn default() -> Self {
        DecideService::new(DecideSettings::default())
    }
}

impl DecideService {
    pub fn new(settings: DecideSettings) -> Self {
        let log = settings.log.clone().map(DecisionLog::new);
        DecideService {
            settings,
            log,
            lines: Mutex::new(VecDeque::new()),
        }
    }

    pub fn from_env() -> Arc<Self> {
        let mut notes = Vec::new();
        let s = decide_settings_from_vars(|k| std::env::var(k).ok(), &mut notes);
        for n in notes {
            eprintln!("citrate-agent-sidecar: {n}");
        }
        Arc::new(DecideService::new(s))
    }

    fn push(&self, line: DecisionLine) {
        if let Some(log) = &self.log {
            if let Err(e) = log.append(&line) {
                eprintln!("citrate-agent-sidecar: decision log append failed: {e}");
            }
        }
        if let Ok(mut l) = self.lines.lock() {
            if l.len() >= STATS_CAP {
                l.pop_front();
            }
            l.push_back(line);
        }
    }

    fn decider(&self, llm: Option<&LlmEndpoint>, model: &str) -> Decider {
        let local = llm.map(|ep| {
            Arc::new(LocalGrammarBackend::new(
                Arc::new(HttpDecideTransport::chat_completions(
                    &ep.base_url,
                    &ep.bearer,
                    LOCAL_TIMEOUT,
                )),
                model,
            )) as Arc<dyn citrate_agent_loop::decide::DecideBackend>
        });
        let jev = self.settings.jev.as_ref().map(|j| {
            Arc::new(JevBackend::new(
                Arc::new(HttpDecideTransport::new(
                    &j.endpoint,
                    &j.api_key,
                    JEV_TIMEOUT,
                )),
                &j.model,
            )) as Arc<dyn citrate_agent_loop::decide::DecideBackend>
        });
        Decider::new(local, jev, self.settings.policy.clone())
    }

    /// One decision (blocking: run it on the blocking pool). Recorded either way.
    pub fn decide(&self, req: &DecideHttpReq) -> Result<Decision, DecideError> {
        if let Some(ep) = &req.llm {
            validate_endpoint(&ep.base_url).map_err(DecideError::Invalid)?;
        }
        let model = req.model.clone().unwrap_or_default();
        if req.llm.is_some() && model.trim().is_empty() {
            return Err(DecideError::Invalid("model is required with llm".into()));
        }
        let decider = self.decider(req.llm.as_ref(), &model);
        let started = std::time::Instant::now();
        let out = decider.decide(&req.request, req.backend);
        match &out {
            Ok(d) => self.push(DecisionLine::Decision(d.record(now_ms()))),
            Err(e) => {
                // Only count failures that reached a backend choice; malformed requests are the
                // caller's, not a backend's.
                if !matches!(e, DecideError::Invalid(_)) {
                    let backend = decider
                        .resolve(&req.request, req.backend)
                        .map(|b| b.kind())
                        .unwrap_or(match req.backend {
                            BackendPref::Jev => BackendKind::Jev,
                            _ => BackendKind::Local,
                        });
                    self.push(DecisionLine::Decision(DecisionRecord::failure(
                        now_ms(),
                        backend,
                        req.request.purpose,
                        req.request.options.len(),
                        started.elapsed().as_millis() as u64,
                        e,
                    )));
                }
            }
        }
        out
    }

    /// Record one task outcome for the per-backend success rate.
    pub fn record_outcome(&self, o: &OutcomeReq) -> Result<(), String> {
        let rec = TaskRecord::new(now_ms(), o.backend, &o.suite, &o.task_id, o.success)?;
        self.push(DecisionLine::Task(rec));
        Ok(())
    }

    pub fn status(&self) -> DecideStatus {
        let lines: Vec<DecisionLine> = self
            .lines
            .lock()
            .map(|l| l.iter().cloned().collect())
            .unwrap_or_default();
        DecideStatus {
            jev_enabled: self.settings.policy.jev_enabled && self.settings.jev.is_some(),
            jev_origins: self.settings.policy.jev_origins.len(),
            jev_non_web: self.settings.policy.jev_non_web,
            logging: self.log.is_some(),
            report: DecisionReport::build(&lines),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn jev_is_off_by_default_and_needs_a_key_and_https() {
        let mut n = vec![];
        let s = decide_settings_from_vars(vars(&[]), &mut n);
        assert!(!s.policy.jev_enabled);
        assert!(s.jev.is_none());
        let s = decide_settings_from_vars(vars(&[(JEV_ENV, "1")]), &mut n);
        assert!(s.jev.is_none(), "no key file -> off");
        assert!(n.iter().any(|l| l.contains("no readable key file")));
        let dir = std::env::temp_dir().join(format!("n4-jev-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let key = dir.join("k");
        std::fs::write(&key, "ts-key\n").unwrap();
        let k = key.to_str().unwrap();
        let s = decide_settings_from_vars(
            vars(&[
                (JEV_ENV, "1"),
                (JEV_KEY_FILE_ENV, k),
                (JEV_ENDPOINT_ENV, "http://api.example/x"),
            ]),
            &mut n,
        );
        assert!(s.jev.is_none(), "plain http endpoint -> off");
        let mut n2 = vec![];
        let s = decide_settings_from_vars(
            vars(&[
                (JEV_ENV, "1"),
                (JEV_KEY_FILE_ENV, k),
                (
                    JEV_ORIGINS_ENV,
                    "https://shop.example, https://docs.example ,",
                ),
            ]),
            &mut n2,
        );
        let j = s.jev.expect("on");
        assert_eq!(j.api_key, "ts-key");
        assert_eq!(j.endpoint, JEV_DEFAULT_ENDPOINT);
        assert_eq!(s.policy.jev_origins.len(), 2);
        assert!(!s.policy.jev_non_web);
        assert!(n2.iter().all(|l| !l.contains("ts-key")));
        assert!(!format!("{j:?}").contains("ts-key"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn task_outcomes_are_validated_and_counted() {
        let svc = DecideService::default();
        assert!(svc
            .record_outcome(&OutcomeReq {
                backend: BackendKind::Local,
                suite: "web-subset-v1".into(),
                task_id: "repo-star".into(),
                success: true,
            })
            .is_ok());
        assert!(svc
            .record_outcome(&OutcomeReq {
                backend: BackendKind::Local,
                suite: "web subset".into(),
                task_id: "x".into(),
                success: true,
            })
            .is_err());
        let st = svc.status();
        assert_eq!(st.report.backends["local"].tasks_attempted, 1);
        assert!(!st.jev_enabled);
    }
}
