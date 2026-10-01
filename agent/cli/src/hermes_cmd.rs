//! `citrate-agent hermes …` (HUP-S1.8) — drive the same sidecar-owned Hermes agent from a terminal.
//!
//! Talks to the running agent sidecar on its loopback control address with the bearer the desktop
//! app wrote (`<app data>/ai.citrate.core/hermes/bearer.token`). What it can do:
//!
//! - `status` — the sidecar's running state, skills and pending approvals.
//! - `events --session <id> [--follow]` — watch any session, including one the app opened.
//! - `stop --session <id>` — stop a session's current turn.
//! - `open` / `send` / `chat` — a headless session of your own. It offers only the sidecar's
//!   installed capsules as tools: core-hosted tools (memory, wallet, groups, deploy…) run inside the
//!   app behind its approval gates, so a terminal session never has them. The model endpoint is
//!   yours to name (`--llm-base-url`, loopback http or https); its key is read from an environment
//!   variable you name (`--llm-key-env`), never from the command line.
//! - `brief [--track <id>] --goal "…" [--defaults]` — the same interview the app runs (HUP-S1.4):
//!   a few questions with defaults (Enter keeps the default), then the brief Hermes would build from.

use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct HermesArgs {
    /// Sidecar control address (loopback only).
    #[arg(
        long,
        env = "CITRATE_HERMES_ADDR",
        default_value = "127.0.0.1:19700",
        global = true
    )]
    pub addr: String,
    /// Bearer-token file the app wrote (default: the app's data dir).
    #[arg(long, env = "CITRATE_HERMES_TOKEN_FILE", global = true)]
    pub token_file: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: HermesCmd,
}

#[derive(Args, Debug, Clone)]
pub struct ModelArgs {
    /// Model name to request.
    #[arg(long)]
    pub model: String,
    /// OpenAI-compatible base URL (loopback http, or https).
    #[arg(long, default_value = "http://127.0.0.1:18080/v1")]
    pub llm_base_url: String,
    /// Name of the environment variable holding the model's API key (empty key if unset).
    #[arg(long)]
    pub llm_key_env: Option<String>,
    /// System prompt.
    #[arg(
        long,
        default_value = "You are Hermes, the member's Citrate agent. Be concise and precise."
    )]
    pub system: String,
}

#[derive(Subcommand, Debug)]
pub enum HermesCmd {
    /// Show the sidecar's status.
    Status,
    /// Open a headless session (sidecar capsules only); prints the session id.
    Open(ModelArgs),
    /// Send one message to a session.
    Send {
        #[arg(long)]
        session: String,
        text: String,
    },
    /// Print a session's events (use --follow to keep watching).
    Events {
        #[arg(long)]
        session: String,
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long)]
        follow: bool,
    },
    /// Stop a session's current turn.
    Stop {
        #[arg(long)]
        session: String,
    },
    /// Interactive chat: opens a headless session and follows each turn.
    Chat(ModelArgs),
    /// Answer a track's interview and print the brief (no track: suggested from the goal).
    Brief {
        /// Track id (creative, code, smart-contract, project-management, full-project).
        #[arg(long)]
        track: Option<String>,
        /// What you want to make.
        #[arg(long)]
        goal: String,
        /// Skip the questions and take every default.
        #[arg(long)]
        defaults: bool,
        /// Print the brief as JSON instead of markdown.
        #[arg(long)]
        json: bool,
    },
}

/// Where the desktop app writes the sidecar bearer (Tauri `app_local_data_dir` + `hermes/`).
pub fn default_token_path(os: &str, home: &str) -> PathBuf {
    let base = PathBuf::from(home);
    match os {
        "macos" => base.join("Library/Application Support/ai.citrate.core/hermes/bearer.token"),
        "windows" => base.join("AppData/Local/ai.citrate.core/hermes/bearer.token"),
        _ => base.join(".local/share/ai.citrate.core/hermes/bearer.token"),
    }
}

/// The control plane is loopback-only; refuse anything else before a byte is sent.
pub fn check_loopback_addr(addr: &str) -> Result<(), String> {
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h.trim_matches(|c| c == '[' || c == ']'),
        None => addr,
    };
    let ok = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(format!("{addr} is not a loopback address; the Hermes control plane only listens on this machine"))
    }
}

pub fn check_session_id(id: &str) -> Result<(), String> {
    if !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Ok(())
    } else {
        Err(format!("{id:?} is not a session id"))
    }
}

/// The `POST /sessions` body for a terminal session: sidecar capsules only.
pub fn build_open_body(
    model: &str,
    system: &str,
    base_url: &str,
    key: &str,
    skills: &[(String, String)],
) -> Value {
    let tools: Vec<Value> = skills
        .iter()
        .map(|(name, desc)| json!({"name": name, "description": desc, "parameters": {"type": "object"}, "host": "sidecar"}))
        .collect();
    json!({
        "model": model,
        "systemPrompt": system,
        "llm": {"baseUrl": base_url, "bearer": key},
        "tools": tools,
        "maxToolsPerRequest": 8,
    })
}

/// The `POST /briefs` body. Without a track the sidecar suggests one from the goal.
pub fn build_brief_body(
    track: Option<&str>,
    goal: &str,
    answers: &BTreeMap<String, String>,
) -> Value {
    let mut b = json!({ "goal": goal, "answers": answers });
    if let Some(t) = track {
        b["track"] = json!(t);
    }
    b
}

/// Ask a track's questions. A blank line keeps the default (the answer is left out, so the
/// sidecar fills it and marks it "default"); a choice can be typed or picked by number; an
/// invalid pick is asked again. End of input keeps the defaults for everything left.
pub fn ask_questions(
    track: &Value,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<BTreeMap<String, String>, String> {
    let mut answers = BTreeMap::new();
    let str_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    for q in track
        .get("questions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        let (id, ask, default) = (str_of(&q, "id"), str_of(&q, "ask"), str_of(&q, "default"));
        let choices: Vec<String> = q
            .get("choices")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        loop {
            if !choices.is_empty() {
                let listed: Vec<String> = choices
                    .iter()
                    .enumerate()
                    .map(|(i, c)| format!("{}) {c}", i + 1))
                    .collect();
                let _ = writeln!(out, "  {}", listed.join("  "));
            }
            let _ = write!(out, "{ask} [{default}] ");
            let _ = out.flush();
            let mut line = String::new();
            if input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
                return Ok(answers);
            }
            let typed = line.trim();
            if typed.is_empty() {
                break;
            }
            if choices.is_empty() {
                answers.insert(id.clone(), typed.to_string());
                break;
            }
            let picked = match typed.parse::<usize>() {
                Ok(n) if (1..=choices.len()).contains(&n) => Some(choices[n - 1].clone()),
                Ok(_) => None,
                Err(_) => choices
                    .iter()
                    .find(|c| c.eq_ignore_ascii_case(typed))
                    .cloned(),
            };
            match picked {
                Some(c) => {
                    answers.insert(id.clone(), c);
                    break;
                }
                None => {
                    let _ = writeln!(out, "  pick 1-{} or type one of the choices", choices.len());
                }
            }
        }
    }
    Ok(answers)
}

/// One readable line per interesting event (None for bookkeeping events).
pub fn render_event(ev: &Value) -> Option<String> {
    let s = |k: &str| ev.get(k).and_then(Value::as_str).unwrap_or("");
    match s("type") {
        "final" => Some(s("content").to_string()),
        "tool_call" => {
            let name = ev
                .pointer("/call/name")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let host = s("host");
            Some(if host == "core" {
                format!("  → {name} (runs in the app, behind its approvals)")
            } else {
                format!("  → {name}")
            })
        }
        "tool_result" => Some(format!("  ← {} ({})", s("call_id"), s("status"))),
        "verifier" => {
            let passed = ev.get("passed").and_then(Value::as_bool).unwrap_or(false);
            Some(format!(
                "  {} {}{}",
                if passed { "✓" } else { "✗" },
                s("name"),
                if passed {
                    String::new()
                } else {
                    format!(" — {}", s("detail"))
                }
            ))
        }
        "error" => Some(format!("error: {}", s("message"))),
        "done" => Some(format!("[{}]", s("outcome"))),
        _ => None,
    }
}

struct Client {
    base: String,
    bearer: String,
    http: reqwest::blocking::Client,
}

impl Client {
    fn new(args: &HermesArgs) -> Result<Self, String> {
        check_loopback_addr(&args.addr)?;
        let path = match &args.token_file {
            Some(p) => p.clone(),
            None => {
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .map_err(|_| {
                        "cannot find your home directory; pass --token-file".to_string()
                    })?;
                default_token_path(std::env::consts::OS, &home)
            }
        };
        let bearer = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read the Hermes bearer at {} ({e}). Is Citrate Core running with Hermes started?", path.display()))?
            .trim()
            .to_string();
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(40))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Client {
            base: format!("http://{}", args.addr),
            bearer,
            http,
        })
    }
    fn get(&self, path: &str) -> Result<Value, String> {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(&self.bearer)
            .send()
            .map_err(|e| format!("request failed: {e}"))?;
        Self::json(r)
    }
    fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let r = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.bearer)
            .json(body)
            .send()
            .map_err(|e| format!("request failed: {e}"))?;
        Self::json(r)
    }
    fn json(r: reqwest::blocking::Response) -> Result<Value, String> {
        let status = r.status();
        let text = r.text().unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "sidecar answered HTTP {}: {}",
                status.as_u16(),
                text.chars().take(200).collect::<String>()
            ));
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }
    fn open(&self, m: &ModelArgs) -> Result<String, String> {
        let key = m
            .llm_key_env
            .as_deref()
            .map(|v| std::env::var(v).unwrap_or_default())
            .unwrap_or_default();
        let skills: Vec<(String, String)> = self
            .get("/skills")?
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| {
                        Some((
                            s.get("name")?.as_str()?.to_string(),
                            s.get("description")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let v = self.post(
            "/sessions",
            &build_open_body(&m.model, &m.system, &m.llm_base_url, &key, &skills),
        )?;
        v.get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "the sidecar returned no session id".into())
    }
    /// Print events after `after` until a `done` (follow) or once; returns the last sequence seen.
    fn events(
        &self,
        id: &str,
        mut after: u64,
        follow: bool,
        out: &mut dyn Write,
    ) -> Result<u64, String> {
        loop {
            let page = self.get(&format!(
                "/sessions/{id}/events?after={after}&wait_ms={}",
                if follow { 15_000 } else { 0 }
            ))?;
            after = page.get("lastSeq").and_then(Value::as_u64).unwrap_or(after);
            let mut done = false;
            for e in page
                .get("events")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                let ev = e.get("event").cloned().unwrap_or(Value::Null);
                if let Some(line) = render_event(&ev) {
                    let _ = writeln!(out, "{line}");
                }
                done |= ev.get("type").and_then(Value::as_str) == Some("done");
            }
            if !follow || done {
                return Ok(after);
            }
        }
    }
}

pub fn run(args: HermesArgs) -> i32 {
    match run_inner(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("hermes: {e}");
            1
        }
    }
}

fn run_inner(args: &HermesArgs) -> Result<(), String> {
    let c = Client::new(args)?;
    let mut stdout = std::io::stdout();
    match &args.cmd {
        HermesCmd::Status => {
            println!(
                "{}",
                serde_json::to_string_pretty(&c.get("/status")?).unwrap_or_default()
            );
        }
        HermesCmd::Open(m) => println!("{}", c.open(m)?),
        HermesCmd::Send { session, text } => {
            check_session_id(session)?;
            c.post(
                &format!("/sessions/{session}/messages"),
                &json!({"text": text}),
            )?;
        }
        HermesCmd::Events {
            session,
            after,
            follow,
        } => {
            check_session_id(session)?;
            c.events(session, *after, *follow, &mut stdout)?;
        }
        HermesCmd::Stop { session } => {
            check_session_id(session)?;
            c.post(&format!("/sessions/{session}/stop"), &json!({}))?;
        }
        HermesCmd::Brief {
            track,
            goal,
            defaults,
            json: as_json,
        } => {
            // First pass with no answers: validates the goal and resolves a suggested track.
            let first = c.post(
                "/briefs",
                &build_brief_body(track.as_deref(), goal, &BTreeMap::new()),
            )?;
            let mut result = first.clone();
            if !*defaults {
                let id = first
                    .pointer("/brief/track")
                    .and_then(Value::as_str)
                    .ok_or("the sidecar returned no track")?
                    .to_string();
                let tracks = c.get("/tracks")?;
                let t = tracks
                    .as_array()
                    .and_then(|a| {
                        a.iter()
                            .find(|t| t.get("id").and_then(Value::as_str) == Some(id.as_str()))
                    })
                    .cloned()
                    .ok_or_else(|| format!("track {id} not found"))?;
                eprintln!(
                    "Track: {} (press Enter to keep a default)",
                    t.get("title").and_then(Value::as_str).unwrap_or(&id)
                );
                let answers =
                    ask_questions(&t, &mut std::io::stdin().lock(), &mut std::io::stderr())?;
                result = c.post("/briefs", &build_brief_body(Some(&id), goal, &answers))?;
            }
            if *as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result["brief"]).unwrap_or_default()
                );
            } else {
                println!("{}", result["markdown"].as_str().unwrap_or(""));
            }
        }
        HermesCmd::Chat(m) => {
            let id = c.open(m)?;
            eprintln!("session {id} — type a message, Ctrl-D to quit");
            let mut after = 0;
            let stdin = std::io::stdin();
            loop {
                eprint!("you › ");
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                if stdin
                    .lock()
                    .read_line(&mut line)
                    .map_err(|e| e.to_string())?
                    == 0
                {
                    break;
                }
                let text = line.trim();
                if text.is_empty() {
                    continue;
                }
                c.post(&format!("/sessions/{id}/messages"), &json!({"text": text}))?;
                after = c.events(&id, after, true, &mut stdout)?;
            }
            let _ = c.post(&format!("/sessions/{id}/stop"), &json!({}));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("hermes_cmd_tests.rs");
}
