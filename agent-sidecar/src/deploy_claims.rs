//! citrate-core #681 (follow-up to #643 / #680): the final-answer check for contract-deploy
//! claims, in the sidecar, so every client gets it. That covers the `citrate hermes` CLI, a node
//! MCP client (`hermes_session_send`), turns the Tauri headless dispatcher served, and the
//! Citrate Core chat view.
//!
//! This is a port of citrate-core `src/agent/deployClaims.ts`. It applies the same rules, uses the
//! same wording and runs the same shared cases (`tests/fixtures/deploy_claims_cases.json`, pinned
//! by sha256 on both sides). In short:
//!
//! - Evidence is kept per session in a [`DeployLedger`]. It holds the deploy request ids the
//!   node's `deploy_propose` returned and the transaction hashes those requests were sent as. A
//!   receipt is TRUSTED only when it comes from the tool that produces it and is bound to this
//!   conversation: a `request_status` / `tasks_get` result for one of those request ids, or an
//!   `explain_tx` result for one of those hashes (or sent from the member's wallet as `wallet_info`
//!   read it). The ledger also keeps every address-like string a tool returned.
//! - An address in a deployment claim stays only when one of these holds:
//!   - a trusted receipt names it and `eth_getCode` on 40204 returns code there now;
//!   - for someone else's contract, `eth_getCode` shows code;
//!   - in a turn that attempted no deploy, the member wrote it and there is code.
//!
//!   A malformed address is removed. A claimed deploy with no receipt is replaced by where the
//!   deploy really stands.
//! - `eth_getCode` goes through [`CodeReader`]. With no chain RPC configured
//!   (`CITRATE_HERMES_CHAIN_RPC`), every read fails, so the code "could not be checked". It never
//!   counts as code (fail closed).

use citrate_agent_loop::{Event, EventSink};
use regex::bytes::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

/// Where the sidecar reads `eth_getCode` for the check (set by citrate-core to the 40204 RPC).
pub const CHAIN_RPC_ENV: &str = "CITRATE_HERMES_CHAIN_RPC";

/// One tool result from the turn, in the order it arrived.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnToolOutput {
    /// The tool's name as the loop called it (`mcp__<server>__` prefixes are allowed).
    pub tool: String,
    /// "ok" | "error" | "denied" when known.
    pub status: Option<String>,
    pub content: String,
}

/// Where the turn's latest deploy attempt stands.
#[derive(Debug, Clone, PartialEq)]
pub enum DeployState {
    None,
    Refused(String),
    Failed(String),
    Pending,
    Declined,
    Expired,
    Sent(Option<String>),
    Reverted(Option<String>),
    Confirmed {
        address: String,
        tx_hash: Option<String>,
    },
}

/// What one conversation has established so far (kept across its turns by the session).
#[derive(Debug, Clone, Default)]
pub struct DeployLedger {
    pub request_ids: HashSet<String>,
    pub tx_hashes: HashSet<String>,
    /// Trusted receipt addresses (lowercase) -> their transaction hash.
    pub receipts: HashMap<String, Option<String>>,
    pub tool_strings: HashSet<String>,
    pub wallet: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeployEvidence {
    pub state: DeployState,
    pub receipts: HashMap<String, Option<String>>,
    pub tool_strings: HashSet<String>,
    pub member_strings: HashSet<String>,
    /// "zero" | "short".
    pub unfunded: Option<&'static str>,
}

/// What the code read says about an address.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CodeRead {
    pub is_contract: bool,
    pub code_size: usize,
}

/// `eth_getCode` at an address on chain 40204. An error is "could not be checked".
pub trait CodeReader: Send + Sync {
    fn read_code(&self, address: &str) -> Result<CodeRead, String>;
}

/// The check's result.
#[derive(Debug, Clone, PartialEq)]
pub struct DeployClaimCheck {
    pub text: String,
    pub changed: bool,
    pub findings: Vec<String>,
}

pub const REMOVED_ADDRESS: &str = "[address removed: not a valid 40-hex address]";
pub const REMOVED_UNGROUNDED: &str = "[address removed: no tool returned it]";

// ---- tokens ----

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Every address-like token (`0x` + 30..50 ASCII letters/digits, not inside a longer word), with
/// its byte range, in order.
fn address_like_spans(text: &str) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'0' && b[i + 1] == b'x' && (i == 0 || !alnum(b[i - 1])) {
            let mut j = i + 2;
            while j < b.len() && alnum(b[j]) {
                j += 1;
            }
            let n = j - (i + 2);
            if (30..=50).contains(&n) {
                out.push((i, j));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

pub fn address_like_tokens(text: &str) -> Vec<String> {
    address_like_spans(text)
        .into_iter()
        .map(|(s, e)| text[s..e].to_string())
        .collect()
}

/// The first transaction hash (`0x` + exactly 64 hex, not inside a longer word).
fn first_tx_hash(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] == b'0' && b[i + 1] == b'x' && (i == 0 || !alnum(b[i - 1])) {
            let start = i + 2;
            let mut j = start;
            while j < b.len() && j - start < 64 && b[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j - start == 64 && (j == b.len() || !alnum(b[j])) {
                return Some(text[i..j].to_string());
            }
        }
        i += 1;
    }
    None
}

pub fn is_well_formed_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|c| c.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Shape {
    Valid,
    Malformed,
    Other,
}

pub fn address_shape(t: &str) -> Shape {
    if is_well_formed_address(t) {
        return Shape::Valid;
    }
    let hex_only =
        t.len() > 2 && t.starts_with("0x") && t[2..].bytes().all(|c| c.is_ascii_hexdigit());
    if !hex_only {
        return Shape::Malformed;
    }
    let n = t.len() - 2;
    if (38..=42).contains(&n) {
        Shape::Malformed
    } else {
        Shape::Other
    }
}

/// The tool name without the sidecar's `mcp__<server>__` prefix.
fn base_name(tool: &str) -> &str {
    if let Some(rest) = tool.strip_prefix("mcp__") {
        // `mcp__.+?__(.+)`: the server is at least one character, then the first `__` after it.
        if rest.len() > 1 {
            if let Some(pos) = rest[1..].find("__") {
                let name = &rest[1 + pos + 2..];
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }
    tool
}

// ---- JSON ----

fn json_values(content: &str) -> Vec<Value> {
    fn visit(raw: &str, depth: usize, out: &mut Vec<Value>) {
        let t = raw.trim();
        if depth > 3 || !(t.starts_with('{') || t.starts_with('[')) {
            return;
        }
        let Ok(v) = serde_json::from_str::<Value>(t) else {
            return;
        };
        out.push(v.clone());
        let mut strings = Vec::new();
        collect_strings(&v, &mut strings);
        for s in strings {
            visit(&s, depth + 1, out);
        }
    }
    let mut out = Vec::new();
    visit(content, 0, &mut out);
    out
}

fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// Every object inside `v`, itself included, outermost first.
fn objects_of<'a>(v: &'a Value, out: &mut Vec<&'a serde_json::Map<String, Value>>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| objects_of(x, out)),
        Value::Object(m) => {
            out.push(m);
            m.values().for_each(|x| objects_of(x, out));
        }
        _ => {}
    }
}

fn receipt_ok(v: &Value) -> bool {
    matches!(v, Value::String(s) if s == "success" || s == "0x1")
        || v.as_f64() == Some(1.0)
        || v == &Value::Bool(true)
}

fn receipt_reverted(v: &Value) -> bool {
    matches!(v, Value::String(s) if s == "reverted" || s == "0x0")
        || v.as_f64() == Some(0.0)
        || v == &Value::Bool(false)
}

fn lower_str(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_lowercase)
}

fn re(p: &str) -> Regex {
    // ASCII semantics, like the JavaScript originals.
    Regex::new(&format!("(?-u){p}")).expect("deploy-claims pattern")
}

static UNFUNDED_SHORT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)insufficient funds|not enough (?:salt|funds|balance)|balance is (?:too low|short)|cannot pay (?:the |for )?(?:deploy )?gas|can't pay (?:the |for )?(?:deploy )?gas",
    )
});
static DEPLOY_REFUSED: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)Deploy refused"));
static EXPIRED: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)expired"));
static REFUSED: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)refused"));
static PREPARE_FAILED: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^couldn't prepare the deploy"));
static WAITING_INCLUDE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)waiting for the chain to include it"));
static REVERTED_WORD: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)reverted"));
static STATUS_SUCCESS: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^Status: success\b"));
static CREATED: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?m)^Created contract (0x[0-9a-fA-F]{40})\b"));
static EXPLAIN_TX: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^explain_tx (0x[0-9a-fA-F]{64})\b"));
static FROM: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)^From (0x[0-9a-fA-F]{40})\b"));

fn cap1(r: &Regex, s: &str) -> Option<String> {
    r.captures(s.as_bytes())
        .and_then(|c| c.get(1))
        .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
}

/// The request/task id a request_status or tasks_get result is about (its top-level object).
fn request_id_of(objects: &[&serde_json::Map<String, Value>]) -> Option<String> {
    let top = objects.first()?;
    for k in ["id", "requestId", "taskId"] {
        if let Some(s) = top.get(k).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    top.get("task")
        .and_then(|t| t.get("taskId"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Read where the turn's deploys stand from its tool results, in order, on top of what the
/// conversation already established (`ledger`, updated in place).
pub fn collect_deploy_evidence(
    outputs: &[TurnToolOutput],
    ledger: &mut DeployLedger,
    member_texts: &[String],
    member_wallet: Option<&str>,
) -> DeployEvidence {
    let mut state = DeployState::None;
    let mut unfunded: Option<&'static str> = None;
    for o in outputs {
        let name = base_name(&o.tool);
        let content = o.content.as_str();
        for t in address_like_tokens(content) {
            ledger.tool_strings.insert(t.to_lowercase());
        }
        let values = json_values(content);
        let mut objects = Vec::new();
        for v in &values {
            objects_of(v, &mut objects);
        }
        let failed = matches!(o.status.as_deref(), Some("error") | Some("denied"));

        if name == "wallet_info" || name == "get_balance" || name == "wallet_balance" {
            for obj in &objects {
                let wei = obj.get("balanceWei").or_else(|| obj.get("balance_wei"));
                if matches!(wei, Some(Value::String(s)) if s == "0")
                    || wei.and_then(Value::as_f64) == Some(0.0)
                {
                    unfunded = Some("zero");
                }
            }
            if name == "wallet_info" && !failed {
                if let Some(a) = objects
                    .first()
                    .and_then(|o| o.get("address"))
                    .and_then(Value::as_str)
                {
                    if is_well_formed_address(a) {
                        ledger.wallet = Some(a.to_lowercase());
                    }
                }
            }
        }
        if UNFUNDED_SHORT.is_match(content.as_bytes()) {
            unfunded = unfunded.or(Some("short"));
        }

        if name == "contract_deploy" {
            if DEPLOY_REFUSED.is_match(content.as_bytes()) {
                state = DeployState::Refused(content.to_string());
            } else if EXPIRED.is_match(content.as_bytes()) && !content.starts_with("Proposed") {
                state = DeployState::Expired;
            } else if content.starts_with("Proposed the contract deploy") {
                state = DeployState::Pending;
            } else if failed || PREPARE_FAILED.is_match(content.as_bytes()) {
                state = DeployState::Failed(content.to_string());
            }
        } else if name == "deploy_propose" {
            let refused = REFUSED.is_match(content.as_bytes());
            if failed || refused {
                state = if refused {
                    DeployState::Refused(content.to_string())
                } else {
                    DeployState::Failed(content.to_string())
                };
            } else {
                for obj in &objects {
                    for k in ["requestId", "taskId", "id"] {
                        if let Some(s) = obj.get(k).and_then(Value::as_str) {
                            ledger.request_ids.insert(s.to_string());
                        }
                    }
                }
                state = DeployState::Pending;
            }
        } else if matches!(name, "request_status" | "tasks_get" | "task_status") {
            let Some(id) = request_id_of(&objects) else {
                continue;
            };
            if !ledger.request_ids.contains(&id) {
                continue;
            }
            let confirmation = objects
                .iter()
                .find_map(|x| x.get("confirmation").filter(|c| c.is_object()))
                .and_then(Value::as_object);
            let sent_hash = lower_str(confirmation.and_then(|c| c.get("txHash")))
                .or_else(|| first_tx_hash(content).map(|h| h.to_lowercase()));
            if let Some(h) = &sent_hash {
                ledger.tx_hashes.insert(h.clone());
            }
            let mut confirmed = false;
            for obj in &objects {
                if !obj.contains_key("contractAddress") {
                    continue;
                }
                let tx_hash =
                    lower_str(obj.get("transactionHash")).or_else(|| lower_str(obj.get("txHash")));
                if let Some(h) = &tx_hash {
                    ledger.tx_hashes.insert(h.clone());
                }
                let status = obj.get("status").cloned().unwrap_or(Value::Null);
                let addr = obj.get("contractAddress").and_then(Value::as_str);
                if receipt_ok(&status) && addr.is_some_and(is_well_formed_address) {
                    let a = addr.unwrap_or_default();
                    ledger.receipts.insert(a.to_lowercase(), tx_hash.clone());
                    state = DeployState::Confirmed {
                        address: a.to_string(),
                        tx_hash,
                    };
                    confirmed = true;
                } else if receipt_reverted(&status) {
                    state = DeployState::Reverted(tx_hash);
                    confirmed = true;
                }
            }
            if confirmed {
                continue;
            }
            let st = objects
                .first()
                .and_then(|o| o.get("state"))
                .and_then(Value::as_str);
            let conf_state = confirmation
                .and_then(|c| c.get("state"))
                .and_then(Value::as_str);
            match st {
                Some("pending") => state = DeployState::Pending,
                Some("rejected") | Some("declined") => state = DeployState::Declined,
                Some("expired") => state = DeployState::Expired,
                Some("failed") => state = DeployState::Failed(content.to_string()),
                _ => {
                    if matches!(conf_state, Some("waiting") | Some("unknown"))
                        || WAITING_INCLUDE.is_match(content.as_bytes())
                    {
                        state = DeployState::Sent(sent_hash);
                    } else if conf_state == Some("reverted")
                        || REVERTED_WORD.is_match(content.as_bytes())
                    {
                        state = DeployState::Reverted(sent_hash);
                    }
                }
            }
        } else if name == "explain_tx" && STATUS_SUCCESS.is_match(content.as_bytes()) {
            let Some(created) = cap1(&CREATED, content) else {
                continue;
            };
            let tx_hash = cap1(&EXPLAIN_TX, content).map(|h| h.to_lowercase());
            let from = cap1(&FROM, content).map(|h| h.to_lowercase());
            let wallet = ledger
                .wallet
                .clone()
                .or_else(|| member_wallet.map(str::to_lowercase));
            let own = tx_hash
                .as_ref()
                .is_some_and(|h| ledger.tx_hashes.contains(h))
                || (from.is_some() && from == wallet);
            if !own {
                continue;
            }
            ledger
                .receipts
                .insert(created.to_lowercase(), tx_hash.clone());
            state = DeployState::Confirmed {
                address: created,
                tx_hash,
            };
        }
    }
    let mut member_strings = HashSet::new();
    for t in member_texts {
        for a in address_like_tokens(t) {
            member_strings.insert(a.to_lowercase());
        }
    }
    DeployEvidence {
        state,
        receipts: ledger.receipts.clone(),
        tool_strings: ledger.tool_strings.clone(),
        member_strings,
        unfunded,
    }
}

// ---- claims ----

static NOT_A_CLAIM: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:not|never)\s+(?:yet\s+)?(?:been\s+)?deployed\b|\b\w+n't\s+(?:yet\s+)?(?:been\s+)?deployed\b|\bno (?:contract|deploy(?:ment)?)\s+(?:was|is|has been|happened|ran)(?:\s+deployed)?\b|\b(?:will|would|can|could|should|may|might|to)\s+be\s+deployed\b|\b(?:once|until|after|before|when|if|unless)\s+(?:it(?:'s| is)?|they(?:'re| are)?|the contract (?:is )?|your contract (?:is )?)?\s*deployed\b|\bnot (?:yet )?live\b|\bready to (?:be )?deploy(?:ed)?\b",
    )
});
static DONE_CLAIM: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:has|have|had)\s+(?:now\s+)?(?:been\s+)?(?:successfully\s+)?deployed\b|\b(?:was|were|is|are|got)\s+(?:now\s+|successfully\s+)*deployed\b|\b(?:successfully|i|i've|we|we've|you've)\s+deployed\b|\bdeployed\s+(?:successfully|it|them|your|the|both|two|a|an)\b|\bdeployment\s+(?:succeeded|is complete|completed|was successful|went through|is done)\b|\b(?:is|are)\s+now\s+live\b|\bwent\s+live\b|\blive\s+(?:at|on)\s+0x|^\W*(?:all\s+|both\s+)?deployed\b",
    )
});
static DEPLOY_WORD: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\bdeployed\b|\bdeployment address(?:es)?\b|\blive\s+(?:at|on)\b|\bcontract address(?:es)?\b|\bcreated contract\b|\bnew contract\b",
    )
});
static ADDRESS_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\baddress(?:es)?\b|\bcontracts?\b|\bwallet\b|\baccount\b|\brecipient\b|\bsend(?:s|ing)?\b[^.!?\n]*\bto\b|\btransfer(?:s|red|ring)?\b[^.!?\n]*\bto\b|\bdeploy\w*\b|\blive\s+(?:at|on)\b|\btoken\b",
    )
});
static OWN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(?:i|i've|i'm|we|we've|our|you|you've|your|my|me|us)\b"));
static THREE_NEWLINES: LazyLock<Regex> = LazyLock::new(|| re(r"\n{3,}"));
static SPACES: LazyLock<Regex> = LazyLock::new(|| re(r"\s+"));

/// Split text into sentences, keeping every character. A sentence ends at a line break, or at
/// `.`, `!` or `?` that is not followed by a letter or digit ("1.2" and "v0.5" stay whole), and
/// takes the whitespace after its end with it.
pub fn sentences(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let end = c == b'\n'
            || (matches!(c, b'.' | b'!' | b'?') && (i + 1 >= b.len() || !alnum(b[i + 1])));
        i += 1;
        if end {
            while i < b.len() && (b[i] as char).is_ascii_whitespace() {
                i += 1;
            }
            out.push(&text[start..i]);
            start = i;
        }
    }
    if start < b.len() {
        out.push(&text[start..]);
    }
    out
}

fn claim_text(sentence: &str) -> String {
    String::from_utf8_lossy(&NOT_A_CLAIM.replace_all(sentence.as_bytes(), &b" "[..])).into_owned()
}

fn is(r: &Regex, s: &str) -> bool {
    r.is_match(s.as_bytes())
}

fn clip_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn gas_line(ev: &DeployEvidence) -> &'static str {
    match ev.unfunded {
        Some("zero") => " The wallet holds 0 SALT, so it cannot pay deploy gas yet.",
        Some("short") => " The wallet does not have enough SALT to pay the deploy gas.",
        _ => "",
    }
}

fn squash(s: &str) -> String {
    String::from_utf8_lossy(&SPACES.replace_all(s.as_bytes(), &b" "[..]))
        .trim()
        .to_string()
}

/// The plain statement of where the deploy stands, said in place of a removed claim.
pub fn deploy_status_line(ev: &DeployEvidence) -> String {
    let gas = gas_line(ev);
    match &ev.state {
        DeployState::Refused(r) => format!("No contract was deployed. The node refused the deploy: {}{gas}", clip_chars(&squash(r), 400)),
        DeployState::Failed(r) => format!("No contract was deployed. The deploy could not be prepared: {}{gas}", clip_chars(&squash(r), 400)),
        DeployState::Pending => format!("No contract is deployed yet. The deploy is waiting for your approval in Citrate Core; nothing is signed or sent until you approve it, and there is no contract address until the chain includes the deploy.{gas}"),
        DeployState::Declined => format!("No contract was deployed: the deploy request was declined, so nothing was signed or sent.{gas}"),
        DeployState::Expired => format!("No contract was deployed: the deploy request expired before it was approved, so nothing was sent.{gas}"),
        DeployState::Sent(h) => format!(
            "The deploy was approved and sent{}, but the chain has not included it yet, so there is no contract address yet.{gas}",
            h.as_ref().map(|h| format!(" ({h})")).unwrap_or_default()
        ),
        DeployState::Reverted(h) => format!(
            "No contract was deployed: the deploy transaction{} reverted, so nothing was created on chain.{gas}",
            h.as_ref().map(|h| format!(" {h}")).unwrap_or_default()
        ),
        DeployState::Confirmed { address, .. } => format!("The only deploy confirmed in this turn is {address}.{gas}"),
        DeployState::None => format!("No deploy ran in this conversation turn, so no contract was deployed by it. There is no contract address to report.{gas}"),
    }
}

#[derive(Clone)]
enum Verdict {
    Code,
    Empty,
    Unknown(String),
}

fn code_line(addr: &str, v: &Verdict) -> String {
    match v {
        Verdict::Unknown(why) => format!(
            "I can't confirm a deploy at {addr}: its code on chain 40204 could not be checked ({}).",
            clip_chars(why, 200)
        ),
        _ => format!("I can't confirm a deploy at {addr}: eth_getCode on chain 40204 returned no code there."),
    }
}

/// Check one final answer against the evidence.
pub fn check_deploy_claims(
    answer: &str,
    ev: &DeployEvidence,
    reader: &dyn CodeReader,
) -> DeployClaimCheck {
    let mut cache: HashMap<String, Verdict> = HashMap::new();
    let mut code = |addr: &str| -> Verdict {
        let k = addr.to_lowercase();
        cache
            .entry(k)
            .or_insert_with(|| match reader.read_code(addr) {
                Ok(c) if c.is_contract && c.code_size > 0 => Verdict::Code,
                Ok(_) => Verdict::Empty,
                Err(e) => Verdict::Unknown(e),
            })
            .clone()
    };
    let attempted = ev.state != DeployState::None;
    let written = |k: &str| ev.tool_strings.contains(k) || ev.member_strings.contains(k);
    let mut findings: Vec<String> = Vec::new();
    let mut status: Vec<String> = Vec::new();
    let say = |status: &mut Vec<String>, line: String| {
        if !status.contains(&line) {
            status.push(line);
        }
    };
    let mut out: Vec<String> = Vec::new();

    for sentence in sentences(answer) {
        let claim = claim_text(sentence);
        let tokens: Vec<String> = address_like_tokens(sentence)
            .into_iter()
            .filter(|t| address_shape(t) != Shape::Other)
            .collect();
        let deploy_claimed = is(&DONE_CLAIM, &claim);
        let in_claim = !tokens.is_empty() && (deploy_claimed || is(&DEPLOY_WORD, &claim));
        let own = is(&OWN, &claim);
        let mut drop = false;
        let mut replace: HashMap<String, &'static str> = HashMap::new();

        for t in &tokens {
            let k = t.to_lowercase();
            if address_shape(t) == Shape::Malformed {
                if written(&k) {
                    continue;
                }
                if in_claim {
                    findings.push(format!(
                        "removed a deploy claim with {t}, which is not a valid address ({} characters after 0x, or non-hex characters)",
                        t.len() - 2
                    ));
                    say(&mut status, deploy_status_line(ev));
                    drop = true;
                } else if is(&ADDRESS_CONTEXT, sentence) {
                    findings.push(format!(
                        "removed {t}: not a valid address (0x + 40 hex characters)"
                    ));
                    replace.insert(t.clone(), REMOVED_ADDRESS);
                }
                continue;
            }
            if ev.receipts.contains_key(&k) {
                if !in_claim {
                    continue;
                }
                let v = code(t);
                if matches!(v, Verdict::Code) {
                    continue;
                }
                findings.push(format!(
                    "removed a deploy claim at {t}: a trusted receipt names it, but {}",
                    if matches!(v, Verdict::Empty) {
                        "eth_getCode returned no code there"
                    } else {
                        "its code could not be checked"
                    }
                ));
                say(&mut status, code_line(t, &v));
                drop = true;
                continue;
            }
            if attempted && !written(&k) {
                findings.push(format!(
                    "removed {t}: this turn attempted a deploy and no tool returned that address"
                ));
                say(&mut status, deploy_status_line(ev));
                if in_claim {
                    drop = true;
                } else {
                    replace.insert(t.clone(), REMOVED_UNGROUNDED);
                }
                continue;
            }
            if !in_claim {
                continue;
            }
            if own {
                if !attempted && ev.member_strings.contains(&k) {
                    let v = code(t);
                    if matches!(v, Verdict::Code) {
                        continue;
                    }
                    findings.push(format!(
                        "removed a claim about the member's contract at {t}: {}",
                        if matches!(v, Verdict::Empty) {
                            "no code there"
                        } else {
                            "its code could not be checked"
                        }
                    ));
                    say(&mut status, code_line(t, &v));
                    drop = true;
                    continue;
                }
                findings.push(format!("removed a deploy claim at {t}: no trusted deploy receipt in this conversation names it"));
                say(&mut status, deploy_status_line(ev));
                drop = true;
                continue;
            }
            let v = code(t);
            if matches!(v, Verdict::Code) {
                continue;
            }
            findings.push(format!(
                "removed a deploy claim at {t}: {}",
                if matches!(v, Verdict::Empty) {
                    "eth_getCode returned no code there"
                } else {
                    "its code could not be checked"
                }
            ));
            say(&mut status, code_line(t, &v));
            drop = true;
        }

        let confirmed = matches!(ev.state, DeployState::Confirmed { .. });
        if !drop
            && tokens.is_empty()
            && deploy_claimed
            && !confirmed
            && (attempted || own)
            && !(own && !attempted && !ev.receipts.is_empty())
        {
            findings.push(format!(
                "removed \"{}\": no trusted deploy receipt in this turn",
                clip_chars(sentence.trim(), 120)
            ));
            say(&mut status, deploy_status_line(ev));
            drop = true;
        }

        if drop {
            // `/\n\s*$/`: the sentence's line break is kept so the answer keeps its shape.
            let keeps_break = sentence
                .rfind('\n')
                .is_some_and(|p| sentence[p..].trim().is_empty());
            out.push(if keeps_break {
                "\n".into()
            } else {
                String::new()
            });
            continue;
        }
        if replace.is_empty() {
            out.push(sentence.to_string());
        } else {
            let mut s = String::with_capacity(sentence.len());
            let mut last = 0;
            for (a, b) in address_like_spans(sentence) {
                s.push_str(&sentence[last..a]);
                let tok = &sentence[a..b];
                s.push_str(replace.get(tok).copied().unwrap_or(tok));
                last = b;
            }
            s.push_str(&sentence[last..]);
            out.push(s);
        }
    }

    if findings.is_empty() {
        return DeployClaimCheck {
            text: answer.to_string(),
            changed: false,
            findings,
        };
    }
    let joined = out.concat();
    let mut text =
        String::from_utf8_lossy(&THREE_NEWLINES.replace_all(joined.as_bytes(), &b"\n\n"[..]))
            .trim()
            .to_string();
    if !status.is_empty() {
        let mut line = status.join(" ");
        if !status.iter().any(|s| s.contains("SALT")) {
            line.push_str(gas_line(ev));
        }
        text = if text.is_empty() {
            line
        } else {
            format!("{text}\n\n{line}")
        };
    }
    DeployClaimCheck {
        text,
        changed: true,
        findings,
    }
}

// ---- code readers ----

/// No chain RPC configured: every read fails, so nothing counts as code.
pub struct NoChain;

impl CodeReader for NoChain {
    fn read_code(&self, _address: &str) -> Result<CodeRead, String> {
        Err(format!(
            "no chain RPC is configured for Hermes ({CHAIN_RPC_ENV})"
        ))
    }
}

/// `eth_getCode` over JSON-RPC at `url` (the 40204 RPC citrate-core passes).
pub struct RpcCodeReader {
    url: String,
    timeout: Duration,
}

impl RpcCodeReader {
    pub fn new(url: impl Into<String>) -> Self {
        RpcCodeReader {
            url: url.into(),
            timeout: Duration::from_secs(8),
        }
    }
}

/// The hex `eth_getCode` result as a code read.
pub fn code_read_of(result: &Value) -> Result<CodeRead, String> {
    let hex = result
        .as_str()
        .ok_or("eth_getCode returned no hex string")?;
    let body = hex
        .strip_prefix("0x")
        .ok_or("eth_getCode returned a value without 0x")?;
    if body.len() % 2 != 0 || !body.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("eth_getCode returned malformed hex".into());
    }
    let n = body.len() / 2;
    Ok(CodeRead {
        is_contract: n > 0,
        code_size: n,
    })
}

impl CodeReader for RpcCodeReader {
    fn read_code(&self, address: &str) -> Result<CodeRead, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| e.to_string())?;
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [address, "latest"]});
        let resp: Value = client
            .post(&self.url)
            .json(&body)
            .send()
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("eth_getCode failed: {e}"))?
            .json()
            .map_err(|e| format!("eth_getCode returned no JSON: {e}"))?;
        if let Some(err) = resp.get("error") {
            return Err(format!("eth_getCode error: {err}"));
        }
        code_read_of(resp.get("result").unwrap_or(&Value::Null))
    }
}

/// The reader for this process: the configured chain RPC, or [`NoChain`] (fail closed).
pub fn reader_from_env() -> std::sync::Arc<dyn CodeReader> {
    match std::env::var(CHAIN_RPC_ENV) {
        Ok(url) if url.starts_with("http://") || url.starts_with("https://") => {
            std::sync::Arc::new(RpcCodeReader::new(url))
        }
        _ => std::sync::Arc::new(NoChain),
    }
}

// ---- the guard on a session's event stream ----

/// Wraps a turn's event sink. It keeps the turn's tool results (named by their `tool_call`) and
/// checks every `final` answer before any reader sees it. A changed answer is preceded by an
/// `answer_check` event, and the corrected text is what is emitted (and what
/// [`ClaimGuardSink::corrections`] reports, so the session history gets it too).
pub struct ClaimGuardSink<'a> {
    inner: &'a dyn EventSink,
    ledger: &'a Mutex<DeployLedger>,
    reader: &'a dyn CodeReader,
    member_texts: Vec<String>,
    names: Mutex<HashMap<String, String>>,
    outputs: Mutex<Vec<TurnToolOutput>>,
    corrections: Mutex<Vec<(String, String)>>,
}

impl<'a> ClaimGuardSink<'a> {
    pub fn new(
        inner: &'a dyn EventSink,
        ledger: &'a Mutex<DeployLedger>,
        reader: &'a dyn CodeReader,
        member_texts: Vec<String>,
    ) -> Self {
        ClaimGuardSink {
            inner,
            ledger,
            reader,
            member_texts,
            names: Mutex::new(HashMap::new()),
            outputs: Mutex::new(Vec::new()),
            corrections: Mutex::new(Vec::new()),
        }
    }

    /// Each corrected answer: (what the model wrote, what was emitted instead).
    pub fn corrections(&self) -> Vec<(String, String)> {
        self.corrections
            .lock()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    fn check(&self, content: &str) -> DeployClaimCheck {
        let outputs = self.outputs.lock().map(|o| o.clone()).unwrap_or_default();
        let ev = match self.ledger.lock() {
            Ok(mut l) => collect_deploy_evidence(&outputs, &mut l, &self.member_texts, None),
            Err(_) => collect_deploy_evidence(
                &outputs,
                &mut DeployLedger::default(),
                &self.member_texts,
                None,
            ),
        };
        check_deploy_claims(content, &ev, self.reader)
    }
}

impl EventSink for ClaimGuardSink<'_> {
    fn emit(&self, ev: Event) {
        match &ev {
            Event::ToolCall { call, .. } => {
                if let Ok(mut n) = self.names.lock() {
                    n.insert(call.id.clone(), call.name.clone());
                }
            }
            Event::ToolResult {
                call_id,
                status,
                content,
                ..
            } => {
                let tool = self
                    .names
                    .lock()
                    .ok()
                    .and_then(|n| n.get(call_id).cloned())
                    .unwrap_or_default();
                if let Ok(mut o) = self.outputs.lock() {
                    o.push(TurnToolOutput {
                        tool,
                        status: Some((*status).to_string()),
                        content: content.clone(),
                    });
                }
            }
            Event::Final { content } => {
                let checked = self.check(content);
                if checked.changed {
                    if let Ok(mut c) = self.corrections.lock() {
                        c.push((content.clone(), checked.text.clone()));
                    }
                    self.inner.emit(Event::AnswerCheck {
                        findings: checked.findings,
                    });
                    self.inner.emit(Event::Final {
                        content: checked.text,
                    });
                    return;
                }
            }
            _ => {}
        }
        self.inner.emit(ev);
    }
}

/// Put the corrected answers into the history the model is sent next turn (the latest assistant
/// message that holds the original text).
pub fn apply_corrections(
    history: &mut [citrate_agent_loop::Message],
    corrections: &[(String, String)],
) {
    for (orig, fixed) in corrections {
        if let Some(m) = history
            .iter_mut()
            .rev()
            .find(|m| m.role == citrate_agent_loop::Role::Assistant && m.content == *orig)
        {
            m.content = fixed.clone();
        }
    }
}
