//! citrate-core #681 (follow-up to #643 / #680): the final-answer check for contract-deploy
//! claims, in the sidecar, so every client gets it. That covers the `citrate hermes` CLI, a node
//! MCP client (`hermes_session_send`), turns the Tauri headless dispatcher served, and the
//! Citrate Core chat view.
//!
//! This is a port of citrate-core `src/agent/deployClaims.ts`. It applies the same rules, uses the
//! same wording and runs the same shared cases (`tests/fixtures/deploy_claims_cases.json`, pinned
//! by sha256 on both sides). In short:
//!
//! - Evidence is kept per session in a [`DeployLedger`]. It counts only from core's own tools,
//!   identified by where the call ran ([`Origin`]): a core-hosted call, or the node MCP server core
//!   registered (see [`evidence_origin`]). A same-named tool on any other MCP server contributes
//!   only the address-like strings it returned. A receipt is TRUSTED only when it sits at its fixed
//!   place in the top-level object of a `request_status` / `tasks_get` result for one of this
//!   conversation's deploy request ids, or in an `explain_tx` result for one of their transaction
//!   hashes (or sent from the member's wallet as `wallet_info` read it).
//! - The answer is read the way it is meant, not by its exact words: invisible characters are
//!   removed and look-alike letters folded; each sentence is read with the one before it and, for
//!   a list item or table row, the line that introduces it. A valid address nothing in this
//!   conversation produced is kept only where `eth_getCode` shows code and it is not called the
//!   member's or Hermes's own deploy, however it is worded.
//! - An address in a deployment claim stays only when one of these holds:
//!   - a trusted receipt names it and `eth_getCode` on 40204 returns code there now;
//!   - for someone else's contract, `eth_getCode` shows code;
//!   - in a turn that attempted no deploy, the member wrote it and there is code.
//!
//!   A malformed address is removed. A claimed deploy with no receipt, or while this turn's deploy
//!   is not confirmed, is replaced by where the deploy really stands.
//! - `eth_getCode` goes through [`CodeReader`]. With no chain RPC configured
//!   (`CITRATE_HERMES_CHAIN_RPC`), every read fails, so the code "could not be checked". It never
//!   counts as code (fail closed). One answer reads at most [`MAX_CODE_READS`] addresses, within
//!   [`CODE_CHECK_BUDGET`].

use citrate_agent_loop::{Event, EventSink, HostKind};
use citrate_agent_mcp_host::config::{ServerConfig, TransportConfig};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Where the sidecar reads `eth_getCode` for the check (set by citrate-core to the 40204 RPC).
pub const CHAIN_RPC_ENV: &str = "CITRATE_HERMES_CHAIN_RPC";
/// The citrate-core executable (set by citrate-core): the node MCP server core registers runs as
/// this program with [`NODE_MCP_STDIO_FLAG`].
pub const CORE_EXE_ENV: &str = "CITRATE_HERMES_CORE_EXE";
/// The name core's allowlist gives its node MCP server (citrate-core `NODE_SERVER_NAME`).
pub const NODE_SERVER_NAME: &str = "node";
/// The argument that runs citrate-core as its node MCP server (citrate-core `STDIO_FLAG`).
pub const NODE_MCP_STDIO_FLAG: &str = "--mcp-stdio";

/// Most address-like strings a conversation's ledger keeps from tool output.
pub const MAX_TOOL_STRINGS: usize = 4096;
/// Most distinct addresses one answer's check reads code for; the rest "could not be checked".
pub const MAX_CODE_READS: usize = 16;
/// Longest one answer's code reads may take together; later reads "could not be checked".
pub const CODE_CHECK_BUDGET: Duration = Duration::from_secs(20);

/// Where a tool ran: core itself, the node MCP server core registered, or anywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Core,
    Node,
    Other,
}

impl Origin {
    pub fn parse(s: &str) -> Option<Origin> {
        match s {
            "core" => Some(Origin::Core),
            "node" => Some(Origin::Node),
            "other" => Some(Origin::Other),
            _ => None,
        }
    }
}

/// One tool result from the turn, in the order it arrived.
#[derive(Debug, Clone, PartialEq)]
pub struct TurnToolOutput {
    /// The tool's name as the loop called it (`mcp__<server>__` prefixes are allowed).
    pub tool: String,
    /// "ok" | "error" | "denied" when known.
    pub status: Option<String>,
    pub content: String,
    /// Where the call ran. `None`: read from the name, as core does (no `mcp__` prefix = core,
    /// `mcp__node__` = the node server, any other server = other). The session always sets it.
    pub origin: Option<Origin>,
}

/// Where the call ran: its recorded origin, or the one its name implies.
pub fn origin_of(o: &TurnToolOutput) -> Origin {
    if let Some(x) = o.origin {
        return x;
    }
    if !o.tool.starts_with("mcp__") {
        Origin::Core
    } else if o.tool.starts_with("mcp__node__") {
        Origin::Node
    } else {
        Origin::Other
    }
}

/// Where a call the session ran came from. A core-hosted call is core's. An MCP tool is the node
/// server's only when the server that offers it (`server`, from the MCP host's registration of
/// that exposed name) is core's node entry: named [`NODE_SERVER_NAME`], run over stdio as the
/// citrate-core executable `core_exe` with [`NODE_MCP_STDIO_FLAG`]. Without `core_exe` no MCP
/// server is trusted. Everything else (sidecar tools, capsules, any other server) is other.
pub fn evidence_origin(
    host: Option<HostKind>,
    server: Option<&ServerConfig>,
    core_exe: Option<&Path>,
) -> Origin {
    if host == Some(HostKind::Core) {
        return Origin::Core;
    }
    let (Some(sc), Some(exe)) = (server, core_exe) else {
        return Origin::Other;
    };
    match &sc.transport {
        TransportConfig::Stdio { command, args, .. }
            if sc.name == NODE_SERVER_NAME
                && command.as_path() == exe
                && args.first().map(String::as_str) == Some(NODE_MCP_STDIO_FLAG) =>
        {
            Origin::Node
        }
        _ => Origin::Other,
    }
}

/// The citrate-core executable this sidecar was started by, if core said so.
pub fn core_exe_from_env() -> Option<PathBuf> {
    std::env::var_os(CORE_EXE_ENV)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
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
    /// At most [`MAX_TOOL_STRINGS`]; later ones are not kept, so they count as unreturned.
    pub tool_strings: HashSet<String>,
    pub wallet: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeployEvidence {
    pub state: DeployState,
    pub receipts: HashMap<String, Option<String>>,
    pub tool_strings: HashSet<String>,
    pub member_strings: HashSet<String>,
    /// Address-like strings in what core told Hermes (the member's wallet, the system prompt).
    pub context_strings: HashSet<String>,
    /// "zero" | "short".
    pub unfunded: Option<&'static str>,
    /// The member's latest message asks for a deploy ("deploy my token").
    pub deploy_requested: bool,
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
pub const REMOVED_NO_CODE: &str = "[address removed: no tool returned it and no contract is there]";
pub const REMOVED_UNCHECKED: &str =
    "[address removed: no tool returned it and its code could not be checked]";

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

// ---- reading the text the way it is meant ----

/// Characters that render as nothing (soft hyphen, zero-width and direction marks, BOM).
fn invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFE00..=0xFE0F | 0xFEFF)
}

/// Spaces other than U+0020.
fn odd_space(c: char) -> bool {
    matches!(
        c as u32,
        0x0085 | 0x00A0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000
    )
}

/// The answer with invisible characters removed, odd spaces made plain, and full-width ASCII made
/// ASCII. A sentence the check rewrites is written from this text.
pub fn plain_text(text: &str) -> String {
    text.chars()
        .filter(|c| !invisible(*c))
        .map(|c| {
            let u = c as u32;
            if odd_space(c) {
                ' '
            } else if matches!(c as u32, 0x2018 | 0x2019 | 0x02BC | 0x2032) {
                '\''
            } else if (0xFF01..=0xFF5E).contains(&u) {
                char::from_u32(u - 0xFEE0).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// Cyrillic and Greek letters that look like Latin ones, folded only for reading claims.
const LOOKALIKE: &[(char, char)] = &[
    ('\u{0430}', 'a'),
    ('\u{0435}', 'e'),
    ('\u{043E}', 'o'),
    ('\u{0440}', 'p'),
    ('\u{0441}', 'c'),
    ('\u{0443}', 'y'),
    ('\u{0445}', 'x'),
    ('\u{0456}', 'i'),
    ('\u{0458}', 'j'),
    ('\u{0455}', 's'),
    ('\u{0501}', 'd'),
    ('\u{04CF}', 'l'),
    ('\u{0410}', 'A'),
    ('\u{0412}', 'B'),
    ('\u{0415}', 'E'),
    ('\u{041A}', 'K'),
    ('\u{041C}', 'M'),
    ('\u{041D}', 'H'),
    ('\u{041E}', 'O'),
    ('\u{0420}', 'P'),
    ('\u{0421}', 'C'),
    ('\u{0422}', 'T'),
    ('\u{0425}', 'X'),
    ('\u{03B1}', 'a'),
    ('\u{03B5}', 'e'),
    ('\u{03BF}', 'o'),
    ('\u{03C1}', 'p'),
    ('\u{03BD}', 'v'),
    ('\u{0391}', 'A'),
    ('\u{0392}', 'B'),
    ('\u{0395}', 'E'),
    ('\u{0397}', 'H'),
    ('\u{0399}', 'I'),
    ('\u{039A}', 'K'),
    ('\u{039C}', 'M'),
    ('\u{039D}', 'N'),
    ('\u{039F}', 'O'),
    ('\u{03A1}', 'P'),
    ('\u{03A4}', 'T'),
    ('\u{03A5}', 'Y'),
    ('\u{03A7}', 'X'),
    ('\u{0396}', 'Z'),
];

/// `text` with look-alike letters folded to Latin and markdown emphasis taken out (for reading).
fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '*' | '_' | '`' | '~') {
            continue;
        }
        out.push(
            LOOKALIKE
                .iter()
                .find(|(k, _)| *k == c)
                .map(|(_, v)| *v)
                .unwrap_or(c),
        );
    }
    out
}

// ---- evidence ----

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

type Obj = serde_json::Map<String, Value>;

/// The result's top-level object. An MCP result may carry it as the text of its one content item;
/// that one wrapper is opened, nothing deeper.
fn top_object(content: &str) -> Option<Obj> {
    fn parse(s: &str) -> Option<Obj> {
        let t = s.trim();
        if !t.starts_with('{') {
            return None;
        }
        match serde_json::from_str::<Value>(t) {
            Ok(Value::Object(m)) => Some(m),
            _ => None,
        }
    }
    let v = parse(content)?;
    if let Some(Value::Array(items)) = v.get("content") {
        if items.len() == 1 {
            if let Some(item) = items[0].as_object() {
                if item.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(text) = item.get("text").and_then(Value::as_str) {
                        return parse(text);
                    }
                }
            }
        }
    }
    Some(v)
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

/// A pattern written in JavaScript's dialect (`\b`, `\w` and `\d` ASCII, as in the TS original;
/// `\s` and counted repeats over characters, as JavaScript counts BMP text).
fn re(p: &str) -> Regex {
    let p = p
        .replace(r"\b", r"(?-u:\b)")
        .replace(r"\W", "[^0-9A-Za-z_]")
        .replace(r"\w", "[0-9A-Za-z_]")
        .replace(r"\d", "[0-9]");
    Regex::new(&p).expect("deploy-claims pattern")
}

/// A member message that asks for a deploy ("deploy my token", "please deploy the vault").
static DEPLOY_ASK: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:deploy|redeploy|launch)\s+(?:my|the|a|an|it|this|that|our|your|these|those|them)\b|\bplease\s+(?:re)?deploy\b|^\W*(?:re)?deploy\b",
    )
});

/// A short yes ("yes", "go ahead", "do it"): a deploy request when Hermes had just offered one.
static AFFIRM: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^\W*(?:yes|yeah|yep|yup|sure|ok|okay|go ahead|do it|please do|go for it|sounds good|y)\b",
    )
});
/// Hermes offering to deploy ("Shall I deploy it?", "Want me to deploy this?").
static DEPLOY_OFFER: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:shall|should|can|may)\s+i\s+(?:go ahead and\s+)?(?:re)?deploy\b|\bwant me to\s+(?:re)?deploy\b|\bready to deploy\b[^.!\n]*\?|\b(?:re)?deploy\s+(?:it|this|that|the|your)\b[^.!\n]*\?",
    )
});
/// How many of the member's latest messages a deploy request is read from.
const REQUEST_LOOKBACK: usize = 3;

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
    r.captures(s)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// The request/task id a result's top-level object names.
fn id_of(top: &Obj) -> Option<String> {
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

/// The receipts at their fixed places: the object itself, `receipt`, `confirmation.receipt`,
/// `task.receipt`.
fn receipts_of(top: &Obj) -> Vec<&Obj> {
    let nested = |k: &str| top.get(k).and_then(|v| v.get("receipt"));
    [
        Some(top),
        top.get("receipt").and_then(Value::as_object),
        nested("confirmation").and_then(Value::as_object),
        nested("task").and_then(Value::as_object),
    ]
    .into_iter()
    .flatten()
    .filter(|o| o.contains_key("contractAddress"))
    .collect()
}

/// Read where the turn's deploys stand from its tool results, in order, on top of what the
/// conversation already established (`ledger`, updated in place).
pub fn collect_deploy_evidence(
    outputs: &[TurnToolOutput],
    ledger: &mut DeployLedger,
    member_texts: &[String],
    assistant_texts: &[String],
    member_wallet: Option<&str>,
    context_texts: &[String],
) -> DeployEvidence {
    let mut state = DeployState::None;
    let mut unfunded: Option<&'static str> = None;
    let wallet_of = |l: &DeployLedger| {
        l.wallet
            .clone()
            .or_else(|| member_wallet.map(str::to_lowercase))
    };
    for o in outputs {
        let name = base_name(&o.tool);
        let content = o.content.as_str();
        for t in address_like_tokens(content) {
            if ledger.tool_strings.len() >= MAX_TOOL_STRINGS {
                break;
            }
            ledger.tool_strings.insert(t.to_lowercase());
        }
        // Only core's own tools speak for a deploy, a balance or a receipt.
        let origin = origin_of(o);
        if origin == Origin::Other {
            continue;
        }
        let top = top_object(content);
        let failed = matches!(o.status.as_deref(), Some("error") | Some("denied"));

        if name == "wallet_info" || name == "get_balance" || name == "wallet_balance" {
            let wei = top
                .as_ref()
                .and_then(|t| t.get("balanceWei").or_else(|| t.get("balance_wei")));
            if matches!(wei, Some(Value::String(s)) if s == "0")
                || wei.and_then(Value::as_f64) == Some(0.0)
            {
                unfunded = Some("zero");
            }
            if name == "wallet_info" && !failed {
                if let Some(a) = top
                    .as_ref()
                    .and_then(|t| t.get("address"))
                    .and_then(Value::as_str)
                {
                    if is_well_formed_address(a) {
                        ledger.wallet = Some(a.to_lowercase());
                    }
                }
            }
        }
        if UNFUNDED_SHORT.is_match(content) {
            unfunded = unfunded.or(Some("short"));
        }

        if name == "contract_deploy" {
            if DEPLOY_REFUSED.is_match(content) {
                state = DeployState::Refused(content.to_string());
            } else if EXPIRED.is_match(content) && !content.starts_with("Proposed") {
                state = DeployState::Expired;
            } else if content.starts_with("Proposed the contract deploy") {
                state = DeployState::Pending;
            } else if failed || PREPARE_FAILED.is_match(content) {
                state = DeployState::Failed(content.to_string());
            }
        } else if name == "deploy_propose" {
            let refused = REFUSED.is_match(content);
            if failed || refused {
                state = if refused {
                    DeployState::Refused(content.to_string())
                } else {
                    DeployState::Failed(content.to_string())
                };
            } else {
                if let Some(t) = &top {
                    for k in ["requestId", "taskId", "id"] {
                        if let Some(s) = t.get(k).and_then(Value::as_str) {
                            ledger.request_ids.insert(s.to_string());
                        }
                    }
                    if let Some(s) = t
                        .get("task")
                        .and_then(|x| x.get("taskId"))
                        .and_then(Value::as_str)
                    {
                        ledger.request_ids.insert(s.to_string());
                    }
                }
                state = DeployState::Pending;
            }
        } else if matches!(name, "request_status" | "tasks_get" | "task_status") {
            let Some(top) = &top else { continue };
            let Some(id) = id_of(top) else { continue };
            if !ledger.request_ids.contains(&id) {
                continue;
            }
            let confirmation = top.get("confirmation").and_then(Value::as_object);
            let sent_hash = lower_str(confirmation.and_then(|c| c.get("txHash")))
                .or_else(|| first_tx_hash(content).map(|h| h.to_lowercase()));
            if let Some(h) = &sent_hash {
                ledger.tx_hashes.insert(h.clone());
            }
            let mut confirmed = false;
            for r in receipts_of(top) {
                let tx_hash =
                    lower_str(r.get("transactionHash")).or_else(|| lower_str(r.get("txHash")));
                if let Some(h) = &tx_hash {
                    ledger.tx_hashes.insert(h.clone());
                }
                let status = r.get("status").cloned().unwrap_or(Value::Null);
                let addr = r.get("contractAddress").and_then(Value::as_str);
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
            let st = top.get("state").and_then(Value::as_str);
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
                        || WAITING_INCLUDE.is_match(content)
                    {
                        state = DeployState::Sent(sent_hash);
                    } else if conf_state == Some("reverted") || REVERTED_WORD.is_match(content) {
                        state = DeployState::Reverted(sent_hash);
                    }
                }
            }
        } else if name == "explain_tx" && origin == Origin::Core && STATUS_SUCCESS.is_match(content)
        {
            // Only a transaction this conversation's deploy was sent as makes it this turn's
            // confirmed deploy; an old deploy from the member's wallet is a receipt, not news.
            let Some(created) = cap1(&CREATED, content) else {
                continue;
            };
            let tx_hash = cap1(&EXPLAIN_TX, content).map(|h| h.to_lowercase());
            let from = cap1(&FROM, content).map(|h| h.to_lowercase());
            let bound = tx_hash
                .as_ref()
                .is_some_and(|h| ledger.tx_hashes.contains(h));
            let wallet = wallet_of(ledger);
            if !bound && !(from.is_some() && from == wallet) {
                continue;
            }
            ledger
                .receipts
                .insert(created.to_lowercase(), tx_hash.clone());
            if bound {
                state = DeployState::Confirmed {
                    address: created,
                    tx_hash,
                };
            }
        }
    }
    let tokens_of = |texts: &[String]| -> HashSet<String> {
        texts
            .iter()
            .flat_map(|t| address_like_tokens(&plain_text(t)))
            .map(|a| a.to_lowercase())
            .collect()
    };
    let member_strings = tokens_of(member_texts);
    let mut context_strings = tokens_of(context_texts);
    if let Some(w) = wallet_of(ledger) {
        context_strings.insert(w);
    }
    DeployEvidence {
        state,
        receipts: ledger.receipts.clone(),
        tool_strings: ledger.tool_strings.clone(),
        member_strings,
        context_strings,
        unfunded,
        deploy_requested: deploy_requested(member_texts, assistant_texts),
    }
}

/// Read from the recent turns: one of the member's last [`REQUEST_LOOKBACK`] messages asks for a
/// deploy, or the member said yes to Hermes's offer of one.
fn deploy_requested(member_texts: &[String], assistant_texts: &[String]) -> bool {
    let read = |t: &String| fold(&plain_text(t));
    let texts: Vec<String> = member_texts.iter().map(read).collect();
    let asked_recently = texts
        .iter()
        .skip(texts.len().saturating_sub(REQUEST_LOOKBACK))
        .any(|t| DEPLOY_ASK.is_match(t));
    let offered = assistant_texts
        .last()
        .is_some_and(|t| DEPLOY_OFFER.is_match(&read(t)));
    asked_recently || (offered && texts.last().is_some_and(|t| AFFIRM.is_match(t)))
}

// ---- claims ----

static NOT_A_CLAIM: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:not|never)\s+(?:yet\s+)?(?:been\s+)?deployed\b|\b\w+n't\s+(?:yet\s+)?(?:been\s+)?deployed\b|\bno (?:contract|deploy(?:ment)?)\s+(?:was|is|has been|happened|ran)(?:\s+deployed)?\b|\b(?:will|would|can|could|should|may|might|to)\s+be\s+deployed\b|\b(?:once|until|after|before|when|if|unless)\s+(?:it(?:'s| is)?|they(?:'re| are)?|the contract (?:is )?|your contract (?:is )?)?\s*deployed\b|\bnot (?:yet )?(?:live|on[- ]?chain)\b|\bready to (?:be )?deploy(?:ed)?\b|\bdeployed nothing\b|\bnothing (?:was |has been |got )?deployed\b|\b(?:once|when|whenever|after|if|until|unless|before|as soon as)\b[^.!?\n,;]*",
    )
});
static DONE_CLAIM: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(?:has|have|had)\s+(?:now\s+)?(?:been\s+)?(?:successfully\s+)?deployed\b|\b(?:was|were|is|are|got)\s+(?:now\s+|successfully\s+)*deployed\b|\b(?:successfully|i|i've|we|we've|you've)\s+deployed\b|\bdeployed\s+(?:successfully|it|them|your|the|both|two|a|an)\b|\bdeploy(?:ment)?\s+(?:is\s+|was\s+)?(?:succeeded|complete|completed|successful|done|finished|went through|worked)\b|\b(?:is|are)\s+now\s+live\b|\bwent\s+live\b|\bnow\s+(?:live|on[- ]?chain)\b|\b(?:contract|token|it|they)\b[^.!?\n]{0,40}\b(?:is|are)\s+(?:now\s+)?(?:live|on[- ]?chain)\s+(?:at|on)\b|\b(?:live|on[- ]?chain)\s+(?:at|on)\s+0x|\bsuccessfully\s+(?:launched|created)\b|\bcreated\s+(?:your|the|a|an)\s+(?:new\s+)?(?:\w+\s+)?contract\b|\bcontract\s+(?:was|is|has been)\s+created\b|\b(?:deploy(?:ment)?|contract)\s+(?:is\s+|was\s+|has been\s+)?confirmed\b|\b(?:it|it's|it is|that's|that is|they're|they are|everything is|we're|we are)\s+(?:now\s+)?live\b|\b(?:it|that|everything)\s+went\s+through\b|^\W*(?:now\s+)?live\b|\b(?:contract|token|it|they|deployment|vault|everything)\b[^.!?\n]{0,40}\b(?:is|are)\s+(?:now\s+)?(?:live|on[- ]?chain)\b|\b(?:has been|was|is|got)\s+shipped\b|^\W*(?:shipped|launched)\b|^\W*(?:the\s+|your\s+|my\s+)?(?:[\w'-]+\s+){0,2}(?:deployed|shipped|launched)\W*$|^\W*(?:all\s+|both\s+)?deployed\b",
    )
});
static DEPLOY_WORD: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\bdeployed\b|\bdeployment address(?:es)?\b|\b(?:your|my|our)\s+(?:new\s+)?(?:\w+\s+)?contracts?\b|\blive\s+(?:at|on)\b|\bcontract(?:'s)?\s+address(?:es)?\b|\btoken(?:'s)?\s+(?:contract\s+)?address\b|\bcreated contract\b|\bnew contract\b|\bon[- ]?chain\s+at\b|\b(?:located|lives|available|found)\s+at\b|\bfind\s+(?:it|them)\s+at\b|\bcontract\s+(?:is\s+)?at\b",
    )
});
static ADDRESS_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\baddress(?:es)?\b|\bcontracts?\b|\bwallet\b|\baccount\b|\brecipient\b|\bsend(?:s|ing)?\b[^.!?\n]*\bto\b|\btransfer(?:s|red|ring)?\b[^.!?\n]*\bto\b|\bdeploy\w*\b|\blive\s+(?:at|on)\b|\btoken\b",
    )
});
static OWN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)\b(?:i|i've|i'm|we|we've|our|you|you've|your|my|me|us)\b"));
static SUBJECTLESS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^\W*(?:(?:all|both|successfully)\s+)?(?:deployed|deployment|deploy\s+(?:done|complete|succeeded)|done|success|shipped|launched|live)\b",
    )
});
/// A claim about "the deployment", "it", "the contract": in a turn where the member asked for a
/// deploy and none was attempted, that is Hermes reporting its own (nonexistent) deploy.
static DEFINITE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)^\W*(?:the|it|it's|its|this|that|they|they're|everything|all)\b"));
/// A headline-style claim ("Token deployed.", "Contract shipped!"): Hermes's own report.
static HEADLINE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)^\W*(?:the\s+|your\s+|my\s+)?(?:[\w'-]+\s+){0,2}(?:deployed|shipped|launched)\W*$")
});
/// A leading interjection or short clause ("Great,", "OK,", "Done \u{2014}", "As you asked,"):
/// the claim after it is read as if the sentence started there.
static LEAD_IN: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)^\W*(?:(?:great|ok|okay|done|all set|perfect|awesome|good news|alright|nice|excellent|sure|yes|yep|yeah|congrats|congratulations|so|and|well|success|boom|there you go|here you go)\b[\s,!.:;\u2014\u2013-]*)+|^[^,.!?:;\n\u2014\u2013]{1,30}[,:;\u2014\u2013]\s*",
    )
});
/// `'s` read as is/has before a deploy word ("It's deployed", "Your token's been deployed").
static HAS_BEEN: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b(\w+)'s\s+been\b"));
static IS_DONE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)\b(\w+)'s\s+((?:now\s+|already\s+|successfully\s+|officially\s+|fully\s+)*(?:deployed|live|on[- ]?chain|done|complete|completed|confirmed|shipped|launched|up)\b)",
    )
});
static LABEL: LazyLock<Regex> =
    LazyLock::new(|| re(r"^\s*(?:[-*+|>]|\d+[.)]\s)|^[^.!?:\n]{0,60}:\s*\S"));
static LIST_LINE: LazyLock<Regex> = LazyLock::new(|| re(r"^\s*(?:[-*+|]|\d+[.)]\s)"));
static OWN_STATUS: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^\s*I can\x27t confirm a deploy at 0x[0-9a-fA-F]{40}: (?:eth_getCode on chain \d+ returned no code there|its code on chain \d+ could not be checked)",
    )
});
static NEWLINE_END: LazyLock<Regex> = LazyLock::new(|| re(r"\n\s*$"));
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
            while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\x0c' | b'\r') {
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
    let f = fold(sentence);
    let f = HAS_BEEN.replace_all(&f, "${1} has been");
    let f = IS_DONE.replace_all(&f, "${1} is ${2}");
    NOT_A_CLAIM.replace_all(&f, " ").into_owned()
}

/// The claim with a leading interjection or short clause taken off.
fn claim_core(claim: &str) -> String {
    LEAD_IN.replace(claim, "").into_owned()
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
    SPACES.replace_all(s, " ").trim().to_string()
}

/// The plain statement of where the deploy stands, said in place of a removed claim.
pub fn deploy_status_line(ev: &DeployEvidence) -> String {
    let gas = gas_line(ev);
    match &ev.state {
        DeployState::Refused(r) => format!(
            "No contract was deployed. The node refused the deploy: {}{gas}",
            clip_chars(&squash(r), 400)
        ),
        DeployState::Failed(r) => format!(
            "No contract was deployed. The deploy could not be prepared: {}{gas}",
            clip_chars(&squash(r), 400)
        ),
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
        DeployState::Confirmed { address, .. } => {
            format!("The only deploy confirmed in this turn is {address}.{gas}")
        }
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
        _ => format!(
            "I can't confirm a deploy at {addr}: eth_getCode on chain 40204 returned no code there."
        ),
    }
}

fn verdict_words(v: &Verdict) -> &'static str {
    if matches!(v, Verdict::Empty) {
        "eth_getCode returned no code there"
    } else {
        "its code could not be checked"
    }
}

/// Check one final answer against the evidence.
pub fn check_deploy_claims(
    answer: &str,
    ev: &DeployEvidence,
    reader: &dyn CodeReader,
) -> DeployClaimCheck {
    let started = Instant::now();
    let mut cache: HashMap<String, Verdict> = HashMap::new();
    let mut code = |addr: &str| -> Verdict {
        let k = addr.to_lowercase();
        if let Some(v) = cache.get(&k) {
            return v.clone();
        }
        let v = if cache.len() >= MAX_CODE_READS {
            Verdict::Unknown(format!(
                "this answer names more than {MAX_CODE_READS} addresses"
            ))
        } else if started.elapsed() >= CODE_CHECK_BUDGET {
            Verdict::Unknown("the code check ran out of time".into())
        } else {
            match reader.read_code(addr) {
                Ok(c) if c.is_contract && c.code_size > 0 => Verdict::Code,
                Ok(_) => Verdict::Empty,
                Err(e) => Verdict::Unknown(e),
            }
        };
        cache.insert(k, v.clone());
        v
    };
    let attempted = ev.state != DeployState::None;
    let confirmed = matches!(ev.state, DeployState::Confirmed { .. });
    let written = |k: &str| {
        ev.tool_strings.contains(k)
            || ev.member_strings.contains(k)
            || ev.context_strings.contains(k)
    };
    let mut findings: Vec<String> = Vec::new();
    let mut status: Vec<String> = Vec::new();
    let say = |status: &mut Vec<String>, line: String| {
        if !status.contains(&line) {
            status.push(line);
        }
    };
    let mut out: Vec<String> = Vec::new();
    let text = plain_text(answer);
    let mut prev = String::new();
    let mut lead = String::new();

    for sentence in sentences(&text) {
        let claim = claim_text(sentence);
        let list_line = LIST_LINE.is_match(sentence);
        // The sentence before, and the line that introduces a list or table, give a bare
        // "Address: 0x…" or a table cell its meaning.
        let around = format!("{prev} {}", if list_line { lead.as_str() } else { "" });
        let around_claim = claim_text(&around);
        let label = LABEL.is_match(sentence);
        let tokens: Vec<String> = if OWN_STATUS.is_match(sentence) {
            Vec::new()
        } else {
            address_like_tokens(sentence)
                .into_iter()
                .filter(|t| address_shape(t) != Shape::Other)
                .collect()
        };
        let core = claim_core(&claim);
        let deploy_claimed = DONE_CLAIM.is_match(&claim) || DONE_CLAIM.is_match(&core);
        let ctx_claimed = deploy_claimed || (label && DONE_CLAIM.is_match(&around_claim));
        let in_claim = !tokens.is_empty()
            && (ctx_claimed
                || DEPLOY_WORD.is_match(&claim)
                || (label && DEPLOY_WORD.is_match(&around_claim)));
        let own = OWN.is_match(&claim)
            || SUBJECTLESS.is_match(&claim)
            || SUBJECTLESS.is_match(&core)
            || HEADLINE.is_match(&core)
            || (ev.deploy_requested
                && !attempted
                && (DEFINITE.is_match(&claim) || DEFINITE.is_match(&core)))
            || (label
                && (OWN.is_match(&around_claim)
                    || SUBJECTLESS.is_match(&claim_text(&prev))
                    || SUBJECTLESS.is_match(&claim_text(&lead))));
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
                } else if ADDRESS_CONTEXT.is_match(&fold(sentence)) {
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
                    verdict_words(&v)
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
            if in_claim && ctx_claimed && attempted && !confirmed {
                findings.push(format!(
                    "removed a deploy claim at {t}: this turn's deploy is not confirmed"
                ));
                say(&mut status, deploy_status_line(ev));
                drop = true;
                continue;
            }
            if in_claim && own {
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
                findings.push(format!(
                    "removed a deploy claim at {t}: no trusted deploy receipt in this conversation names it"
                ));
                say(&mut status, deploy_status_line(ev));
                drop = true;
                continue;
            }
            if !in_claim && written(&k) {
                continue;
            }
            // Someone else's contract, or an address nothing in this conversation produced,
            // however it is worded: grounded only when there is code at it.
            let v = code(t);
            if matches!(v, Verdict::Code) {
                continue;
            }
            if in_claim {
                findings.push(format!(
                    "removed a deploy claim at {t}: {}",
                    verdict_words(&v)
                ));
                say(&mut status, code_line(t, &v));
                drop = true;
            } else {
                findings.push(format!(
                    "removed {t}: no tool returned it and {}",
                    verdict_words(&v)
                ));
                replace.insert(
                    t.clone(),
                    if matches!(v, Verdict::Empty) {
                        REMOVED_NO_CODE
                    } else {
                        REMOVED_UNCHECKED
                    },
                );
            }
        }

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

        if !sentence.trim().is_empty() {
            prev = sentence.to_string();
            if !list_line {
                lead = sentence.to_string();
            }
        }
        if drop {
            // Keep the sentence's line break so the rest of the answer keeps its shape.
            out.push(if NEWLINE_END.is_match(sentence) {
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
    let mut text = THREE_NEWLINES
        .replace_all(&joined, "\n\n")
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

/// Says where a call ran from its exposed name and the host its `tool_call` announced.
pub type OriginFn<'a> = Box<dyn Fn(&str, Option<HostKind>) -> Origin + Send + Sync + 'a>;

/// Wraps a turn's event sink. It keeps the turn's tool results (named by their `tool_call`, with
/// where each call ran) and checks every `final` answer before any reader sees it. A changed answer is preceded by an
/// `answer_check` event, and the corrected text is what is emitted (and what
/// [`ClaimGuardSink::corrections`] reports, so the session history gets it too).
pub struct ClaimGuardSink<'a> {
    inner: &'a dyn EventSink,
    ledger: &'a Mutex<DeployLedger>,
    reader: &'a dyn CodeReader,
    member_texts: Vec<String>,
    assistant_texts: Vec<String>,
    context_texts: Vec<String>,
    origin: OriginFn<'a>,
    names: Mutex<HashMap<String, (String, Origin)>>,
    outputs: Mutex<Vec<TurnToolOutput>>,
    corrections: Mutex<Vec<(String, String)>>,
}

impl<'a> ClaimGuardSink<'a> {
    pub fn new(
        inner: &'a dyn EventSink,
        ledger: &'a Mutex<DeployLedger>,
        reader: &'a dyn CodeReader,
        member_texts: Vec<String>,
        assistant_texts: Vec<String>,
        context_texts: Vec<String>,
        origin: OriginFn<'a>,
    ) -> Self {
        ClaimGuardSink {
            inner,
            ledger,
            reader,
            member_texts,
            assistant_texts,
            context_texts,
            origin,
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
            Ok(mut l) => collect_deploy_evidence(
                &outputs,
                &mut l,
                &self.member_texts,
                &self.assistant_texts,
                None,
                &self.context_texts,
            ),
            Err(_) => collect_deploy_evidence(
                &outputs,
                &mut DeployLedger::default(),
                &self.member_texts,
                &self.assistant_texts,
                None,
                &self.context_texts,
            ),
        };
        check_deploy_claims(content, &ev, self.reader)
    }
}

impl EventSink for ClaimGuardSink<'_> {
    fn emit(&self, ev: Event) {
        match &ev {
            Event::ToolCall { call, host, .. } => {
                let origin = (self.origin)(&call.name, *host);
                if let Ok(mut n) = self.names.lock() {
                    n.insert(call.id.clone(), (call.name.clone(), origin));
                }
            }
            Event::ToolResult {
                call_id,
                status,
                content,
                ..
            } => {
                // A result with no announced call is nobody's evidence.
                let (tool, origin) = self
                    .names
                    .lock()
                    .ok()
                    .and_then(|n| n.get(call_id).cloned())
                    .unwrap_or((String::new(), Origin::Other));
                if let Ok(mut o) = self.outputs.lock() {
                    o.push(TurnToolOutput {
                        tool,
                        status: Some((*status).to_string()),
                        content: content.clone(),
                        origin: Some(origin),
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
