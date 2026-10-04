//! HUP-S6 US-6.1 AC2 + US-6.2 — **Hermes refuses unready code and proposes the fix.**
//!
//! The deploy gate in citrate-core is the one source of truth for a deploy verdict, and
//! `contract_deploy` is refused there unless a READY record exists for exactly the bytecode being
//! deployed. This module is the agent's side of the same rule, so Hermes never even asks:
//!
//! - [`findings_from_report`] reads the raw report of one toolchain run (the same bytes core's
//!   gate parses: forge's `--json`, slither's and aderyn's SARIF, medusa's log) with this crate's
//!   own parsers and lists what blocks a deploy: each failing test by name, each scan finding at
//!   High or above by its rule id and location, each failing fuzz property, and each tool that did
//!   not complete. Free text the contract or the scanner wrote (revert strings, finding messages)
//!   is never quoted: only identifiers, severities and locations are.
//! - [`propose_fix`] turns a finding into a proposed fix: one sentence of advice from a fixed
//!   catalog and, where the cause is mechanical (a missing check the template's own tests name,
//!   an unprotected `selfdestruct`), a unified diff against the project's source. A proposal is
//!   only ever text for the member and the model; nothing here writes a file.
//! - [`is_deploy_request`] recognizes a request to deploy ("deploy it", "deploy anyway", "ship
//!   it"), and [`refusal_text`] is Hermes's answer while findings block: it declines, names every
//!   finding, gives the proposed fixes, and says no signature request was opened.
//!
//! The sidecar applies it twice: a deploy request in a session whose latest toolchain reports
//! block is answered with [`refusal_text`] without a model call, and a `contract_deploy` call the
//! model makes anyway is declined before it is announced (a [`crate::CallPolicy`]), so core never
//! sees it and no SignatureCeremony is created. Neither path can make a deploy happen: they only
//! take one away. Rule 3: nothing here signs or holds a key.

use crate::verifiers_tooling::{
    parse_forge_test_json, parse_medusa_output, parse_sarif, RunStatus, SarifProfile, Severity,
    ADERYN_SCAN_TOOL, FORGE_TEST_TOOL, MEDUSA_FUZZ_TOOL, SLITHER_SCAN_TOOL,
};

/// The tool name the guard keeps from the model while findings block.
pub const CONTRACT_DEPLOY_TOOL: &str = "contract_deploy";
/// Findings listed in a refusal (the rest are counted).
pub const MAX_LISTED: usize = 8;
/// Fix proposals with a patch in one refusal.
pub const MAX_PATCHES: usize = 3;
/// Context lines around a patch hunk.
const CONTEXT: usize = 2;
/// The longest identifier or location quoted.
const MAX_QUOTED: usize = 160;

/// One thing that blocks a deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateFinding {
    /// The toolchain tool that reported it (`forge_test`, `slither_scan`, ...).
    pub tool: String,
    pub kind: FindingKind,
    /// The test name, rule id, property name, or the run status.
    pub id: String,
    /// `High` / `Critical` for a scan finding.
    pub severity: Option<Severity>,
    /// `path[:line]` inside the project, when the tool gave one.
    pub location: Option<String>,
}

/// What kind of blocker a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// A forge test failed.
    FailingTest,
    /// A scanner finding at High or above.
    ScanFinding,
    /// A fuzzing property or assertion failed.
    FailingProperty,
    /// The tool did not complete (not installed, timed out, failed, unreadable report).
    NotCompleted,
}

/// A proposed fix for one finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixProposal {
    pub finding: GateFinding,
    /// One or two sentences, from a fixed catalog.
    pub advice: String,
    /// A unified diff against the project, when the cause is mechanical and the source matched.
    pub patch: Option<String>,
}

/// Printable ASCII only, no backticks, bounded: identifiers and paths from tool reports are quoted
/// inside markdown code spans, so nothing in them can close the span or add markup.
fn quoted(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .filter(|c| *c != '`')
        .take(MAX_QUOTED)
        .collect();
    if s.chars().count() > MAX_QUOTED {
        out.push_str("...");
    }
    out
}

fn tool_label(tool: &str) -> &'static str {
    match tool {
        FORGE_TEST_TOOL => "Forge tests",
        SLITHER_SCAN_TOOL => "Slither",
        ADERYN_SCAN_TOOL => "Aderyn",
        MEDUSA_FUZZ_TOOL => "Medusa",
        _ => "Toolchain",
    }
}

fn status_word(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Completed => "completed",
        RunStatus::NotInstalled => "not_installed",
        RunStatus::TimedOut => "timed_out",
        RunStatus::Refused => "refused",
        RunStatus::Failed => "failed",
    }
}

fn not_completed(tool: &str, id: &str) -> GateFinding {
    GateFinding {
        tool: tool.to_string(),
        kind: FindingKind::NotCompleted,
        id: id.to_string(),
        severity: None,
        location: None,
    }
}

/// What blocks a deploy in one toolchain run of `tool`: `status` is how the run ended and
/// `output` its raw report when it completed. Empty = this run blocks nothing. A tool this module
/// does not know is ignored (it is not one of the gate's checks).
pub fn findings_from_report(
    tool: &str,
    status: RunStatus,
    output: Option<&str>,
) -> Vec<GateFinding> {
    if ![
        FORGE_TEST_TOOL,
        SLITHER_SCAN_TOOL,
        ADERYN_SCAN_TOOL,
        MEDUSA_FUZZ_TOOL,
    ]
    .contains(&tool)
    {
        return Vec::new();
    }
    if status != RunStatus::Completed {
        return vec![not_completed(tool, status_word(status))];
    }
    let Some(raw) = output else {
        return vec![not_completed(tool, "no_report")];
    };
    match tool {
        FORGE_TEST_TOOL => match parse_forge_test_json(raw) {
            Err(_) => vec![not_completed(tool, "unreadable_report")],
            Ok(r) if r.failed == 0 && r.passed == 0 => vec![not_completed(tool, "no_tests_ran")],
            Ok(r) => r
                .failing
                .iter()
                .map(|name| GateFinding {
                    tool: tool.to_string(),
                    kind: FindingKind::FailingTest,
                    id: quoted(name),
                    severity: None,
                    location: name.split(':').next().map(quoted),
                })
                .collect(),
        },
        SLITHER_SCAN_TOOL | ADERYN_SCAN_TOOL => {
            let profile = if tool == SLITHER_SCAN_TOOL {
                SarifProfile::Slither
            } else {
                SarifProfile::Aderyn
            };
            match parse_sarif(raw, profile) {
                Err(_) => vec![not_completed(tool, "unreadable_report")],
                Ok(r) => r
                    .findings
                    .iter()
                    .filter(|f| f.severity >= Severity::High)
                    .map(|f| GateFinding {
                        tool: tool.to_string(),
                        kind: FindingKind::ScanFinding,
                        id: quoted(&f.rule_id),
                        severity: Some(f.severity),
                        location: f.location.as_deref().map(quoted),
                    })
                    .collect(),
            }
        }
        _ => match parse_medusa_output(raw) {
            Err(_) => vec![not_completed(tool, "unreadable_report")],
            Ok(r) => r
                .failing
                .iter()
                .map(|name| GateFinding {
                    tool: tool.to_string(),
                    kind: FindingKind::FailingProperty,
                    id: quoted(name),
                    severity: None,
                    location: None,
                })
                .collect(),
        },
    }
}

/// The gate's four checks, by tool name.
pub const GATE_TOOLS: [&str; 4] = [
    FORGE_TEST_TOOL,
    SLITHER_SCAN_TOOL,
    ADERYN_SCAN_TOOL,
    MEDUSA_FUZZ_TOOL,
];

// ------------------------------------------------------------------------------------------
// Intent
// ------------------------------------------------------------------------------------------

/// Whether `text` asks Hermes to deploy (or to deploy despite the gate). Matches "deploy",
/// "deploying", "redeploy", "ship it", "push it live", "go live" as words; a request that says
/// not to deploy ("don't deploy", "do not deploy yet") is not one.
pub fn is_deploy_request(text: &str) -> bool {
    let t = text.to_ascii_lowercase().replace(['\u{2019}', '\''], "");
    let words: Vec<&str> = t
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let negated_before = |i: usize| -> bool {
        let from = i.saturating_sub(3);
        words[from..i]
            .iter()
            .any(|w| matches!(*w, "dont" | "not" | "never" | "cannot" | "shouldnt"))
    };
    for (i, w) in words.iter().enumerate() {
        let hit = matches!(*w, "deploy" | "deploying" | "redeploy")
            || (*w == "ship"
                && words
                    .get(i + 1)
                    .is_some_and(|n| matches!(*n, "it" | "this" | "the")))
            || (*w == "live" && i > 0 && matches!(words[i - 1], "go" | "push" | "it"));
        if hit && !negated_before(i) {
            return true;
        }
    }
    false
}

// ------------------------------------------------------------------------------------------
// Fix proposals
// ------------------------------------------------------------------------------------------

/// A template test whose failure names one missing check in `mint`, and the line that restores it.
struct MissingCheck {
    test: &'static str,
    /// The source line after which the check belongs (trimmed), or `None` = first line of mint.
    after: Option<&'static str>,
    /// The check itself (trimmed); a source that already has it gets no patch.
    check: &'static str,
    advice: &'static str,
}

const MISSING_CHECKS: [MissingCheck; 3] = [
    MissingCheck {
        test: "test_mint_stops_at_the_cap",
        after: Some("uint256 remaining = MAX_SUPPLY - minted;"),
        check: "if (quantity > remaining) revert SoldOut(quantity, remaining);",
        advice: "mint must revert with SoldOut when the quantity is larger than the supply that is left, so the total can never pass MAX_SUPPLY. Restore the cap check in mint (keep the test as it is).",
    },
    MissingCheck {
        test: "test_mint_rejects_a_wrong_payment",
        after: Some("uint256 expected = PRICE * quantity;"),
        check: "if (msg.value != expected) revert WrongPayment(msg.value, expected);",
        advice: "mint must revert with WrongPayment unless exactly PRICE * quantity is paid. Restore the payment check in mint (keep the test as it is).",
    },
    MissingCheck {
        test: "test_mint_rejects_zero_and_oversized_quantities",
        after: None,
        check: "if (quantity == 0 || quantity > MAX_PER_TX) revert BadQuantity(quantity);",
        advice: "mint must revert with BadQuantity for 0 or for more than MAX_PER_TX tokens. Restore the quantity check at the top of mint (keep the test as it is).",
    },
];

/// One scan rule's advice, keyed by the rule id's last segment (slither's
/// `<impact>-<confidence>-<check>` or aderyn's detector name).
const SCAN_ADVICE: [(&str, &str); 10] = [
    ("suicidal", "Anyone can destroy the contract. Remove the function that calls selfdestruct (a mint contract never needs it)."),
    ("selfdestruct", "Remove the selfdestruct instruction and the function around it; it is deprecated and lets a caller destroy the contract or move its balance."),
    ("arbitrary-send-eth", "A caller can send the contract's SALT to any address. Send only to a fixed or owner-checked recipient (onlyOwner) and check the call's result."),
    ("reentrancy-eth", "State is written after an external call that sends value. Update state before the call (checks, effects, interactions) or add nonReentrant."),
    ("controlled-delegatecall", "A caller controls a delegatecall target. Remove the delegatecall or restrict the target to a fixed, owner-set address."),
    ("unprotected-upgrade", "Anyone can upgrade or initialize the implementation. Protect the upgrade and initializer functions with the owner check and disable initializers in the constructor."),
    ("uninitialized-state", "A state variable is read before it is ever set. Set it in the constructor or where it is declared."),
    ("arbitrary-send-erc20", "transferFrom takes the from address from the caller. Use msg.sender as from, or check an allowance the owner gave for this purpose."),
    ("unchecked-transfer", "A token transfer's return value is ignored. Use SafeERC20 or check the returned bool."),
    ("weak-prng", "Randomness comes from block values a validator can steer. Do not derive anything valuable from them."),
];

/// The last `-`-separated segment group of a slither id (`0-0-suicidal` -> `suicidal`), or the
/// id itself (aderyn's detector names).
fn rule_name(id: &str) -> &str {
    let mut parts = id.splitn(3, '-');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(rest))
            if a.chars().all(|c| c.is_ascii_digit()) && b.chars().all(|c| c.is_ascii_digit()) =>
        {
            rest
        }
        _ => id,
    }
}

/// The project-relative file a finding points at (`src/Token.sol:19` -> `src/Token.sol`), when it
/// is a plain relative path under `src/`.
fn finding_file(f: &GateFinding) -> Option<String> {
    let loc = f.location.as_deref()?;
    let path = loc.split(':').next()?;
    safe_src_path(path).then(|| path.to_string())
}

/// A relative `src/...` path with no `..`, no absolute root and no backslash.
pub fn safe_src_path(path: &str) -> bool {
    path.starts_with("src/")
        && path.ends_with(".sol")
        && !path.contains('\\')
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Unified diff of one replaced line range: `lines[start..end]` becomes `new`.
fn unified_diff(path: &str, lines: &[&str], start: usize, end: usize, new: &[String]) -> String {
    let ctx_start = start.saturating_sub(CONTEXT);
    let ctx_end = (end + CONTEXT).min(lines.len());
    let old_len = ctx_end - ctx_start;
    let new_len = old_len - (end - start) + new.len();
    // A hunk with no old lines starts at the line before (unified diff convention).
    let old_start = if old_len == 0 {
        ctx_start
    } else {
        ctx_start + 1
    };
    let new_start = if new_len == 0 {
        ctx_start
    } else {
        ctx_start + 1
    };
    let mut out = format!(
        "--- a/{path}\n+++ b/{path}\n@@ -{old_start},{old_len} +{new_start},{new_len} @@\n"
    );
    for l in &lines[ctx_start..start] {
        out.push_str(&format!(" {l}\n"));
    }
    for l in &lines[start..end] {
        out.push_str(&format!("-{l}\n"));
    }
    for l in new {
        out.push_str(&format!("+{l}\n"));
    }
    for l in &lines[end..ctx_end] {
        out.push_str(&format!(" {l}\n"));
    }
    out
}

fn indent_of(line: &str) -> &str {
    &line[..line.len() - line.trim_start().len()]
}

/// The diff that puts a missing `mint` check back, when `source` lacks it and has its anchor.
fn missing_check_patch(path: &str, source: &str, mc: &MissingCheck) -> Option<String> {
    if source.contains(mc.check) {
        return None;
    }
    let lines: Vec<&str> = source.lines().collect();
    let mint = lines
        .iter()
        .position(|l| l.trim_start().starts_with("function mint("))?;
    // The mint body ends at the first line after it that closes at the function's indentation.
    let fn_indent = indent_of(lines[mint]);
    let body_end = (mint + 1..lines.len()).find(|&i| {
        lines[i].starts_with(fn_indent) && lines[i][fn_indent.len()..].starts_with('}')
    })?;
    let at = match mc.after {
        None => mint + 1,
        Some(anchor) => (mint + 1..body_end).find(|&i| lines[i].trim() == anchor)? + 1,
    };
    let indent = if at < body_end {
        indent_of(lines[at]).to_string()
    } else {
        format!("{fn_indent}    ")
    };
    Some(unified_diff(
        path,
        &lines,
        at,
        at,
        &[format!("{indent}{}", mc.check)],
    ))
}

/// The diff that removes the function around a `selfdestruct(` (and one blank line before it).
fn remove_selfdestruct_patch(path: &str, source: &str) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let sd = lines.iter().position(|l| l.contains("selfdestruct("))?;
    let start = (0..=sd)
        .rev()
        .find(|&i| lines[i].trim_start().starts_with("function "))?;
    let indent = indent_of(lines[start]);
    let end = (sd..lines.len())
        .find(|&i| lines[i].starts_with(indent) && lines[i][indent.len()..].starts_with('}'))?
        + 1;
    let start = if start > 0 && lines[start - 1].trim().is_empty() {
        start - 1
    } else {
        start
    };
    Some(unified_diff(path, &lines, start, end, &[]))
}

/// The proposed fix for one finding. `read_source` returns a project file's text by its
/// project-relative path (`src/Token.sol`); it is only asked for paths that pass
/// [`safe_src_path`].
pub fn propose_fix(f: &GateFinding, read_source: &dyn Fn(&str) -> Option<String>) -> FixProposal {
    let read = |p: &str| -> Option<String> {
        if safe_src_path(p) {
            read_source(p)
        } else {
            None
        }
    };
    let (advice, patch) = match f.kind {
        FindingKind::NotCompleted => (
            match f.id.as_str() {
                "not_installed" => format!(
                    "{} is not installed on this machine. Install the toolchain component, then run it again; a check that did not run is never a pass.",
                    tool_label(&f.tool)
                ),
                "timed_out" => format!(
                    "{} hit its time limit. Run it again (on a smaller budget if needed); a check that did not finish is never a pass.",
                    tool_label(&f.tool)
                ),
                _ => format!(
                    "{} did not produce a usable report. Fix the build error it reported and run it again.",
                    tool_label(&f.tool)
                ),
            },
            None,
        ),
        FindingKind::FailingTest => {
            let test_fn = f.id.rsplit("::").next().unwrap_or(&f.id);
            match MISSING_CHECKS.iter().find(|m| test_fn.starts_with(m.test)) {
                Some(mc) => {
                    let patch = read("src/Token.sol")
                        .and_then(|src| missing_check_patch("src/Token.sol", &src, mc));
                    (mc.advice.to_string(), patch)
                }
                None => (
                    format!(
                        "The test {} fails. Change the contract so it passes; do not edit or delete the test.",
                        quoted(test_fn)
                    ),
                    None,
                ),
            }
        }
        FindingKind::ScanFinding => {
            let name = rule_name(&f.id);
            let advice = SCAN_ADVICE
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, a)| a.to_string())
                .unwrap_or_else(|| {
                    format!(
                        "Change the code at the reported location so the {} rule no longer fires; do not suppress the finding.",
                        quoted(&f.id)
                    )
                });
            let patch = if matches!(name, "suicidal" | "selfdestruct") {
                finding_file(f)
                    .and_then(|p| read(&p).and_then(|src| remove_selfdestruct_patch(&p, &src)))
            } else {
                None
            };
            (advice, patch)
        }
        FindingKind::FailingProperty => (
            format!(
                "The fuzzer broke {}. Its call sequence in the Medusa log shows the steps; fix the contract so the property holds, then run medusa_fuzz again.",
                quoted(&f.id)
            ),
            None,
        ),
    };
    FixProposal {
        finding: f.clone(),
        advice,
        patch,
    }
}

// ------------------------------------------------------------------------------------------
// The refusal
// ------------------------------------------------------------------------------------------

fn finding_line(f: &GateFinding) -> String {
    let what = match (f.kind, f.severity) {
        (FindingKind::ScanFinding, Some(s)) => format!(
            "{} `{}` ({})",
            tool_label(&f.tool),
            f.id,
            match s {
                Severity::Critical => "Critical",
                _ => "High",
            }
        ),
        (FindingKind::FailingTest, _) => format!("{} failing: `{}`", tool_label(&f.tool), f.id),
        (FindingKind::FailingProperty, _) => format!("{} broke `{}`", tool_label(&f.tool), f.id),
        (FindingKind::NotCompleted, _) => {
            format!("{} did not complete: `{}`", tool_label(&f.tool), f.id)
        }
        (FindingKind::ScanFinding, None) => format!("{} `{}`", tool_label(&f.tool), f.id),
    };
    match &f.location {
        Some(l) if f.kind == FindingKind::ScanFinding => format!("{what} at `{l}`"),
        _ => what,
    }
}

/// Hermes's answer to a deploy request while `findings` block: it declines, names every finding,
/// gives the proposed fixes, and says no signature request was opened. `project` is shown as the
/// folder's last component only.
pub fn refusal_text(project: &str, findings: &[GateFinding], fixes: &[FixProposal]) -> String {
    let name = project
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .map(quoted)
        .unwrap_or_default();
    let mut out = format!(
        "I won't deploy this contract. The deploy gate is NOT READY for `{name}`, and I never deploy past it, even when asked to.\n\nWhat blocks it:\n"
    );
    for f in findings.iter().take(MAX_LISTED) {
        out.push_str(&format!("- {}\n", finding_line(f)));
    }
    if findings.len() > MAX_LISTED {
        out.push_str(&format!("- and {} more\n", findings.len() - MAX_LISTED));
    }
    out.push_str("\nProposed fix:\n");
    let mut patches = 0usize;
    for p in fixes.iter().take(MAX_LISTED) {
        out.push_str(&format!("- {}: {}\n", finding_line(&p.finding), p.advice));
        if let Some(d) = &p.patch {
            if patches < MAX_PATCHES {
                patches += 1;
                out.push_str(&format!("\n```diff\n{d}```\n\n"));
            }
        }
    }
    out.push_str(
        "\nNo signature request was opened and nothing was sent to the chain. After the fix, run forge_test, slither_scan, aderyn_scan and medusa_fuzz again; Deploy opens the SignatureCeremony only when the gate reads READY.",
    );
    out
}
