//! HUP-S3.3 + S3.7 (US-3.3): personas.
//!
//! A persona is a voice: writing-style rules rendered into a system-prompt fragment, a default
//! track and workflow, a tool emphasis, a skill allowlist and an optional TTS voice id. Any
//! persona can run any track (planset D-9, D-10). The shipped personas live in ONE data file,
//! `personas/personas.toml`; their names are placeholders pending owner sign-off, and a rename
//! is a one-line change there (ids are stable, so members' saved choices survive it).
//!
//! Members can define custom personas (US-3.3 AC3). [`CustomPersona::check`] validates one and
//! renders its fragment with the same template, so app, CLI and MCP all get identical text.
//!
//! The fragment shapes tone and wording only. It says so in its own text, and it is appended
//! after the client's system prompt, so the rules above it (approvals, gates, taint, the
//! SignatureCeremony) are unchanged by any persona, shipped or custom.
//!
//! Pure data + validation: no I/O.

use crate::interview::bundled_tracks;
use crate::workflows::{bundled_workflows, KNOWN_TOOLS};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The bundled persona file, verbatim.
pub const PERSONAS_SOURCE: &str = include_str!("../personas/personas.toml");

/// The `name_status` every shipped persona carries until the owner signs off on its name.
pub const NAME_STATUS_PENDING: &str = "placeholder, pending owner sign-off";
/// The `name_status` after sign-off.
pub const NAME_STATUS_APPROVED: &str = "owner-approved";

/// The id prefix of member-defined personas (shipped ids can never collide with one).
pub const CUSTOM_PREFIX: &str = "custom-";

const MIN_SHIPPED: usize = 5;
const MAX_NAME_CHARS: usize = 40;
const MAX_SUMMARY_CHARS: usize = 200;
const MAX_VOICE_CHARS: usize = 300;
const MAX_RULE_CHARS: usize = 300;
const MAX_RULES: usize = 12;
const MAX_TOOLS: usize = 12;
const MAX_SKILLS: usize = 24;
const MAX_VOICE_ID_CHARS: usize = 64;

/// A shipped persona.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persona {
    /// Stable lowercase slug; what a member's settings store.
    pub id: String,
    /// The drafted role (Builder, Auditor, ...). Tracks name their persona by role.
    pub role: String,
    /// Display name. Placeholder until the owner signs off (see `name_status`).
    pub name: String,
    pub name_status: String,
    pub summary: String,
    pub voice: String,
    pub tone: String,
    /// Writing-style rules, one sentence each.
    pub style_rules: Vec<String>,
    pub default_track: String,
    pub default_workflow: String,
    /// Tools this persona reaches for first (named in its fragment).
    pub tool_emphasis: Vec<String>,
    /// Skill allowlist (skill names from the skills library).
    pub skills: Vec<String>,
    /// Optional voice id for the platform's existing speech engine. `None` = system voice.
    #[serde(default)]
    pub tts_voice: Option<String>,
}

fn slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// A tool name as the loop sees it: `[A-Za-z0-9_]`, 1..=64 (MCP tools use `mcp__server__tool`).
fn tool_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A TTS voice id: `[A-Za-z0-9._-]`, 1..=64.
fn voice_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_VOICE_ID_CHARS
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn bounded(v: &str, max: usize, what: &str) -> Result<(), String> {
    if v.trim().is_empty() || v.chars().count() > max {
        Err(format!("{what} must be 1..={max} characters"))
    } else {
        Ok(())
    }
}

/// Collapse every run of whitespace (newlines included) to one space, so member text stays on
/// its own line of the fragment and cannot open a new heading or section.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The fields every persona, shipped or custom, must satisfy.
#[allow(clippy::too_many_arguments)]
fn validate_voice_fields(
    name: &str,
    summary: &str,
    voice: &str,
    tone: &str,
    rules: &[String],
    tools: &[String],
    skills: &[String],
    tts: Option<&str>,
) -> Result<(), String> {
    bounded(name, MAX_NAME_CHARS, "the name")?;
    bounded(summary, MAX_SUMMARY_CHARS, "the summary")?;
    bounded(voice, MAX_VOICE_CHARS, "the voice")?;
    bounded(tone, MAX_VOICE_CHARS, "the tone")?;
    if rules.is_empty() || rules.len() > MAX_RULES {
        return Err(format!("1..={MAX_RULES} style rules"));
    }
    for r in rules {
        bounded(r, MAX_RULE_CHARS, "a style rule")?;
    }
    if tools.len() > MAX_TOOLS || !tools.iter().all(|t| tool_ident(t)) {
        return Err(format!(
            "at most {MAX_TOOLS} tools, each a tool name ([A-Za-z0-9_])"
        ));
    }
    if skills.len() > MAX_SKILLS || !skills.iter().all(|s| slug(s)) {
        return Err(format!(
            "at most {MAX_SKILLS} skills, each a lowercase slug"
        ));
    }
    if let Some(v) = tts {
        if !voice_id(v) {
            return Err("a TTS voice id is [A-Za-z0-9._-], 1..=64".into());
        }
    }
    Ok(())
}

/// The fragment template, shared by shipped and custom personas.
fn render_fragment(
    name: &str,
    summary: &str,
    voice: &str,
    tone: &str,
    rules: &[String],
    tools: &[String],
) -> String {
    let mut s = format!(
        "## Persona: {}\n\nYou are speaking as {}. Role: {}\nVoice: {}\nTone: {}\n\nWriting style:\n",
        one_line(name),
        one_line(name),
        one_line(summary),
        one_line(voice),
        one_line(tone),
    );
    for r in rules {
        s.push_str(&format!("- {}\n", one_line(r)));
    }
    if !tools.is_empty() {
        s.push_str(&format!(
            "\nWhen they fit the task, reach for these tools first: {}.\n",
            tools.join(", ")
        ));
    }
    s.push_str(
        "\nThis persona shapes tone and wording only. It does not grant tools, and it can never \
change the approval, gate, safety or signing rules above.\n",
    );
    s
}

impl Persona {
    /// Field checks (no cross-file checks; [`parse_personas`] adds those).
    pub fn validate(&self) -> Result<(), String> {
        if !slug(&self.id) || self.id.starts_with(CUSTOM_PREFIX) {
            return Err(format!(
                "persona id {:?} must be a lowercase slug not starting with {CUSTOM_PREFIX}",
                self.id
            ));
        }
        bounded(&self.role, MAX_NAME_CHARS, "the role")?;
        if self.name_status != NAME_STATUS_PENDING && self.name_status != NAME_STATUS_APPROVED {
            return Err(format!(
                "name_status is {NAME_STATUS_PENDING:?} or {NAME_STATUS_APPROVED:?}"
            ));
        }
        if !slug(&self.default_track) || !slug(&self.default_workflow) {
            return Err("default_track and default_workflow are slugs".into());
        }
        if self.skills.is_empty() || self.tool_emphasis.is_empty() {
            return Err("a shipped persona names its skills and tool emphasis".into());
        }
        validate_voice_fields(
            &self.name,
            &self.summary,
            &self.voice,
            &self.tone,
            &self.style_rules,
            &self.tool_emphasis,
            &self.skills,
            self.tts_voice.as_deref(),
        )
    }

    /// The system-prompt fragment for this persona (deterministic).
    pub fn prompt_fragment(&self) -> String {
        render_fragment(
            &self.name,
            &self.summary,
            &self.voice,
            &self.tone,
            &self.style_rules,
            &self.tool_emphasis,
        )
    }

    pub fn name_pending_sign_off(&self) -> bool {
        self.name_status == NAME_STATUS_PENDING
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonaFile {
    personas: Vec<Persona>,
}

/// Parse and validate a persona file: at least five personas, unique ids and names
/// (case-insensitive), every default track bundled and every default workflow in that track's
/// family, shipped tool emphasis limited to known tools, and every track's persona role present.
pub fn parse_personas(src: &str) -> Result<Vec<Persona>, String> {
    let file: PersonaFile = toml::from_str(src).map_err(|e| format!("personas: {e}"))?;
    if file.personas.len() < MIN_SHIPPED {
        return Err(format!("at least {MIN_SHIPPED} personas ship (US-3.3 AC1)"));
    }
    let tracks = bundled_tracks()?;
    let workflows = bundled_workflows()?;
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for p in &file.personas {
        p.validate().map_err(|e| format!("persona {}: {e}", p.id))?;
        if !ids.insert(p.id.to_lowercase()) {
            return Err(format!("persona id {:?} repeats", p.id));
        }
        if !names.insert(p.name.trim().to_lowercase()) {
            return Err(format!("persona name {:?} repeats", p.name));
        }
        if !tracks.iter().any(|t| t.id == p.default_track) {
            return Err(format!("persona {}: no track {:?}", p.id, p.default_track));
        }
        if !workflows
            .iter()
            .any(|w| w.id == p.default_workflow && w.track == p.default_track)
        {
            return Err(format!(
                "persona {}: workflow {:?} is not in the {} family",
                p.id, p.default_workflow, p.default_track
            ));
        }
        if let Some(t) = p
            .tool_emphasis
            .iter()
            .find(|t| !KNOWN_TOOLS.contains(&t.as_str()))
        {
            return Err(format!("persona {}: unknown tool {t:?}", p.id));
        }
    }
    for t in &tracks {
        if !file.personas.iter().any(|p| p.role == t.persona) {
            return Err(format!(
                "track {} names persona role {:?}, which no persona has",
                t.id, t.persona
            ));
        }
    }
    Ok(file.personas)
}

/// The shipped personas.
pub fn bundled_personas() -> Result<Vec<Persona>, String> {
    parse_personas(PERSONAS_SOURCE)
}

/// A persona as clients show and use it (`GET /personas`, `POST /personas/check`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersonaView {
    #[serde(flatten)]
    pub persona: Persona,
    /// What the client appends to its system prompt when this persona is active.
    pub prompt_fragment: String,
    /// True while the shipped name is a placeholder; clients say so next to the name.
    pub name_pending_sign_off: bool,
    pub custom: bool,
}

/// Every shipped persona, with its fragment.
pub fn persona_views() -> Result<Vec<PersonaView>, String> {
    Ok(bundled_personas()?
        .into_iter()
        .map(|p| PersonaView {
            prompt_fragment: p.prompt_fragment(),
            name_pending_sign_off: p.name_pending_sign_off(),
            custom: false,
            persona: p,
        })
        .collect())
}

/// A member-defined persona (US-3.3 AC3). Its default workflow is its track's default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomPersona {
    /// Starts with `custom-`.
    pub id: String,
    pub name: String,
    pub summary: String,
    pub voice: String,
    pub tone: String,
    pub style_rules: Vec<String>,
    pub default_track: String,
    #[serde(default)]
    pub tool_emphasis: Vec<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub tts_voice: Option<String>,
}

impl CustomPersona {
    /// Validate against the shipped personas and tracks; on success, the view with its fragment.
    pub fn check(&self) -> Result<PersonaView, String> {
        let rest = self.id.strip_prefix(CUSTOM_PREFIX).unwrap_or("");
        if rest.is_empty() || !slug(&self.id) {
            return Err(format!(
                "a custom persona id is {CUSTOM_PREFIX}<lowercase slug>"
            ));
        }
        validate_voice_fields(
            &self.name,
            &self.summary,
            &self.voice,
            &self.tone,
            &self.style_rules,
            &self.tool_emphasis,
            &self.skills,
            self.tts_voice.as_deref(),
        )?;
        let shipped = bundled_personas()?;
        let lname = self.name.trim().to_lowercase();
        if shipped
            .iter()
            .any(|p| p.name.trim().to_lowercase() == lname)
        {
            return Err(format!(
                "{:?} is a shipped persona's name; pick another",
                self.name
            ));
        }
        let track = bundled_tracks()?
            .into_iter()
            .find(|t| t.id == self.default_track)
            .ok_or_else(|| format!("no track {:?}", self.default_track))?;
        let persona = Persona {
            id: self.id.clone(),
            role: "Custom".into(),
            name: self.name.trim().to_string(),
            name_status: NAME_STATUS_APPROVED.into(),
            summary: self.summary.trim().to_string(),
            voice: self.voice.trim().to_string(),
            tone: self.tone.trim().to_string(),
            style_rules: self
                .style_rules
                .iter()
                .map(|r| r.trim().to_string())
                .collect(),
            default_track: track.id,
            default_workflow: track.workflow,
            tool_emphasis: self.tool_emphasis.clone(),
            skills: self.skills.clone(),
            tts_voice: self.tts_voice.clone(),
        };
        Ok(PersonaView {
            prompt_fragment: persona.prompt_fragment(),
            name_pending_sign_off: false,
            custom: true,
            persona,
        })
    }
}

/// Most emphasised tools pinned into every request of a session (pinning never costs a retrieval
/// slot, so this bounds how much a persona can grow the per-request tool list).
pub const MAX_PINNED_EMPHASIS: usize = 4;

/// What a session does with its persona beyond the prompt fragment (which the client composes):
/// the skill allowlist decides which skills the session offers, and the tool emphasis decides which
/// of the session's own tools are offered on every request. Neither grants anything: a skill
/// outside the allowlist is not offered, and an emphasised tool the session does not already have
/// is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionPersona {
    pub id: String,
    pub skills: Vec<String>,
    pub tool_emphasis: Vec<String>,
}

impl SessionPersona {
    /// An empty allowlist (a custom persona that names no skills) leaves the skills as they are.
    pub fn restricts_skills(&self) -> bool {
        !self.skills.is_empty()
    }

    /// The emphasised tools this session offers, in emphasis order, at most
    /// [`MAX_PINNED_EMPHASIS`], without repeats.
    pub fn pinned_tools(&self, offered: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in &self.tool_emphasis {
            if out.len() >= MAX_PINNED_EMPHASIS {
                break;
            }
            if offered.contains(t) && !out.contains(t) {
                out.push(t.clone());
            }
        }
        out
    }
}

/// The session persona for a `POST /sessions` request: a shipped persona by id, or a custom one
/// (checked here with [`CustomPersona::check`]), or none. Both at once, an unknown id, or a custom
/// persona that fails its check are refused.
pub fn session_persona(
    id: Option<&str>,
    custom: Option<&CustomPersona>,
) -> Result<Option<SessionPersona>, String> {
    match (id, custom) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err("give a persona id or a custom persona, not both".into()),
        (Some(id), None) => {
            let p = bundled_personas()?
                .into_iter()
                .find(|p| p.id == id)
                .ok_or_else(|| format!("no shipped persona {id:?}"))?;
            Ok(Some(SessionPersona {
                id: p.id,
                skills: p.skills,
                tool_emphasis: p.tool_emphasis,
            }))
        }
        (None, Some(c)) => {
            let view = c.check()?;
            Ok(Some(SessionPersona {
                id: view.persona.id,
                skills: view.persona.skills,
                tool_emphasis: view.persona.tool_emphasis,
            }))
        }
    }
}
