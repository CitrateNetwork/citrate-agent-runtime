//! Per-session host tool-set allowlist (`toolSets` on `POST /sessions`), for Store daemons
//! (citrate-core #356).
//!
//! The sidecar hosts tool sets of its own (search, the browser, MCP servers, the contract
//! toolchain, installed skills, skill learning, installed capsules, the grant-document file
//! tools and `shell_run`). Without an allowlist a session gets every set the sidecar process was
//! started with, as before. With one, the session gets ONLY the sets it names (deny by default):
//! every other set's tools are absent from the tool list, and a call to one is refused (the loop
//! answers "unknown tool", and the session's sidecar host has no executor for it either).
//!
//! The set names are citrate-core's permission names for these sets
//! (`docs/STORE_CATALOG.md`, "Tools the Hermes sidecar hosts itself"), so core passes a Store
//! daemon's approved permissions through unchanged. `files` and `shell_run` have no Store
//! permission in core today; they are named so that an allowlist can leave them out explicitly.

/// One sidecar-hosted tool set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSet {
    /// `web_search`, `read_url` (`CITRATE_HERMES_SEARCH=1`).
    WebSearch,
    /// `browser_*` (`CITRATE_HERMES_BROWSER=1`).
    WebBrowse,
    /// `mcp__<server>__<tool>` (`CITRATE_HERMES_MCP`).
    Mcp,
    /// `forge_test`, `slither_scan`, `aderyn_scan`, `medusa_fuzz` (`CITRATE_HERMES_TOOLCHAIN=1`).
    Toolchain,
    /// `skill_load` and the per-turn skill index (`CITRATE_HERMES_SKILLS`).
    SkillsRead,
    /// `learn_propose` (`CITRATE_HERMES_LEARN_DIR`).
    LearnPropose,
    /// Installed capsules (`CITRATE_HERMES_CAPSULES`): every sidecar-hosted spec core passes.
    CapsulesRun,
    /// `file_*`, `sheet_*`, `fs_*`, `project_create` (need a grant document).
    Files,
    /// `shell_run` (needs `CITRATE_HERMES_SHELL_RUN=1` and a grant document).
    ShellRun,
}

impl HostSet {
    /// Every set, in the order the capability lists them.
    pub const ALL: [HostSet; 9] = [
        HostSet::WebSearch,
        HostSet::WebBrowse,
        HostSet::Mcp,
        HostSet::Toolchain,
        HostSet::SkillsRead,
        HostSet::LearnPropose,
        HostSet::CapsulesRun,
        HostSet::Files,
        HostSet::ShellRun,
    ];

    /// The canonical wire name.
    pub fn name(self) -> &'static str {
        match self {
            HostSet::WebSearch => "web_search",
            HostSet::WebBrowse => "web_browse",
            HostSet::Mcp => "mcp",
            HostSet::Toolchain => "toolchain",
            HostSet::SkillsRead => "skills_read",
            HostSet::LearnPropose => "learn_propose",
            HostSet::CapsulesRun => "capsules_run",
            HostSet::Files => "files",
            HostSet::ShellRun => "shell_run",
        }
    }

    /// The set a wire name names (exact match only).
    pub fn parse(name: &str) -> Option<HostSet> {
        HostSet::ALL.into_iter().find(|s| s.name() == name)
    }

    fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

/// Every canonical set name, as `GET /status` reports them under `capabilities`.
pub fn set_names() -> Vec<&'static str> {
    HostSet::ALL.into_iter().map(HostSet::name).collect()
}

/// The host sets one session may use. `Unrestricted` = no allowlist was given (every set the
/// sidecar runs with, as before).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSets {
    Unrestricted,
    Only(u16),
}

impl HostSets {
    /// From a session's `toolSets`: absent = unrestricted; present = exactly those sets. An
    /// unknown name refuses the whole request (nothing is guessed).
    pub fn from_allowlist(names: Option<&[String]>) -> Result<HostSets, String> {
        let Some(names) = names else {
            return Ok(HostSets::Unrestricted);
        };
        let mut bits = 0u16;
        for n in names {
            let set = HostSet::parse(n).ok_or_else(|| {
                format!(
                    "toolSets names an unknown tool set '{n}'; this sidecar knows: {}",
                    set_names().join(", ")
                )
            })?;
            bits |= set.bit();
        }
        Ok(HostSets::Only(bits))
    }

    /// Whether this session may use `set`.
    pub fn allows(self, set: HostSet) -> bool {
        match self {
            HostSets::Unrestricted => true,
            HostSets::Only(bits) => bits & set.bit() != 0,
        }
    }

    /// The allowed set names in canonical order, or `None` when unrestricted.
    pub fn names(self) -> Option<Vec<&'static str>> {
        match self {
            HostSets::Unrestricted => None,
            HostSets::Only(_) => Some(
                HostSet::ALL
                    .into_iter()
                    .filter(|s| self.allows(*s))
                    .map(HostSet::name)
                    .collect(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_match_core_permission_names() {
        // citrate-core docs/STORE_CATALOG.md "Covering permission" column, plus files/shell_run.
        assert_eq!(
            set_names(),
            vec![
                "web_search",
                "web_browse",
                "mcp",
                "toolchain",
                "skills_read",
                "learn_propose",
                "capsules_run",
                "files",
                "shell_run",
            ]
        );
        for s in HostSet::ALL {
            assert_eq!(HostSet::parse(s.name()), Some(s));
        }
    }

    #[test]
    fn absent_is_unrestricted_empty_allows_nothing_unknown_is_refused() {
        let all = HostSets::from_allowlist(None).expect("absent");
        assert!(HostSet::ALL.into_iter().all(|s| all.allows(s)));
        assert_eq!(all.names(), None);

        let none = HostSets::from_allowlist(Some(&[])).expect("empty");
        assert!(HostSet::ALL.into_iter().all(|s| !none.allows(s)));
        assert_eq!(none.names(), Some(vec![]));

        let one = HostSets::from_allowlist(Some(&["web_search".to_string()])).expect("one");
        assert!(one.allows(HostSet::WebSearch));
        assert!(HostSet::ALL
            .into_iter()
            .filter(|s| *s != HostSet::WebSearch)
            .all(|s| !one.allows(s)));

        let err = HostSets::from_allowlist(Some(&["search".to_string()])).unwrap_err();
        assert!(err.contains("unknown tool set 'search'"), "{err}");
    }
}
