//! HUP-S3.2 — one loader for agentskills.io `SKILL.md` skills, a token-bounded description index,
//! and the `skill_load` tool. Skills are instructions only: nothing here executes a script.

use citrate_agent_loop::skills::{
    parse_skill_md, skill_load_spec, SkillError, SkillHost, SkillLibrary, SkillSource,
    MAX_DESCRIPTION_LEN, MAX_NAME_LEN, MAX_REF_BYTES, MAX_SKILL_FILE_BYTES, SKILL_LOAD_TOOL,
};
use citrate_agent_loop::{CharTokenCounter, HostKind, ToolCall, ToolHost, ToolOutcome};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static N: AtomicUsize = AtomicUsize::new(0);

/// A fresh scratch directory under the OS temp dir (removed on drop).
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "citrate-skills-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn skill(root: &Path, name: &str, description: &str, body: &str) -> PathBuf {
    let dir = root.join(name);
    write(
        &dir.join("SKILL.md"),
        &format!("---\nname: {name}\ndescription: {description}\n---\n{body}"),
    );
    dir
}

fn call(args: serde_json::Value) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: SKILL_LOAD_TOOL.into(),
        arguments: args.to_string(),
    }
}

// ---------------------------------------------------------------------------------------------
// Frontmatter parsing
// ---------------------------------------------------------------------------------------------

#[test]
fn a_valid_skill_md_parses_name_description_and_body() {
    let (fm, body) = parse_skill_md(
        "---\nname: gh-cli\ndescription: Use the gh CLI for GitHub work.\nlicense: Apache-2.0\n---\n# gh-cli\n\nSteps.\n",
    )
    .unwrap();
    assert_eq!(fm.name, "gh-cli");
    assert_eq!(fm.description, "Use the gh CLI for GitHub work.");
    assert_eq!(fm.license.as_deref(), Some("Apache-2.0"));
    assert_eq!(body, "# gh-cli\n\nSteps.\n");
}

#[test]
fn quoted_and_folded_descriptions_are_supported() {
    let (fm, _) =
        parse_skill_md("---\nname: a\ndescription: \"Says: hi, there\"\n---\nbody").unwrap();
    assert_eq!(fm.description, "Says: hi, there");
    let (fm, _) = parse_skill_md(
        "---\nname: b\ndescription: >-\n  Folded onto\n  one line.\nmetadata:\n  author: citrate\n  version: \"1.0\"\nallowed-tools: Read Grep\n---\nbody",
    )
    .unwrap();
    assert_eq!(fm.description, "Folded onto one line.");
    assert_eq!(
        fm.metadata.get("author").map(String::as_str),
        Some("citrate")
    );
    assert_eq!(fm.metadata.get("version").map(String::as_str), Some("1.0"));
    assert_eq!(
        fm.allowed_tools,
        vec!["Read".to_string(), "Grep".to_string()]
    );
    let (fm, _) =
        parse_skill_md("---\nname: c\ndescription: |\n  Line one.\n  Line two.\n---\nbody")
            .unwrap();
    assert_eq!(fm.description, "Line one.\nLine two.");
}

#[test]
fn missing_or_unterminated_frontmatter_is_rejected() {
    assert_eq!(
        parse_skill_md("# no frontmatter\n").unwrap_err(),
        SkillError::NoFrontmatter
    );
    assert_eq!(
        parse_skill_md("---\nname: a\ndescription: d\n").unwrap_err(),
        SkillError::Unterminated
    );
}

#[test]
fn required_fields_must_be_present_and_non_empty() {
    assert_eq!(
        parse_skill_md("---\ndescription: d\n---\nb").unwrap_err(),
        SkillError::MissingField("name")
    );
    assert_eq!(
        parse_skill_md("---\nname: a\n---\nb").unwrap_err(),
        SkillError::MissingField("description")
    );
    assert_eq!(
        parse_skill_md("---\nname: a\ndescription: \"  \"\n---\nb").unwrap_err(),
        SkillError::MissingField("description")
    );
}

#[test]
fn the_name_charset_is_lowercase_alnum_and_single_hyphens() {
    for bad in [
        "Gh-Cli", "gh_cli", "-gh", "gh-", "gh--cli", "gh cli", "../x", "ñame",
    ] {
        let text = format!("---\nname: \"{bad}\"\ndescription: d\n---\nb");
        assert!(
            matches!(parse_skill_md(&text), Err(SkillError::InvalidName(_))),
            "{bad:?} should be rejected"
        );
    }
    let long = "a".repeat(MAX_NAME_LEN + 1);
    assert!(matches!(
        parse_skill_md(&format!("---\nname: {long}\ndescription: d\n---\nb")),
        Err(SkillError::InvalidName(_))
    ));
    let ok = "a".repeat(MAX_NAME_LEN);
    assert!(parse_skill_md(&format!("---\nname: {ok}\ndescription: d\n---\nb")).is_ok());
}

#[test]
fn size_caps_are_enforced_exactly() {
    let at = "x".repeat(MAX_DESCRIPTION_LEN);
    assert!(parse_skill_md(&format!("---\nname: a\ndescription: {at}\n---\nb")).is_ok());
    let over = "x".repeat(MAX_DESCRIPTION_LEN + 1);
    assert_eq!(
        parse_skill_md(&format!("---\nname: a\ndescription: {over}\n---\nb")).unwrap_err(),
        SkillError::TooLong {
            field: "description",
            max: MAX_DESCRIPTION_LEN
        }
    );
    let head = "---\nname: a\ndescription: d\n---\n";
    let fits = format!("{head}{}", "b".repeat(MAX_SKILL_FILE_BYTES - head.len()));
    assert!(parse_skill_md(&fits).is_ok());
    let too_big = format!("{fits}b");
    assert_eq!(
        parse_skill_md(&too_big).unwrap_err(),
        SkillError::TooLarge {
            max: MAX_SKILL_FILE_BYTES
        }
    );
}

#[test]
fn unknown_duplicate_and_unsupported_yaml_is_rejected() {
    assert_eq!(
        parse_skill_md("---\nname: a\ndescription: d\nrun-on-load: true\n---\nb").unwrap_err(),
        SkillError::UnknownKey("run-on-load".into())
    );
    assert_eq!(
        parse_skill_md("---\nname: a\nname: b\ndescription: d\n---\nb").unwrap_err(),
        SkillError::DuplicateKey("name".into())
    );
    // Anchors, aliases and tags are not part of the accepted subset.
    for text in [
        "---\nname: &n a\ndescription: d\n---\nb",
        "---\nname: a\ndescription: *n\n---\nb",
        "---\nname: !!str a\ndescription: d\n---\nb",
        "---\nname: a\ndescription: d\nmetadata:\n  nested:\n    deep: x\n---\nb",
    ] {
        assert!(
            matches!(parse_skill_md(text), Err(SkillError::Yaml { .. })),
            "{text:?} should be rejected"
        );
    }
}

#[test]
fn claude_code_extension_keys_are_tolerated_and_recorded() {
    let (fm, _) = parse_skill_md(
        "---\nname: a\ndescription: d\nargument-hint: \"[path]\"\ndisable-model-invocation: true\n---\nb",
    )
    .unwrap();
    assert_eq!(
        fm.extensions.get("argument-hint").map(String::as_str),
        Some("[path]")
    );
    assert_eq!(
        fm.extensions
            .get("disable-model-invocation")
            .map(String::as_str),
        Some("true")
    );
}

// ---------------------------------------------------------------------------------------------
// Loading a tree from several sources
// ---------------------------------------------------------------------------------------------

#[test]
fn a_tree_loads_nested_skills_and_rejects_a_dir_name_mismatch() {
    let s = Scratch::new("tree");
    skill(s.path(), "alpha", "First skill.", "Do alpha.");
    // Nested the way plugin marketplaces lay skills out.
    skill(
        &s.path().join("plugins/p/skills"),
        "beta",
        "Second.",
        "Do beta.",
    );
    // Directory name and frontmatter name disagree: rejected, not silently renamed.
    write(
        &s.path().join("gamma/SKILL.md"),
        "---\nname: not-gamma\ndescription: x\n---\nb",
    );
    // Invalid frontmatter: rejected with a reason.
    write(&s.path().join("delta/SKILL.md"), "no frontmatter");
    let lib = SkillLibrary::load(&[SkillSource::new("user", s.path())]);
    assert_eq!(lib.names(), vec!["alpha", "beta"]);
    let rejected = &lib.report().rejected;
    assert_eq!(rejected.len(), 2, "{rejected:?}");
    assert!(rejected.iter().any(|r| r.reason.contains("not-gamma")));
    assert!(rejected.iter().any(|r| r.path.ends_with("delta/SKILL.md")));
}

#[test]
fn earlier_sources_take_precedence_and_shadowing_is_reported() {
    let user = Scratch::new("user");
    let bundled = Scratch::new("bundled");
    skill(
        user.path(),
        "deploy",
        "User's own deploy notes.",
        "USER BODY",
    );
    skill(
        bundled.path(),
        "deploy",
        "Bundled deploy notes.",
        "BUNDLED BODY",
    );
    skill(bundled.path(), "audit", "Bundled audit.", "AUDIT BODY");
    let lib = SkillLibrary::load(&[
        SkillSource::new("user", user.path()),
        SkillSource::new("bundled", bundled.path()),
    ]);
    assert_eq!(lib.names(), vec!["audit", "deploy"]);
    let deploy = lib.get("deploy").unwrap();
    assert_eq!(deploy.source, "user");
    assert_eq!(deploy.body, "USER BODY");
    let shadowed = &lib.report().shadowed;
    assert_eq!(shadowed.len(), 1);
    assert_eq!(shadowed[0].name, "deploy");
    assert_eq!(shadowed[0].kept_source, "user");
    assert_eq!(shadowed[0].dropped_source, "bundled");
}

#[test]
fn a_duplicate_name_inside_one_source_is_ambiguous_and_both_are_rejected() {
    let s = Scratch::new("dup");
    skill(&s.path().join("a"), "same", "One.", "1");
    skill(&s.path().join("b"), "same", "Two.", "2");
    skill(s.path(), "other", "Other.", "o");
    let lib = SkillLibrary::load(&[SkillSource::new("user", s.path())]);
    assert_eq!(lib.names(), vec!["other"]);
    assert_eq!(
        lib.report()
            .rejected
            .iter()
            .filter(|r| r.reason.contains("duplicate"))
            .count(),
        2
    );
}

#[test]
fn a_missing_source_is_reported_not_fatal() {
    let s = Scratch::new("present");
    skill(s.path(), "alpha", "A.", "a");
    let lib = SkillLibrary::load(&[
        SkillSource::new("gone", s.path().join("does-not-exist")),
        SkillSource::new("user", s.path()),
    ]);
    assert_eq!(lib.names(), vec!["alpha"]);
    assert!(lib
        .report()
        .rejected
        .iter()
        .any(|r| r.reason.contains("not a directory")));
}

#[test]
fn refs_and_scripts_are_listed_and_scripts_are_flagged() {
    let s = Scratch::new("res");
    let dir = skill(
        s.path(),
        "auditor",
        "Audits.",
        "Read references/checklist.md first.",
    );
    write(&dir.join("references/checklist.md"), "- check one\n");
    write(&dir.join("assets/template.txt"), "tmpl");
    write(&dir.join("scripts/run.sh"), "#!/bin/sh\necho hi\n");
    let lib = SkillLibrary::load(&[SkillSource::new("user", s.path())]);
    let sk = lib.get("auditor").unwrap();
    assert_eq!(
        sk.refs,
        vec![
            "assets/template.txt".to_string(),
            "references/checklist.md".to_string()
        ]
    );
    assert_eq!(sk.scripts, vec!["scripts/run.sh".to_string()]);
}

// ---------------------------------------------------------------------------------------------
// The description index
// ---------------------------------------------------------------------------------------------

#[test]
fn the_index_is_one_line_per_skill_sorted_and_within_budget() {
    let s = Scratch::new("idx");
    for i in 0..40 {
        skill(
            s.path(),
            &format!("skill-{i:02}"),
            &format!("Does thing number {i} with a reasonably long description that goes on."),
            "b",
        );
    }
    let lib = SkillLibrary::load(&[SkillSource::new("user", s.path())]);
    let counter = CharTokenCounter;
    let big = lib.index(10_000, &counter);
    assert_eq!(big.included, 40);
    assert_eq!(big.omitted, 0);
    let lines: Vec<&str> = big.text.lines().collect();
    assert_eq!(lines.len(), 40);
    assert!(lines[0].starts_with("- skill-00: "));
    assert!(lines[39].starts_with("- skill-39: "));

    let small = lib.index(120, &counter);
    assert!(small.included < 40 && small.included > 0);
    assert_eq!(small.included + small.omitted, 40);
    assert!(
        use_count(&counter, &small.text) <= 120,
        "index exceeded its budget: {}",
        use_count(&counter, &small.text)
    );
    assert!(small.text.contains(&format!("{} more", small.omitted)));
}

fn use_count(c: &CharTokenCounter, s: &str) -> usize {
    use citrate_agent_loop::TokenCounter;
    c.count(s)
}

#[test]
fn index_lines_truncate_long_descriptions_to_one_short_line() {
    let s = Scratch::new("trunc");
    let long = "word ".repeat(150);
    skill(s.path(), "wordy", long.trim(), "b");
    write(
        &s.path().join("multi/SKILL.md"),
        "---\nname: multi\ndescription: |\n  First line.\n  Second line.\n---\nb",
    );
    let lib = SkillLibrary::load(&[SkillSource::new("user", s.path())]);
    let idx = lib.index(10_000, &CharTokenCounter);
    assert_eq!(idx.text.lines().count(), 2);
    for line in idx.text.lines() {
        assert!(line.chars().count() <= 200, "line too long: {line}");
    }
    assert!(idx.text.contains("- multi: First line. Second line."));
}

#[test]
fn an_empty_library_has_an_empty_index() {
    let lib = SkillLibrary::empty();
    let idx = lib.index(500, &CharTokenCounter);
    assert_eq!(idx.text, "");
    assert_eq!(idx.included, 0);
}

// ---------------------------------------------------------------------------------------------
// The skill_load tool
// ---------------------------------------------------------------------------------------------

#[test]
fn the_skill_load_spec_is_sidecar_hosted_and_read_only() {
    let spec = skill_load_spec();
    assert_eq!(spec.name, SKILL_LOAD_TOOL);
    assert_eq!(spec.host, HostKind::Sidecar);
    assert!(spec.annotations.read_only);
    assert!(!spec.annotations.destructive);
    assert_eq!(spec.parameters["required"], serde_json::json!(["name"]));
}

#[test]
fn skill_load_returns_the_body_and_lists_refs_and_flagged_scripts() {
    let s = Scratch::new("load");
    let dir = skill(s.path(), "auditor", "Audits.", "STEP ONE\nSTEP TWO\n");
    write(&dir.join("references/checklist.md"), "- check one\n");
    write(&dir.join("scripts/run.sh"), "#!/bin/sh\necho hi\n");
    let host = SkillHost::new(Arc::new(SkillLibrary::load(&[SkillSource::new(
        "user",
        s.path(),
    )])));
    let ToolOutcome::Ok(out) = host.execute(&call(serde_json::json!({"name": "auditor"}))) else {
        panic!("expected ok");
    };
    assert!(out.contains("STEP ONE\nSTEP TWO"));
    assert!(out.contains("references/checklist.md"));
    assert!(out.contains("scripts/run.sh"));
    assert!(out.contains("never executed"));
}

#[test]
fn skill_load_reads_a_listed_ref() {
    let s = Scratch::new("ref");
    let dir = skill(s.path(), "auditor", "Audits.", "b");
    write(&dir.join("references/checklist.md"), "- check one\n");
    let host = SkillHost::new(Arc::new(SkillLibrary::load(&[SkillSource::new(
        "user",
        s.path(),
    )])));
    let out = host.execute(&call(
        serde_json::json!({"name": "auditor", "ref": "references/checklist.md"}),
    ));
    assert_eq!(out, ToolOutcome::Ok("- check one\n".into()));
}

#[test]
fn skill_load_refuses_path_traversal_and_unlisted_paths() {
    let s = Scratch::new("trav");
    let dir = skill(s.path(), "auditor", "Audits.", "b");
    write(&dir.join("references/checklist.md"), "ok");
    // A secret sitting next to the skills root, and a sibling skill.
    write(&s.path().join("secret.txt"), "TOP SECRET");
    skill(s.path(), "other", "Other.", "OTHER BODY");
    let host = SkillHost::new(Arc::new(SkillLibrary::load(&[SkillSource::new(
        "user",
        s.path(),
    )])));
    let secret_abs = s.path().join("secret.txt").display().to_string();
    for bad in [
        "../secret.txt",
        "../other/SKILL.md",
        "references/../../secret.txt",
        secret_abs.as_str(),
        "/etc/passwd",
        "references/missing.md",
        "SKILL.md",
        "",
    ] {
        let out = host.execute(&call(serde_json::json!({"name": "auditor", "ref": bad})));
        match out {
            ToolOutcome::Error(e) => {
                assert!(!e.contains("TOP SECRET") && !e.contains("OTHER BODY"))
            }
            other => panic!("{bad:?} must be refused, got {other:?}"),
        }
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_ref_that_escapes_the_skill_dir_is_not_listed_or_readable() {
    let s = Scratch::new("sym");
    let dir = skill(s.path(), "auditor", "Audits.", "b");
    write(&s.path().join("secret.txt"), "TOP SECRET");
    std::fs::create_dir_all(dir.join("references")).unwrap();
    std::os::unix::fs::symlink(s.path().join("secret.txt"), dir.join("references/leak.md"))
        .unwrap();
    let lib = Arc::new(SkillLibrary::load(&[SkillSource::new("user", s.path())]));
    assert!(lib.get("auditor").unwrap().refs.is_empty());
    let out = SkillHost::new(lib).execute(&call(
        serde_json::json!({"name": "auditor", "ref": "references/leak.md"}),
    ));
    assert!(matches!(out, ToolOutcome::Error(ref e) if !e.contains("TOP SECRET")));
}

#[test]
fn scripts_are_never_executed_nor_readable_through_skill_load() {
    let s = Scratch::new("noexec");
    let dir = skill(s.path(), "runner", "Has a script.", "b");
    let marker = s.path().join("executed.marker");
    write(
        &dir.join("scripts/run.sh"),
        &format!("#!/bin/sh\ntouch {}\n", marker.display()),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("scripts/run.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let host = SkillHost::new(Arc::new(SkillLibrary::load(&[SkillSource::new(
        "user",
        s.path(),
    )])));
    let _ = host.execute(&call(serde_json::json!({"name": "runner"})));
    let out = host.execute(&call(
        serde_json::json!({"name": "runner", "ref": "scripts/run.sh"}),
    ));
    assert!(matches!(out, ToolOutcome::Error(ref e) if e.contains("never executed")));
    assert!(!marker.exists(), "a skill script ran");
}

#[test]
fn an_oversized_ref_is_refused() {
    let s = Scratch::new("bigref");
    let dir = skill(s.path(), "big", "Big ref.", "b");
    write(
        &dir.join("references/huge.md"),
        &"x".repeat(MAX_REF_BYTES + 1),
    );
    let host = SkillHost::new(Arc::new(SkillLibrary::load(&[SkillSource::new(
        "user",
        s.path(),
    )])));
    let out = host.execute(&call(
        serde_json::json!({"name": "big", "ref": "references/huge.md"}),
    ));
    assert!(matches!(out, ToolOutcome::Error(ref e) if e.contains("too large")));
}

#[test]
fn bad_arguments_and_unknown_skills_are_tool_errors() {
    let host = SkillHost::new(Arc::new(SkillLibrary::empty()));
    for args in [
        serde_json::json!({}),
        serde_json::json!({"name": 3}),
        serde_json::json!({"name": "nope"}),
        serde_json::json!({"name": "x", "ref": 1}),
    ] {
        assert!(matches!(host.execute(&call(args)), ToolOutcome::Error(_)));
    }
    let wrong_tool = ToolCall {
        id: "c".into(),
        name: "something_else".into(),
        arguments: "{}".into(),
    };
    assert!(matches!(host.execute(&wrong_tool), ToolOutcome::Error(_)));
}

// ---------------------------------------------------------------------------------------------
// Pinned tools: skill_load must survive per-request tool retrieval
// ---------------------------------------------------------------------------------------------

struct Capture(std::sync::Mutex<Vec<Vec<String>>>);
impl citrate_agent_loop::LlmClient for Capture {
    fn complete(
        &self,
        req: &citrate_agent_loop::CompletionRequest,
    ) -> Result<citrate_agent_loop::AssistantTurn, citrate_agent_loop::LlmError> {
        self.0
            .lock()
            .unwrap()
            .push(req.tools.iter().map(|t| t.name.clone()).collect());
        Ok(citrate_agent_loop::AssistantTurn::text("ok"))
    }
}
struct NullSink;
impl citrate_agent_loop::EventSink for NullSink {
    fn emit(&self, _ev: citrate_agent_loop::Event) {}
}

#[test]
fn a_pinned_tool_is_offered_even_when_retrieval_would_drop_it() {
    use citrate_agent_loop::{
        run_turn_with, LoopConfig, StopFlag, ToolAnnotations, ToolRegistry, ToolSpec, TurnOptions,
    };
    let mk = |n: &str, d: &str| ToolSpec {
        name: n.into(),
        description: d.into(),
        parameters: serde_json::json!({"type": "object"}),
        host: HostKind::Core,
        annotations: ToolAnnotations::default(),
    };
    let specs = vec![
        mk("node_status", "node status height peers"),
        mk("wallet_balance", "wallet balance"),
        skill_load_spec(),
    ];
    let cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 2,
        max_tool_calls_per_step: 2,
        max_tokens: 256,
    };
    let llm = Capture(std::sync::Mutex::new(vec![]));
    let mut history = vec![];
    // Without pinning, k=1 and a node-flavoured question offers only node_status.
    run_turn_with(
        &cfg,
        &TurnOptions {
            max_tools_per_request: Some(1),
            ..Default::default()
        },
        &llm,
        &ToolRegistry::new(specs.clone()),
        &NullSink,
        &StopFlag::default(),
        &mut history,
        "what is the node height",
    );
    assert_eq!(llm.0.lock().unwrap()[0], vec!["node_status".to_string()]);
    // Pinned: skill_load rides along on every request, outside k.
    let mut history = vec![];
    run_turn_with(
        &cfg,
        &TurnOptions {
            max_tools_per_request: Some(1),
            pinned_tools: vec![SKILL_LOAD_TOOL.to_string()],
            ..Default::default()
        },
        &llm,
        &ToolRegistry::new(specs),
        &NullSink,
        &StopFlag::default(),
        &mut history,
        "what is the node height",
    );
    assert_eq!(
        llm.0.lock().unwrap()[1],
        vec![SKILL_LOAD_TOOL.to_string(), "node_status".to_string()]
    );
}

// ---------------------------------------------------------------------------------------------
// Review hardening (HUP-S3.2 adversarial review)
// ---------------------------------------------------------------------------------------------

#[test]
fn an_ambiguous_name_in_an_earlier_source_is_not_filled_by_a_later_source() {
    let user = Scratch::new("amb-user");
    let bundled = Scratch::new("amb-bundled");
    skill(&user.path().join("a"), "deploy", "One.", "USER A");
    skill(&user.path().join("b"), "deploy", "Two.", "USER B");
    skill(bundled.path(), "deploy", "Bundled.", "BUNDLED BODY");
    let lib = SkillLibrary::load(&[
        SkillSource::new("user", user.path()),
        SkillSource::new("bundled", bundled.path()),
    ]);
    // Precedence holds even when the earlier source is ambiguous: the later copy must not win.
    assert!(lib.get("deploy").is_none(), "{:?}", lib.names());
    assert!(lib.report().rejected.iter().any(|r| r
        .path
        .starts_with(bundled.path().canonicalize().unwrap())
        || r.path.starts_with(bundled.path())));
}

#[cfg(unix)]
#[test]
fn one_skill_reached_twice_through_a_symlink_is_not_a_duplicate() {
    let s = Scratch::new("alias");
    skill(&s.path().join("real"), "auditor", "Audits.", "BODY");
    std::os::unix::fs::symlink(s.path().join("real"), s.path().join("alias")).unwrap();
    let lib = SkillLibrary::load(&[SkillSource::new("user", s.path())]);
    assert_eq!(lib.names(), vec!["auditor"], "{:?}", lib.report());
}

#[cfg(unix)]
#[test]
fn a_listed_ref_swapped_for_an_escaping_symlink_after_load_is_refused() {
    let s = Scratch::new("swap");
    let dir = skill(s.path(), "auditor", "Audits.", "b");
    write(&dir.join("references/checklist.md"), "ok");
    write(&s.path().join("secret.txt"), "TOP SECRET");
    let host = SkillHost::new(Arc::new(SkillLibrary::load(&[SkillSource::new(
        "user",
        s.path(),
    )])));
    // The file was listed at load time; it is replaced by a link out of the skill afterwards.
    std::fs::remove_file(dir.join("references/checklist.md")).unwrap();
    std::os::unix::fs::symlink(
        s.path().join("secret.txt"),
        dir.join("references/checklist.md"),
    )
    .unwrap();
    let out = host.execute(&call(
        serde_json::json!({"name": "auditor", "ref": "references/checklist.md"}),
    ));
    assert!(
        matches!(out, ToolOutcome::Error(ref e) if !e.contains("TOP SECRET")),
        "{out:?}"
    );
}

/// HUP-S2.7 × S3.2: skill_load reads text and runs nothing (callable after taint), and skill bodies
/// can be third-party, so its output is untrusted.
#[test]
fn skill_load_is_not_effectful_and_its_output_is_untrusted() {
    let spec = citrate_agent_loop::skills::skill_load_spec();
    assert!(!spec.annotations.is_effectful());
    assert!(spec.annotations.output_untrusted());
}

/// US-3.2 AC2 (one format, one loader): the exact bytes citrate-core writes when the member saves
/// a skill (`src-tauri/src/skills_local.rs`, pinned there as `MORNING_CHECK_MD`) load through this
/// strict loader from the member's skills folder.
#[test]
fn core_written_skill_md_parses_strictly() {
    const MORNING_CHECK_MD: &str = "---\nname: morning-check\ndescription: \"Read node status, then the \\\"staking\\\" status.\"\nmetadata:\n  display-name: \"Morning check\"\n  origin: citrate-core-skill-write\n---\n\n1. node_status\n2. staking_status\n";
    let (fm, body) = parse_skill_md(MORNING_CHECK_MD).unwrap();
    assert_eq!(fm.name, "morning-check");
    assert_eq!(
        fm.description,
        "Read node status, then the \"staking\" status."
    );
    assert_eq!(fm.metadata["display-name"], "Morning check");
    assert_eq!(body, "\n1. node_status\n2. staking_status\n");
    let s = Scratch::new("core-written");
    write(&s.path().join("morning-check/SKILL.md"), MORNING_CHECK_MD);
    let lib = SkillLibrary::load(&[SkillSource::new("2:agent-skills", s.path())]);
    assert_eq!(lib.names(), vec!["morning-check"]);
}
