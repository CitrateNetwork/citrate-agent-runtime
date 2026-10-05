//! HUP-S3.2: the reviewed third-party skills citrate-core stages beside `skills.lock`
//! (`CITRATE_HERMES_SKILLS_LOCK` + `CITRATE_HERMES_SKILLS_THIRD_PARTY`) join the skills library as
//! the lowest-precedence source, loaded through the same SKILL.md loader.

use super::*;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static N: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "citrate-sidecar-skills-lock-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn put(path: &Path, text: &str) -> String {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn fixture(s: &Scratch) -> (PathBuf, PathBuf) {
    let root = s.0.join("skills-bundle");
    let h = put(
        &root.join("trailofbits/plugins/a/skills/semgrep-rules/SKILL.md"),
        "---\nname: semgrep-rules\ndescription: Write Semgrep rules.\n---\nBody.\n",
    );
    let lock = s.0.join("skills.lock");
    put(
        &lock,
        &format!(
            "version = 1\n[[source]]\nlabel = \"trailofbits\"\nupstream = \"https://github.com/trailofbits/skills\"\ncommit = \"a56045e9ae00b3506cacefea0f672aab0a1a6e3c\"\nlicense = \"CC-BY-SA-4.0\"\n[[skill]]\nname = \"semgrep-rules\"\nsource = \"trailofbits\"\ncommit = \"a56045e9ae00b3506cacefea0f672aab0a1a6e3c\"\npath = \"plugins/a/skills/semgrep-rules\"\nverdict = \"include-as-is\"\nskill_md_sha256 = \"{h}\"\n"
        ),
    );
    (lock, root)
}

#[test]
fn the_staged_reviewed_skills_become_a_locked_source() {
    let s = Scratch::new();
    let (lock, root) = fixture(&s);
    let src = third_party_skill_source(&lock, &root).unwrap();
    assert!(src.lock.is_some());
    assert_eq!(src.label, THIRD_PARTY_SKILLS_LABEL);
    let lib = citrate_agent_loop::skills::SkillLibrary::load(&[src]);
    assert_eq!(lib.names(), vec!["semgrep-rules"]);
}

#[test]
fn an_unreadable_or_invalid_lock_is_refused() {
    let s = Scratch::new();
    let (_, root) = fixture(&s);
    assert!(third_party_skill_source(&s.0.join("missing.lock"), &root).is_err());
    let bad = s.0.join("bad.lock");
    std::fs::write(&bad, "version = 9\n").unwrap();
    assert!(third_party_skill_source(&bad, &root).is_err());
}

#[test]
fn reviewed_skills_follow_the_members_own_sources() {
    let s = Scratch::new();
    let (lock, root) = fixture(&s);
    let member = s.0.join("member-skills");
    put(
        &member.join("semgrep-rules/SKILL.md"),
        "---\nname: semgrep-rules\ndescription: My own version.\n---\nMine.\n",
    );
    let sources = all_skill_sources(
        member.to_string_lossy().as_ref(),
        Some((lock.as_path(), root.as_path())),
    );
    assert_eq!(sources.len(), 2);
    assert!(sources[0].lock.is_none());
    assert!(sources[1].lock.is_some());
    let lib = citrate_agent_loop::skills::SkillLibrary::load(&sources);
    assert_eq!(
        lib.get("semgrep-rules").unwrap().description,
        "My own version."
    );
    assert_eq!(lib.report().shadowed.len(), 1);
}

#[test]
fn without_the_third_party_pair_only_the_members_sources_load() {
    let s = Scratch::new();
    let member = s.0.join("member-skills");
    std::fs::create_dir_all(&member).unwrap();
    let sources = all_skill_sources(member.to_string_lossy().as_ref(), None);
    assert_eq!(sources.len(), 1);
    // A bad lock never fails the member's own skills: it is logged and left out.
    let bad = s.0.join("bad.lock");
    std::fs::write(&bad, "nope [[").unwrap();
    let sources = all_skill_sources(
        member.to_string_lossy().as_ref(),
        Some((bad.as_path(), s.0.as_path())),
    );
    assert_eq!(sources.len(), 1);
}
