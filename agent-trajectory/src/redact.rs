//! Default-on redaction for exported trajectories.
//!
//! Pattern-based and deliberately over-eager: a false positive costs one training token, a false
//! negative leaks a secret. Every pass is counted per category; the counts never carry values.

use crate::policy::ExportPolicy;
use crate::TrajectoryError;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

const BIP39_ENGLISH: &str = include_str!("bip39_english.txt");

/// The BIP-39 English wordlist used for seed-phrase detection (2048 words, one per line).
pub fn bip39_english_wordlist() -> &'static str {
    BIP39_ENGLISH
}

fn bip39_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| BIP39_ENGLISH.lines().map(str::trim).collect())
}

/// Fewest consecutive BIP-39 words treated as a seed phrase (the shortest standard mnemonic).
pub const SEED_PHRASE_MIN_WORDS: usize = 12;

/// What a redaction removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Private keys, provider API tokens, raw 32-byte hex, `password=`-style values.
    Secret,
    /// The credential after `Bearer` / `Basic`.
    BearerToken,
    /// Runs of 12 or more BIP-39 words.
    SeedPhrase,
    /// An absolute path outside every granted root.
    Path,
    /// A 20-byte hex wallet address not on the allow list.
    Address,
    Email,
}

impl Category {
    fn placeholder(self) -> &'static str {
        match self {
            Category::Secret => "[REDACTED:secret]",
            Category::BearerToken => "[REDACTED:bearer_token]",
            Category::SeedPhrase => "[REDACTED:seed_phrase]",
            Category::Path => "[REDACTED:path]",
            Category::Address => "[REDACTED:address]",
            Category::Email => "[REDACTED:email]",
        }
    }
}

/// Redaction counts. Values are never kept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionCounts {
    pub secret: u32,
    pub bearer_token: u32,
    pub seed_phrase: u32,
    pub path: u32,
    pub address: u32,
    pub email: u32,
    /// Paths inside a granted root rewritten to `[root:N]/...` (not a redaction).
    pub relativised: u32,
}

impl RedactionCounts {
    pub fn get(&self, c: Category) -> u32 {
        match c {
            Category::Secret => self.secret,
            Category::BearerToken => self.bearer_token,
            Category::SeedPhrase => self.seed_phrase,
            Category::Path => self.path,
            Category::Address => self.address,
            Category::Email => self.email,
        }
    }
    fn bump(&mut self, c: Category) {
        let f = match c {
            Category::Secret => &mut self.secret,
            Category::BearerToken => &mut self.bearer_token,
            Category::SeedPhrase => &mut self.seed_phrase,
            Category::Path => &mut self.path,
            Category::Address => &mut self.address,
            Category::Email => &mut self.email,
        };
        *f = f.saturating_add(1);
    }
    /// Redactions of every category (relativised paths excluded).
    pub fn total(&self) -> u32 {
        [
            self.secret,
            self.bearer_token,
            self.seed_phrase,
            self.path,
            self.address,
            self.email,
        ]
        .iter()
        .fold(0u32, |a, b| a.saturating_add(*b))
    }
    pub fn add(&mut self, o: &RedactionCounts) {
        self.secret = self.secret.saturating_add(o.secret);
        self.bearer_token = self.bearer_token.saturating_add(o.bearer_token);
        self.seed_phrase = self.seed_phrase.saturating_add(o.seed_phrase);
        self.path = self.path.saturating_add(o.path);
        self.address = self.address.saturating_add(o.address);
        self.email = self.email.saturating_add(o.email);
        self.relativised = self.relativised.saturating_add(o.relativised);
    }
}

// Characters that end a path token (and may precede one).
const PATH_END: &str = r#"\s"'`)\]}<>,;|"#;

struct Patterns {
    pem: Regex,
    bearer: Regex,
    provider: Regex,
    hex32: Regex,
    query: Regex,
    kv: Regex,
    word: Regex,
    email: Regex,
    address: Regex,
    file_url: Regex,
    windows: Regex,
    unix: Regex,
}

fn compile(p: &str) -> Result<Regex, TrajectoryError> {
    Regex::new(p).map_err(|e| TrajectoryError::Pattern(e.to_string()))
}

impl Patterns {
    fn new() -> Result<Self, TrajectoryError> {
        Ok(Patterns {
            pem: compile(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            )?,
            bearer: compile(r"(?i)\b(bearer|basic)(\s+)([A-Za-z0-9\-._~+/]+=*)")?,
            provider: compile(concat!(
                r"\b(?:sk-[A-Za-z0-9_\-]{16,}",
                r"|gh[pousr]_[A-Za-z0-9]{20,}",
                r"|github_pat_[A-Za-z0-9_]{20,}",
                r"|xox[abposr]-[A-Za-z0-9\-]{10,}",
                r"|(?:AKIA|ASIA)[0-9A-Z]{16}",
                r"|AIza[0-9A-Za-z_\-]{35}",
                r"|[sr]k_(?:live|test)_[A-Za-z0-9]{10,}",
                r"|eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})",
            ))?,
            hex32: compile(r"\b(?:0x)?[0-9a-fA-F]{64}\b")?,
            query: compile(
                r#"(?i)([?&](?:access_token|refresh_token|id_token|token|api_key|apikey|key|secret|client_secret|password|sig|signature|auth)=)([^&\s#"'<>\[][^&\s#"'<>]*)"#,
            )?,
            kv: compile(
                r#"(?i)\b(api[_-]?key|client[_-]?secret|secret[_-]?key|secret|password|passwd|passphrase|private[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|mnemonic)("?'?\s*[:=]\s*["']?)([^\s"',;}&\[<>][^\s"',;}&<>]{3,})"#,
            )?,
            word: compile(r"[A-Za-z]+")?,
            email: compile(
                r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b",
            )?,
            address: compile(r"\b0x[0-9a-fA-F]{40}\b")?,
            file_url: compile(&format!(r"file://(/[^{PATH_END}]*)"))?,
            windows: compile(&format!(
                r"(^|[{PATH_END}(\[{{=:])([A-Za-z]:\\[^{PATH_END}]+)"
            ))?,
            unix: compile(&format!(
                r"(^|[{PATH_END}(\[{{=,:<>])((?:~|/[^/{PATH_END}]+)/[^{PATH_END}]*)"
            ))?,
        })
    }
}

/// A path root, as normalized components (lowercased for Windows roots).
#[derive(Debug, Clone)]
struct Root {
    windows: bool,
    comps: Vec<String>,
}

fn is_windows_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Lexical normalization: drops empty and `.` components and resolves `..` (never above the
/// root). Windows paths are lowercased and use `\` or `/` as separators.
fn normalize(p: &str, windows: bool) -> Vec<String> {
    let owned;
    let p = if windows {
        owned = p.replace('\\', "/").to_lowercase();
        owned.as_str()
    } else {
        p
    };
    let mut out: Vec<String> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if !(windows && out.len() == 1) {
                    out.pop();
                }
            }
            c => out.push(c.to_string()),
        }
    }
    out
}

/// Applies every redaction pass under one [`ExportPolicy`].
pub struct Redactor {
    pats: Patterns,
    roots: Vec<Root>,
    home: Option<String>,
    allowed_addresses: BTreeSet<String>,
}

impl Redactor {
    pub fn new(policy: &ExportPolicy) -> Result<Self, TrajectoryError> {
        let home = policy
            .home()
            .map(|h| h.to_string_lossy().trim_end_matches('/').to_string());
        let roots = policy
            .granted_roots()
            .iter()
            .map(|r| {
                let s = r.to_string_lossy().to_string();
                let s = match (&home, s.strip_prefix('~')) {
                    (Some(h), Some(rest)) if rest.is_empty() || rest.starts_with('/') => {
                        format!("{h}{rest}")
                    }
                    _ => s,
                };
                let windows = is_windows_path(&s);
                Root {
                    windows,
                    comps: normalize(&s, windows),
                }
            })
            .collect();
        Ok(Redactor {
            pats: Patterns::new()?,
            roots,
            home,
            allowed_addresses: policy.allowed_addresses().clone(),
        })
    }

    /// Redact one string. Returns the redacted text and what was removed.
    pub fn redact(&self, input: &str) -> (String, RedactionCounts) {
        let mut c = RedactionCounts::default();
        let p = &self.pats;

        let s = p
            .pem
            .replace_all(input, |_: &Captures| self.hit(&mut c, Category::Secret))
            .into_owned();
        let s = self.redact_seed_phrases(&s, &mut c);
        let s = p
            .bearer
            .replace_all(&s, |cap: &Captures| {
                let tok = &cap[3];
                if looks_like_credential(tok) {
                    c.bump(Category::BearerToken);
                    format!(
                        "{}{}{}",
                        &cap[1],
                        &cap[2],
                        Category::BearerToken.placeholder()
                    )
                } else {
                    cap[0].to_string()
                }
            })
            .into_owned();
        let s = p
            .provider
            .replace_all(&s, |_: &Captures| self.hit(&mut c, Category::Secret))
            .into_owned();
        let s = p
            .hex32
            .replace_all(&s, |_: &Captures| self.hit(&mut c, Category::Secret))
            .into_owned();
        let s = p
            .query
            .replace_all(&s, |cap: &Captures| {
                c.bump(Category::Secret);
                format!("{}{}", &cap[1], Category::Secret.placeholder())
            })
            .into_owned();
        let s =
            p.kv.replace_all(&s, |cap: &Captures| {
                c.bump(Category::Secret);
                format!("{}{}{}", &cap[1], &cap[2], Category::Secret.placeholder())
            })
            .into_owned();
        let s = p
            .email
            .replace_all(&s, |_: &Captures| self.hit(&mut c, Category::Email))
            .into_owned();
        let s = p
            .address
            .replace_all(&s, |cap: &Captures| {
                if self.allowed_addresses.contains(&cap[0].to_lowercase()) {
                    cap[0].to_string()
                } else {
                    self.hit(&mut c, Category::Address)
                }
            })
            .into_owned();
        let s = p
            .file_url
            .replace_all(&s, |cap: &Captures| self.path(&cap[1], &mut c))
            .into_owned();
        let s = p
            .windows
            .replace_all(&s, |cap: &Captures| {
                format!("{}{}", &cap[1], self.path(&cap[2], &mut c))
            })
            .into_owned();
        let s = p
            .unix
            .replace_all(&s, |cap: &Captures| {
                format!("{}{}", &cap[1], self.path(&cap[2], &mut c))
            })
            .into_owned();
        (s, c)
    }

    fn hit(&self, c: &mut RedactionCounts, cat: Category) -> String {
        c.bump(cat);
        cat.placeholder().to_string()
    }

    /// Classify one absolute path token: inside a granted root becomes `[root:N]/rest`,
    /// anything else is redacted. Trailing sentence punctuation is kept outside the token.
    fn path(&self, raw: &str, c: &mut RedactionCounts) -> String {
        let core = raw.trim_end_matches(['.', ',', ':', ';', '!', '?']);
        let trail = &raw[core.len()..];
        let windows = is_windows_path(core);
        let expanded = if let Some(rest) = core.strip_prefix('~') {
            match &self.home {
                Some(h) => format!("{h}{rest}"),
                None => {
                    c.bump(Category::Path);
                    return format!("{}{trail}", Category::Path.placeholder());
                }
            }
        } else {
            core.to_string()
        };
        let comps = normalize(&expanded, windows);
        for (i, root) in self.roots.iter().enumerate() {
            if root.windows == windows
                && !root.comps.is_empty()
                && comps.len() >= root.comps.len()
                && comps[..root.comps.len()] == root.comps[..]
            {
                c.relativised = c.relativised.saturating_add(1);
                let rest = &comps[root.comps.len()..];
                return if rest.is_empty() {
                    format!("[root:{i}]{trail}")
                } else {
                    format!("[root:{i}]/{}{trail}", rest.join("/"))
                };
            }
        }
        c.bump(Category::Path);
        format!("{}{trail}", Category::Path.placeholder())
    }

    fn redact_seed_phrases(&self, s: &str, c: &mut RedactionCounts) -> String {
        let set = bip39_set();
        let mut spans: Vec<(usize, usize)> = Vec::new();
        // (start, end, words) of the current run of BIP-39 words.
        let mut run: Option<(usize, usize, usize)> = None;
        let flush = |run: &mut Option<(usize, usize, usize)>, spans: &mut Vec<(usize, usize)>| {
            if let Some((a, b, n)) = run.take() {
                if n >= SEED_PHRASE_MIN_WORDS {
                    spans.push((a, b));
                }
            }
        };
        for m in self.pats.word.find_iter(s) {
            if !set.contains(m.as_str().to_lowercase().as_str()) {
                flush(&mut run, &mut spans);
                continue;
            }
            let joins = match run {
                Some((_, end, _)) => {
                    // Words join across whitespace, commas, hyphens and list numbering ("2. ",
                    // "3)"). A '.' or ':' without a number is a sentence break and ends the run.
                    let gap = &s[end..m.start()];
                    let numbered = gap.chars().any(|ch| ch.is_ascii_digit());
                    gap.len() <= 8
                        && gap.chars().all(|ch| {
                            ch.is_whitespace()
                                || ch.is_ascii_digit()
                                || ",;()-".contains(ch)
                                || (numbered && ".:".contains(ch))
                        })
                }
                None => false,
            };
            run = match (joins, run) {
                (true, Some((a, _, n))) => Some((a, m.end(), n + 1)),
                _ => {
                    flush(&mut run, &mut spans);
                    Some((m.start(), m.end(), 1))
                }
            };
        }
        flush(&mut run, &mut spans);
        if spans.is_empty() {
            return s.to_string();
        }
        let mut out = String::with_capacity(s.len());
        let mut last = 0;
        for (a, b) in spans {
            out.push_str(&s[last..a]);
            out.push_str(Category::SeedPhrase.placeholder());
            c.bump(Category::SeedPhrase);
            last = b;
        }
        out.push_str(&s[last..]);
        out
    }
}

/// A `Bearer`/`Basic` argument is a credential when it is long and not a plain word: it carries a
/// digit, a token symbol, or an uppercase letter after the first character.
fn looks_like_credential(tok: &str) -> bool {
    tok.len() >= 8
        && (tok
            .chars()
            .any(|ch| ch.is_ascii_digit() || "-._~+/=".contains(ch))
            || tok.chars().skip(1).any(|ch| ch.is_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        assert!(Patterns::new().is_ok());
    }

    #[test]
    fn normalize_resolves_dots_and_never_climbs_above_root() {
        assert_eq!(normalize("/a/./b/../c", false), vec!["a", "c"]);
        assert_eq!(normalize("/../../etc", false), vec!["etc"]);
        assert_eq!(
            normalize("C:\\Users\\X\\..\\..\\..\\y", true),
            vec!["c:", "y"]
        );
    }

    #[test]
    fn credential_shape() {
        assert!(looks_like_credential("dXNlcjpwYXNz"));
        assert!(looks_like_credential("abc12345"));
        assert!(!looks_like_credential("understanding"));
        assert!(!looks_like_credential("Understanding"));
        assert!(!looks_like_credential("ab1"));
    }
}
