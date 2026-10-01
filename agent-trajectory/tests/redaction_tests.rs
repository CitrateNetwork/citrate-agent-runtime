//! HUP-S9.3: redaction by default. Every category, its edge cases, and what must survive.
use citrate_agent_trajectory::*;
use std::path::PathBuf;

fn policy() -> ExportPolicy {
    ExportPolicy::new()
        .with_granted_root("/Users/member/work/app")
        .with_home("/Users/member")
}
fn red(s: &str) -> (String, RedactionCounts) {
    let r = Redactor::new(&policy()).unwrap();
    r.redact(s)
}
fn red_with(p: &ExportPolicy, s: &str) -> String {
    Redactor::new(p).unwrap().redact(s).0
}

// ---------------------------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------------------------

#[test]
fn raw_32_byte_keys_are_secrets() {
    let hex = "5a".repeat(32);
    let (out, c) = red(&format!("my key is 0x{hex}."));
    assert_eq!(out, "my key is [REDACTED:secret].");
    assert_eq!(c.get(Category::Secret), 1);
    let (out, _) = red(&hex);
    assert_eq!(out, "[REDACTED:secret]");
}

#[test]
fn pem_private_keys_are_secrets() {
    // Fixtures are assembled at run time so no key-shaped literal sits in the source.
    let pk = ["PRIVATE", " KEY"].concat();
    let pem = format!(
        "-----BEGIN EC {pk}-----\nMHQCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5\noAcGBSuBBAAK\n-----END EC {pk}-----"
    );
    let (out, c) = red(&format!("here:\n{pem}\nthanks"));
    assert_eq!(out, "here:\n[REDACTED:secret]\nthanks");
    assert_eq!(c.get(Category::Secret), 1);
    let (out, _) = red(&format!(
        "-----BEGIN OPENSSH {pk}-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH {pk}-----"
    ));
    assert_eq!(out, "[REDACTED:secret]");
}

#[test]
fn provider_token_formats_are_secrets() {
    // Synthetic, assembled at run time so no token-shaped literal sits in the source.
    let toks: Vec<String> = [
        ["sk-", "proj-abcdefghijklmnopqrstuvwxyz012345"],
        ["sk-", "ant-api03-AbCdEfGhIjKlMnOpQrStUv"],
        ["gh", "p_0123456789abcdefghijABCDEFGHIJ012345"],
        ["github", "_pat_11ABCDEFG0123456789_abcdefghijklmnop"],
        ["xo", "xb-1234567890-abcdefghijkl"],
        ["AKIA", "IOSFODNN7EXAMPLE"],
        ["AI", "zaSyA1234567890abcdefghijklmnopqrstuv"],
        ["sk", "_live_51H8abcdefghijklmnop"],
        ["ey", "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"],
    ]
    .iter()
    .map(|p| p.concat())
    .collect();
    for tok in &toks {
        let (out, c) = red(&format!("use {tok} now"));
        assert_eq!(out, "use [REDACTED:secret] now", "{tok}");
        assert_eq!(c.total(), 1, "{tok}");
    }
}

#[test]
fn secret_assignments_keep_the_key_and_lose_the_value() {
    let value = ["abc123", "def456"].concat();
    let (out, _) = red(&format!("API_KEY={value} and password: hunter2222"));
    assert_eq!(
        out,
        "API_KEY=[REDACTED:secret] and password: [REDACTED:secret]"
    );
    let (out, _) = red(r#"{"client_secret": "s3cr3t-value", "name": "app"}"#);
    assert_eq!(
        out,
        r#"{"client_secret": "[REDACTED:secret]", "name": "app"}"#
    );
    let (out, _) = red("curl 'https://rpc.example/v1?chain=40204&access_token=abcd1234&x=1'");
    assert_eq!(
        out,
        "curl 'https://rpc.example/v1?chain=40204&access_token=[REDACTED:secret]&x=1'"
    );
}

#[test]
fn bearer_tokens_keep_the_scheme() {
    let (out, c) = red("Authorization: Bearer abc.DEF-123_xyz~+/=");
    assert_eq!(out, "Authorization: Bearer [REDACTED:bearer_token]");
    assert_eq!(c.get(Category::BearerToken), 1);
    let (out, _) = red("header bearer eyJhbGciOiJIUzI1NiJ9 then basic dXNlcjpwYXNz");
    assert_eq!(
        out,
        "header bearer [REDACTED:bearer_token] then basic [REDACTED:bearer_token]"
    );
}

#[test]
fn ordinary_words_near_keywords_survive() {
    for s in [
        "the token count was high",
        "set a password for the vault",
        "bearer bonds are old",
        "Basic idea: keep it simple",
    ] {
        assert_eq!(red(s).0, s);
    }
}

// ---------------------------------------------------------------------------------------------
// Seed phrases
// ---------------------------------------------------------------------------------------------

const SEED12: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

#[test]
fn a_twelve_word_seed_phrase_is_redacted_and_its_context_kept() {
    let (out, c) = red(&format!("my words: {SEED12}. keep them safe"));
    assert_eq!(out, "my words: [REDACTED:seed_phrase]. keep them safe");
    assert_eq!(c.get(Category::SeedPhrase), 1);
}

#[test]
fn numbered_comma_and_newline_and_capitalised_seed_phrases_are_redacted() {
    let words: Vec<&str> = SEED12.split(' ').collect();
    let numbered: String = words
        .iter()
        .enumerate()
        .map(|(i, w)| format!("{}. {w}\n", i + 1))
        .collect();
    assert_eq!(red(&numbered).0, "1. [REDACTED:seed_phrase]\n");
    assert_eq!(red(&words.join(", ")).0, "[REDACTED:seed_phrase]");
    assert_eq!(red(&SEED12.to_uppercase()).0, "[REDACTED:seed_phrase]");
    let twenty_four = format!("{SEED12} {SEED12}");
    let (out, c) = red(&twenty_four);
    assert_eq!(out, "[REDACTED:seed_phrase]");
    assert_eq!(c.get(Category::SeedPhrase), 1);
}

#[test]
fn eleven_words_or_ordinary_prose_are_not_a_seed_phrase() {
    let eleven: Vec<&str> = SEED12.split(' ').take(11).collect();
    let s = eleven.join(" ");
    assert_eq!(red(&s).0, s);
    let prose = "Hermes deployed the token contract and the tests passed on the first try, \
                 so the member asked for a second one with a different name and symbol.";
    assert_eq!(red(prose).0, prose);
}

// ---------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------

#[test]
fn paths_inside_a_granted_root_are_relativised() {
    let (out, c) = red("edited /Users/member/work/app/src/main.rs and ran it");
    assert_eq!(out, "edited [root:0]/src/main.rs and ran it");
    assert_eq!(c.get(Category::Path), 0, "relativising is not a redaction");
    assert_eq!(c.relativised, 1);
    assert_eq!(red("cd /Users/member/work/app").0, "cd [root:0]");
    assert_eq!(
        red("see ~/work/app/README.md.").0,
        "see [root:0]/README.md."
    );
}

#[test]
fn paths_outside_granted_roots_are_redacted() {
    for s in [
        "read /etc/passwd",
        "read /Users/member/.ssh/id_ed25519",
        "read ~/Documents/taxes.pdf",
        "read /Users/member/work/app-evil/x.rs",
        "read /Users/member/work/app/../other/secret.txt",
        "read file:///Users/member/Desktop/notes.txt",
        "read C:\\Users\\member\\notes.txt",
    ] {
        let (out, c) = red(s);
        assert_eq!(out, "read [REDACTED:path]", "{s}");
        assert_eq!(c.get(Category::Path), 1, "{s}");
    }
}

#[test]
fn quoted_and_json_paths_are_found() {
    let (out, _) = red(r#"{"path":"/private/var/db/x.db","rel":"src/lib.rs"}"#);
    assert_eq!(out, r#"{"path":"[REDACTED:path]","rel":"src/lib.rs"}"#);
    assert_eq!(red("(/opt/homebrew/bin/forge)").0, "([REDACTED:path])");
}

#[test]
fn urls_relative_paths_dates_and_fractions_survive() {
    for s in [
        "see https://docs.citrate.ai/agents/hermes for details",
        "edit src/main.rs",
        "on 10/01/2026",
        "and/or 1/2 of it",
        "a single /tmp",
        "tokens /s",
    ] {
        assert_eq!(red(s).0, s);
    }
}

#[test]
fn without_a_home_a_tilde_path_is_outside_every_root() {
    let p = ExportPolicy::new().with_granted_root("/Users/member/work/app");
    assert_eq!(red_with(&p, "open ~/work/app/x"), "open [REDACTED:path]");
}

#[test]
fn several_roots_are_numbered_in_order() {
    let p = ExportPolicy::new()
        .with_granted_root("/a/one")
        .with_granted_root(PathBuf::from("/b/two"));
    assert_eq!(
        red_with(&p, "/a/one/x and /b/two/y/z"),
        "[root:0]/x and [root:1]/y/z"
    );
}

// ---------------------------------------------------------------------------------------------
// Addresses and emails
// ---------------------------------------------------------------------------------------------

const ADDR: &str = "0x9D5d16FD1c2bF9a1E9C1b1f0C3d5B6b7a8e9F0a1";

#[test]
fn wallet_addresses_are_redacted_unless_allowed() {
    let (out, c) = red(&format!("send to {ADDR} please"));
    assert_eq!(out, "send to [REDACTED:address] please");
    assert_eq!(c.get(Category::Address), 1);
    let p = policy().allow_address(&ADDR.to_lowercase());
    assert_eq!(
        red_with(&p, &format!("send to {ADDR}")),
        format!("send to {ADDR}")
    );
}

#[test]
fn hex_that_is_not_an_address_is_left_alone() {
    for s in ["0x1234", "selector 0xfce25138", "0xdeadbeef00"] {
        assert_eq!(red(s).0, s);
    }
}

#[test]
fn emails_are_redacted() {
    let (out, c) = red("mail larry.k+hermes@example.co.uk or a@b.io.");
    assert_eq!(out, "mail [REDACTED:email] or [REDACTED:email].");
    assert_eq!(c.get(Category::Email), 2);
    assert_eq!(
        red("@handle and user@localhost").0,
        "@handle and user@localhost"
    );
}

// ---------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------

#[test]
fn redaction_is_idempotent_and_placeholders_are_stable() {
    let s = format!(
        "{SEED12} {ADDR} me@x.io /etc/hosts Bearer abcdef0123 API_KEY=zzzz9999 \
         0x{}",
        "5a".repeat(32)
    );
    let once = red(&s).0;
    let (twice, c) = red(&once);
    assert_eq!(once, twice);
    assert_eq!(c.total(), 0, "placeholders are never re-redacted");
}

#[test]
fn the_bip39_wordlist_is_the_canonical_english_list() {
    use sha2::{Digest, Sha256};
    let list = bip39_english_wordlist();
    assert_eq!(list.lines().count(), 2048);
    let digest = Sha256::digest(list.as_bytes());
    assert_eq!(
        format!("{digest:x}"),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
}
