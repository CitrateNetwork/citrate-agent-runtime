//! HUP-S2.8 red-green tests: one block per deny category, plus the path-shape
//! robustness cases (relative, `..`, `~`, trailing slash, Windows separators,
//! case, Unicode normalization) and the `.env` project-root decision.

use citrate_agent_guard::{check_path, DenyCategory, GuardContext};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A real, canonical fake home with a project directory inside it, so the
/// allow-cases resolve against an existing tree on every platform.
fn fixture() -> (TempDir, PathBuf, GuardContext) {
    let tmp = TempDir::new().expect("tempdir");
    let home = std::fs::canonicalize(tmp.path())
        .expect("canon")
        .join("home");
    let proj = home.join("work").join("proj");
    std::fs::create_dir_all(&proj).expect("mkdir proj");
    let ctx = GuardContext::new(&home, &proj).with_project_root(&proj);
    (tmp, home, ctx)
}

fn denied_as(path: &str, ctx: &GuardContext, want: DenyCategory) {
    match check_path(path, ctx) {
        Ok(p) => panic!(
            "{path:?} was ALLOWED as {:?}; expected {want:?}",
            p.as_path()
        ),
        Err(d) => assert_eq!(d.category, want, "{path:?} denied as {d:?}"),
    }
}

fn allowed(path: &str, ctx: &GuardContext) -> PathBuf {
    match check_path(path, ctx) {
        Ok(p) => p.into_path_buf(),
        Err(d) => panic!("{path:?} was DENIED ({d:?}); expected allowed"),
    }
}

// ---------------------------------------------------------------- credentials

#[test]
fn credentials_ssh_gnupg_cloud_and_token_files_are_denied() {
    let (_t, _h, ctx) = fixture();
    for p in [
        "~/.ssh",
        "~/.ssh/id_ed25519",
        "~/.ssh/authorized_keys",
        "~/.gnupg/private-keys-v1.d/x.key",
        "~/.aws/credentials",
        "~/.config/gcloud/application_default_credentials.json",
        "~/.azure/msal_token_cache.json",
        "~/.kube/config",
        "~/.docker/config.json",
        "~/.netrc",
        "~/.npmrc",
        "~/.pypirc",
        "~/.git-credentials",
        "~/.config/gh/hosts.yml",
        "~/.cargo/credentials.toml",
        "/root/.ssh/id_rsa",
        "/home/someone-else/.ssh/id_rsa",
    ] {
        denied_as(p, &ctx, DenyCategory::Credentials);
    }
}

#[test]
fn credentials_rules_match_whole_components_not_substrings() {
    let (_t, home, ctx) = fixture();
    // `.sshfoo` and `my.ssh` are not `.ssh`; `.docker/other.json` is not the auth file.
    for p in [
        "~/work/proj/.sshfoo",
        "~/work/proj/my.ssh",
        "~/.docker/daemon.json",
        "~/work/proj/npmrc-notes.md",
    ] {
        let got = allowed(p, &ctx);
        assert!(got.starts_with(&home), "{p:?} -> {got:?}");
    }
}

// ------------------------------------------------------------------ keychains

#[test]
fn os_keychains_are_denied() {
    let (_t, _h, ctx) = fixture();
    for p in [
        "~/Library/Keychains/login.keychain-db",
        "/Library/Keychains/System.keychain",
        "/System/Library/Keychains/SystemRootCertificates.keychain",
        "~/.local/share/keyrings/login.keyring",
        "~/.local/share/kwalletd/kdewallet.kwl",
        "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5\\key",
        "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Credentials\\ABC",
    ] {
        denied_as(p, &ctx, DenyCategory::Keychain);
    }
}

// ----------------------------------------------------------- browser profiles

#[test]
fn browser_profiles_are_denied_on_every_os_layout() {
    let (_t, _h, ctx) = fixture();
    for p in [
        // macOS
        "~/Library/Application Support/Google/Chrome/Default/Cookies",
        "~/Library/Application Support/Chromium/Default/Login Data",
        "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
        "~/Library/Application Support/Microsoft Edge/Default/Cookies",
        "~/Library/Application Support/Firefox/Profiles/abc.default/logins.json",
        "~/Library/Safari/History.db",
        "~/Library/Containers/com.apple.Safari/Data/x",
        "~/Library/Cookies/Cookies.binarycookies",
        // Linux
        "~/.config/google-chrome/Default/Cookies",
        "~/.config/chromium/Default/Cookies",
        "~/.config/BraveSoftware/Brave-Browser/Default/Cookies",
        "~/.config/microsoft-edge/Default/Cookies",
        "~/.mozilla/firefox/abc.default/key4.db",
        // Windows
        "C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies",
        "C:\\Users\\bob\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default",
        "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default",
        "C:\\Users\\bob\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\x\\key4.db",
    ] {
        denied_as(p, &ctx, DenyCategory::BrowserProfile);
    }
}

// --------------------------------------------------- wallet extension storage

#[test]
fn wallet_extension_and_desktop_wallet_storage_is_denied() {
    let (_t, _h, ctx) = fixture();
    for p in [
        // Extension storage for a Chromium fork not otherwise listed.
        "~/some-browser/Profile 1/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log",
        "~/some-browser/Profile 1/Sync Extension Settings/x",
        "~/some-browser/Default/IndexedDB/chrome-extension_nkbihfbeogaeaoehlefnkodbefgpgknn_0.indexeddb.leveldb",
        "~/ff/storage/default/moz-extension+++0b1c-uuid/idb/x.sqlite",
        "~/.ethereum/keystore/UTC--2026",
        "~/.foundry/keystores/deployer",
        "~/.citrate-wallet/keystore/k.json",
    ] {
        denied_as(p, &ctx, DenyCategory::WalletStorage);
    }
}

// --------------------------------------------------------- Citrate app data

#[test]
fn citrate_app_data_including_vault_and_hermes_bearer_token_is_denied() {
    let (_t, _h, ctx) = fixture();
    for p in [
        "~/Library/Application Support/ai.citrate.core/hermes/bearer.token",
        "~/Library/Application Support/ai.citrate.core/vault/vault.bin",
        "~/.local/share/ai.citrate.core/hermes/bearer.token",
        "~/.config/ai.citrate.core/settings.json",
        "C:\\Users\\bob\\AppData\\Local\\ai.citrate.core\\hermes\\bearer.token",
        "C:\\Users\\bob\\AppData\\Roaming\\ai.citrate.core\\x",
        "~/Library/Application Support/ai.citrate.core.custody/x",
        "~/.citrate/noise/key",
        "~/.citrate/proposer/key",
        "~/.citrate/keystore/k",
    ] {
        denied_as(p, &ctx, DenyCategory::CitrateAppData);
    }
}

#[test]
fn citrate_model_cache_is_not_app_data() {
    let (_t, _h, ctx) = fixture();
    allowed("~/.citrate/models/gemma.gguf", &ctx);
}

// ------------------------------------------------------------ shell history

#[test]
fn shell_histories_are_denied() {
    let (_t, _h, ctx) = fixture();
    for p in [
        "~/.zsh_history",
        "~/.bash_history",
        "~/.sh_history",
        "~/.local/share/fish/fish_history",
        "~/.python_history",
        "~/.node_repl_history",
        "~/.psql_history",
        "~/.zsh_sessions/ABC.history",
        "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    ] {
        denied_as(p, &ctx, DenyCategory::ShellHistory);
    }
}

// ------------------------------------------------------------------- system

#[test]
fn system_secret_paths_are_denied() {
    let (_t, _h, ctx) = fixture();
    for p in [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/master.passwd",
        "/etc/sudoers",
        "/etc/sudoers.d/90-cloud",
        "/etc/ssh/ssh_host_ed25519_key",
        "/private/etc/master.passwd",
        "/private/var/db/dslocal/nodes/Default/users/root.plist",
        "/var/db/sudo/ts/x",
        "/proc/self/environ",
        "/proc/1/mem",
        "C:\\Windows\\System32\\config\\SAM",
    ] {
        denied_as(p, &ctx, DenyCategory::SystemPath);
    }
}

#[test]
fn ordinary_system_paths_are_allowed() {
    let (_t, _h, ctx) = fixture();
    // `/etc/hosts` exists on macOS and Linux; resolving `/etc` -> `/private/etc`
    // on macOS must not trip the anchored `etc/...` secrets.
    allowed("/etc/hosts", &ctx);
    allowed("/usr/bin/env", &ctx);
}

// --------------------------------------------------------------------- .env

#[test]
fn dotenv_inside_a_granted_project_root_is_allowed() {
    let (_t, home, ctx) = fixture();
    let got = allowed(".env", &ctx);
    assert_eq!(got, home.join("work/proj/.env"));
    allowed("sub/dir/.env.local", &ctx);
}

#[test]
fn dotenv_outside_project_roots_is_denied() {
    let (_t, _h, ctx) = fixture();
    for p in [
        "~/.env",
        "~/work/.env",
        "~/other/.env.production",
        "~/.envrc",
        "/opt/app/.env",
    ] {
        denied_as(p, &ctx, DenyCategory::DotEnv);
    }
}

#[test]
fn dotenv_templates_are_allowed_anywhere() {
    let (_t, _h, ctx) = fixture();
    for p in [
        "~/other/.env.example",
        "~/other/.env.sample",
        "~/other/.env.template",
    ] {
        allowed(p, &ctx);
    }
}

#[test]
fn dotenv_is_denied_when_no_project_root_is_granted() {
    let (_t, home, _ctx) = fixture();
    let bare = GuardContext::new(&home, home.join("work/proj"));
    denied_as(".env", &bare, DenyCategory::DotEnv);
}

// ------------------------------------------------------------- path shapes

#[test]
fn relative_paths_resolve_against_cwd() {
    let (_t, home, ctx) = fixture();
    let got = allowed("src/main.rs", &ctx);
    assert_eq!(got, home.join("work/proj/src/main.rs"));
    denied_as("../../.ssh/id_rsa", &ctx, DenyCategory::Credentials);
    denied_as("./../.././.aws/config", &ctx, DenyCategory::Credentials);
}

#[test]
fn passing_through_a_denied_dir_with_dotdot_is_denied() {
    let (_t, home, ctx) = fixture();
    std::fs::create_dir_all(home.join(".ssh")).expect("mkdir");
    denied_as("~/.ssh/../work/proj/x", &ctx, DenyCategory::Credentials);
}

#[test]
fn tilde_expansion() {
    let (_t, home, ctx) = fixture();
    assert_eq!(allowed("~", &ctx), home);
    assert_eq!(allowed("~/", &ctx), home);
    denied_as("~/.gnupg", &ctx, DenyCategory::Credentials);
    // `~user` cannot be resolved without the account database: fail closed.
    denied_as("~root/.profile", &ctx, DenyCategory::Malformed);
}

#[test]
fn trailing_slashes_and_doubled_separators() {
    let (_t, _h, ctx) = fixture();
    denied_as("~/.ssh/", &ctx, DenyCategory::Credentials);
    denied_as("~//.ssh//", &ctx, DenyCategory::Credentials);
    denied_as("~/.aws/./", &ctx, DenyCategory::Credentials);
}

#[test]
fn windows_style_separators() {
    let (_t, _h, ctx) = fixture();
    denied_as("~\\.ssh\\id_rsa", &ctx, DenyCategory::Credentials);
    denied_as("..\\..\\.ssh\\id_rsa", &ctx, DenyCategory::Credentials);
    denied_as(
        "~/Library\\Keychains/login.keychain-db",
        &ctx,
        DenyCategory::Keychain,
    );
}

#[test]
fn case_variants_are_denied() {
    let (_t, _h, ctx) = fixture();
    denied_as("~/.SSH/id_rsa", &ctx, DenyCategory::Credentials);
    denied_as("~/LIBRARY/keychains/x", &ctx, DenyCategory::Keychain);
    denied_as("~/.Zsh_History", &ctx, DenyCategory::ShellHistory);
    denied_as("/ETC/Shadow", &ctx, DenyCategory::SystemPath);
}

#[test]
fn unicode_normalization_variants_are_denied() {
    let (_t, _h, ctx) = fixture();
    // U+212A KELVIN SIGN is canonically equivalent to `K`.
    denied_as("~/.\u{212A}ube/config", &ctx, DenyCategory::Credentials);
    // U+FF0E FULLWIDTH FULL STOP is compatibility-equivalent to `.`.
    denied_as("~/\u{FF0E}ssh/id_rsa", &ctx, DenyCategory::Credentials);
    // A precomposed vs decomposed spelling must fold to the same key.
    denied_as(
        "~/Library/Application Support/ai.citrate.core/x",
        &ctx,
        DenyCategory::CitrateAppData,
    );
}

#[test]
fn windows_trailing_dot_and_stream_suffixes_are_denied() {
    let (_t, _h, ctx) = fixture();
    denied_as("~/.ssh./id_rsa", &ctx, DenyCategory::Credentials);
    denied_as("~/.netrc::$DATA", &ctx, DenyCategory::Credentials);
}

#[test]
fn malformed_inputs_fail_closed() {
    let (_t, _h, ctx) = fixture();
    denied_as("", &ctx, DenyCategory::Malformed);
    denied_as("a\0b", &ctx, DenyCategory::Malformed);
}

#[test]
fn ordinary_project_paths_are_allowed_and_canonical() {
    let (_t, home, ctx) = fixture();
    let got = allowed("~/work/proj/src/../Cargo.toml", &ctx);
    assert_eq!(got, home.join("work/proj/Cargo.toml"));
    assert!(Path::new(&got).is_absolute());
}

// ---------------------------------------------------------------- symlinks

#[cfg(unix)]
mod symlinks {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn symlink_into_a_denied_dir_is_denied() {
        let (_t, home, ctx) = fixture();
        std::fs::create_dir_all(home.join(".ssh")).expect("mkdir");
        std::fs::write(home.join(".ssh/id_rsa"), b"k").expect("write");
        symlink(home.join(".ssh"), home.join("work/proj/keys")).expect("link");
        denied_as("keys/id_rsa", &ctx, DenyCategory::Credentials);
        denied_as("keys", &ctx, DenyCategory::Credentials);
    }

    #[test]
    fn relative_symlink_into_a_denied_dir_is_denied() {
        let (_t, home, ctx) = fixture();
        std::fs::create_dir_all(home.join(".aws")).expect("mkdir");
        symlink("../../.aws", home.join("work/proj/cfg")).expect("link");
        denied_as("cfg/credentials", &ctx, DenyCategory::Credentials);
    }

    #[test]
    fn dangling_symlink_to_a_denied_target_is_denied_for_writes() {
        let (_t, home, ctx) = fixture();
        // Target does not exist yet; a write through the link would create it.
        symlink(home.join(".ssh/authorized_keys"), home.join("work/proj/ak")).expect("link");
        denied_as("ak", &ctx, DenyCategory::Credentials);
    }

    #[test]
    fn chained_symlinks_are_followed() {
        let (_t, home, ctx) = fixture();
        std::fs::create_dir_all(home.join(".gnupg")).expect("mkdir");
        symlink(home.join(".gnupg"), home.join("work/l2")).expect("l2");
        symlink(home.join("work/l2"), home.join("work/proj/l1")).expect("l1");
        denied_as("l1/secring.gpg", &ctx, DenyCategory::Credentials);
    }

    #[test]
    fn symlink_named_like_a_denied_dir_is_denied_even_if_target_is_benign() {
        let (_t, home, ctx) = fixture();
        std::fs::create_dir_all(home.join("benign")).expect("mkdir");
        symlink(home.join("benign"), home.join(".ssh")).expect("link");
        denied_as("~/.ssh/x", &ctx, DenyCategory::Credentials);
    }

    #[test]
    fn dotdot_after_a_symlink_follows_the_kernel_not_the_lexical_path() {
        let (_t, home, ctx) = fixture();
        // proj/deep -> ~/.ssh/sub ; "deep/../x" is ~/.ssh/x to the kernel,
        // while a lexical normalizer would say proj/x.
        std::fs::create_dir_all(home.join(".ssh/sub")).expect("mkdir");
        symlink(home.join(".ssh/sub"), home.join("work/proj/deep")).expect("link");
        denied_as("deep/../x", &ctx, DenyCategory::Credentials);
    }

    #[test]
    fn symlink_loop_fails_closed() {
        let (_t, home, ctx) = fixture();
        symlink(home.join("work/proj/b"), home.join("work/proj/a")).expect("a");
        symlink(home.join("work/proj/a"), home.join("work/proj/b")).expect("b");
        denied_as("a/x", &ctx, DenyCategory::Unresolvable);
    }

    #[test]
    fn benign_symlink_resolves_to_its_target() {
        let (_t, home, ctx) = fixture();
        std::fs::create_dir_all(home.join("data")).expect("mkdir");
        symlink(home.join("data"), home.join("work/proj/data")).expect("link");
        assert_eq!(allowed("data/x.csv", &ctx), home.join("data/x.csv"));
    }

    #[test]
    fn dotenv_reached_through_a_symlink_from_outside_is_denied() {
        let (_t, home, ctx) = fixture();
        std::fs::create_dir_all(home.join("other")).expect("mkdir");
        std::fs::write(home.join("other/.env"), b"K=V").expect("write");
        symlink(home.join("other/.env"), home.join("work/proj/settings")).expect("link");
        denied_as("settings", &ctx, DenyCategory::DotEnv);
    }

    #[test]
    fn nonexistent_write_target_is_checked_via_nearest_existing_ancestor() {
        let (_t, home, ctx) = fixture();
        std::fs::create_dir_all(home.join(".kube")).expect("mkdir");
        symlink(home.join(".kube"), home.join("work/proj/k")).expect("link");
        denied_as("k/new/dir/file.yaml", &ctx, DenyCategory::Credentials);
        assert_eq!(
            allowed("new/dir/file.txt", &ctx),
            home.join("work/proj/new/dir/file.txt")
        );
    }
}
