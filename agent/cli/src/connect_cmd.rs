//! `citrate-agent connect` — one-click login that writes the memory config file,
//! so a standalone agent needs no environment variables.
//!
//! Flow: OIDC authorization-code + PKCE with a loopback redirect (auth.citrate.ai
//! has no device endpoint) → id_token → `POST <gateway>/connect/token` mints a
//! long-lived connect token → write `~/.config/citrate/memory.json`. The user
//! clicks through a browser login once; no token or secret is ever typed.
//!
//! Prerequisites (owner-side): a public `citrate-cli` OIDC client registered at
//! the issuer with a `http://127.0.0.1` loopback redirect, and the gateway's
//! `/connect/token` endpoint deployed.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;

use base64::Engine;
use clap::Args;
use sha2::{Digest, Sha256};

#[derive(Args, Debug)]
pub struct ConnectArgs {
    /// OIDC issuer.
    #[arg(long, default_value = "https://auth.citrate.ai")]
    issuer: String,
    /// Public OIDC client id registered for the CLI (loopback redirect).
    #[arg(long, default_value = "citrate-cli")]
    client_id: String,
    /// Memory gateway origin (mints the connect token).
    #[arg(long, default_value = "https://mem-gateway.citrate.ai")]
    gateway: String,
    /// Where to write the config (default: $CITRATE_MEMORY_CONFIG or
    /// ~/.config/citrate/memory.json).
    #[arg(long)]
    config: Option<String>,
    /// Print the config that would be written instead of writing it.
    #[arg(long)]
    dry_run: bool,
}

pub fn run(args: ConnectArgs) -> i32 {
    match connect(&args) {
        Ok(path) => {
            println!("✓ connected — wrote {}", path.display());
            0
        }
        Err(e) => {
            eprintln!("connect failed: {e}");
            1
        }
    }
}

fn connect(args: &ConnectArgs) -> Result<PathBuf, String> {
    let disco = discover(&args.issuer)?;
    let verifier = pkce_verifier();
    let challenge = pkce_challenge(&verifier);
    let state = random_urlsafe(24);

    // Loopback redirect on an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind loopback: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid&state={}&code_challenge={}&code_challenge_method=S256",
        disco.authorization_endpoint,
        urlencode(&args.client_id),
        urlencode(&redirect),
        urlencode(&state),
        urlencode(&challenge),
    );

    println!("Opening your browser to sign in…");
    println!("If it doesn't open, visit:\n  {auth_url}");
    let _ = open_browser(&auth_url);

    let code = wait_for_code(&listener, &state)?;

    // Exchange the code for an id_token (PKCE — no client secret).
    let id_token = exchange_code(&disco.token_endpoint, &args.client_id, &redirect, &code, &verifier)?;

    // Trade the id_token for a long-lived connect token.
    let (sub, connect_token) = mint_connect(&args.gateway, &id_token)?;

    let cfg = serde_json::json!({
        "origin": args.gateway.trim_end_matches('/'),
        "sub": sub,
        "connect_token": connect_token,
    });
    let path = config_path(args.config.as_deref());
    if args.dry_run {
        println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
        return Ok(path);
    }
    write_config(&path, &serde_json::to_vec_pretty(&cfg).unwrap())?;
    Ok(path)
}

// --- OIDC discovery ---

struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

fn discover(issuer: &str) -> Result<Discovery, String> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let v: serde_json::Value = http_get_json(&url)?;
    let field = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("discovery missing {k}"))
    };
    Ok(Discovery {
        authorization_endpoint: field("authorization_endpoint")?,
        token_endpoint: field("token_endpoint")?,
    })
}

// --- PKCE ---

fn pkce_verifier() -> String {
    random_urlsafe(32)
}

/// S256: base64url-nopad( SHA256( ascii(verifier) ) ).
fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn random_urlsafe(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).expect("OS randomness");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

// --- Loopback callback ---

fn wait_for_code(listener: &TcpListener, expected_state: &str) -> Result<String, String> {
    let (mut stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
    let req = String::from_utf8_lossy(&buf[..n]);
    // First line: "GET /callback?code=..&state=.. HTTP/1.1"
    let target = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or("malformed callback request")?;
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let params = parse_query(query);

    let body;
    let result;
    if let Some(err) = params.get("error") {
        body = "Login failed. You can close this tab.";
        result = Err(format!("authorization error: {err}"));
    } else if params.get("state").map(String::as_str) != Some(expected_state) {
        body = "State mismatch. You can close this tab.";
        result = Err("state mismatch (possible CSRF) — aborted".to_string());
    } else if let Some(code) = params.get("code") {
        body = "Connected. You can close this tab and return to the terminal.";
        result = Ok(code.clone());
    } else {
        body = "No authorization code. You can close this tab.";
        result = Err("callback carried no code".to_string());
    }
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><p>{body}</p></body></html>"
    );
    result
}

fn parse_query(q: &str) -> std::collections::HashMap<String, String> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), urldecode(v)))
        .collect()
}

// --- Token exchange + mint ---

fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    redirect: &str,
    code: &str,
    verifier: &str,
) -> Result<String, String> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    let resp = reqwest::blocking::Client::new()
        .post(token_endpoint)
        .form(&form)
        .send()
        .map_err(|e| format!("token request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("token endpoint {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().map_err(|e| format!("token response: {e}"))?;
    v.get("id_token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "token response had no id_token".to_string())
}

fn mint_connect(gateway: &str, id_token: &str) -> Result<(String, String), String> {
    let url = format!("{}/connect/token", gateway.trim_end_matches('/'));
    let resp = reqwest::blocking::Client::new()
        .post(&url)
        .bearer_auth(id_token)
        .send()
        .map_err(|e| format!("mint request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("mint endpoint {} (is /connect/token deployed?)", resp.status()));
    }
    let v: serde_json::Value = resp.json().map_err(|e| format!("mint response: {e}"))?;
    let get = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("mint response missing {k}"))
    };
    Ok((get("sub")?, get("connect_token")?))
}

// --- Config + helpers ---

fn config_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("CITRATE_MEMORY_CONFIG") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.config")))
        .unwrap_or_else(|| ".config".to_string());
    PathBuf::from(base).join("citrate").join("memory.json")
}

fn write_config(path: &PathBuf, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    // 0600 — the file holds a token.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let resp = reqwest::blocking::get(url).map_err(|e| format!("GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {url} -> {}", resp.status()));
    }
    resp.json().map_err(|e| format!("parse {url}: {e}"))
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let (cmd, args) = ("open", vec![url]);
    #[cfg(target_os = "linux")]
    let (cmd, args) = ("xdg-open", vec![url]);
    #[cfg(target_os = "windows")]
    let (cmd, args) = ("cmd", vec!["/C", "start", "", url]);
    std::process::Command::new(cmd).args(args).spawn().map(|_| ())
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn urldecode(s: &str) -> String {
    let bytes = s.replace('+', " ");
    let bytes = bytes.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636_vector() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_challenge(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn verifier_is_urlsafe_and_long_enough() {
        let v = pkce_verifier();
        assert!(v.len() >= 43, "PKCE verifier must be >= 43 chars, got {}", v.len());
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')));
    }

    #[test]
    fn parse_query_decodes_pairs() {
        let m = parse_query("code=abc%2F123&state=xy%2Bz");
        assert_eq!(m.get("code").unwrap(), "abc/123");
        assert_eq!(m.get("state").unwrap(), "xy+z");
    }

    #[test]
    fn url_round_trip() {
        let s = "oidc|abc/def+ghi";
        assert_eq!(urldecode(&urlencode(s)), s);
    }

    #[test]
    fn config_path_prefers_explicit_then_env() {
        assert_eq!(config_path(Some("/tmp/x.json")), PathBuf::from("/tmp/x.json"));
    }
}
