//! HUP-S1.3: the session-scoped hosts behind the `http_status_is` and `sha256_equals` workflow
//! verifiers.
//!
//! - [`SessionHttpProbe`] checks one `GET` against a URL whose origin is loopback, or an origin
//!   the member consented to in the browser's origin scope (the same per-origin consent, and the
//!   same sensitive-origin denylist, as attach mode; HUP-S5.6). It follows no redirects (a 302
//!   is the answer, not a hop to another origin), sends no cookies or credentials, and waits at
//!   most [`citrate_agent_loop::HTTP_VERIFIER_MAX_TIMEOUT`].
//! - [`GrantFileDigest`] hashes one file only when the session's live folder grants allow reading
//!   it (the grant ledger's own check, including the default-deny list), and only up to
//!   [`MAX_HASH_BYTES`].
//!
//! Both are checked again at every verdict, so a consent or grant revoked mid-run fails the next
//! check instead of being remembered.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use citrate_agent_browser::scope::Origin;
use citrate_agent_browser::BrowserService;
use citrate_agent_grants::Op;
use citrate_agent_loop::workflows::VerifierEnv;
use citrate_agent_loop::{FileDigest, HttpProbe, HTTP_VERIFIER_MAX_TIMEOUT};
use sha2::{Digest, Sha256};

use crate::grants::SessionGrants;

/// The largest file a `sha256_equals` check reads.
pub const MAX_HASH_BYTES: u64 = 1 << 30;

/// True for `localhost`, `127.0.0.0/8` and `[::1]` (an origin's normalised host).
pub fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host == "[::1]" {
        return true;
    }
    host.parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// `GET` probe for one session: loopback, or an origin the member consented to.
pub struct SessionHttpProbe {
    browser: Option<Arc<BrowserService>>,
}

impl SessionHttpProbe {
    /// `browser`: the browser worker whose origin consents also open an origin here (`None`:
    /// loopback only).
    pub fn new(browser: Option<Arc<BrowserService>>) -> Self {
        SessionHttpProbe { browser }
    }

    /// May a verifier contact `url`? Returns the normalised origin.
    pub fn allowed(&self, url: &str) -> Result<String, String> {
        let origin = Origin::parse(url)?;
        let shown = origin.to_string();
        if is_loopback_host(origin.host()) {
            return Ok(shown);
        }
        let consented = self
            .browser
            .as_ref()
            .map(|b| b.consented_origins())
            .unwrap_or_default();
        if consented.contains(&shown) {
            return Ok(shown);
        }
        Err(format!(
            "{shown} is not loopback and the member has not consented to it"
        ))
    }
}

impl HttpProbe for SessionHttpProbe {
    fn status(&self, url: &str, timeout: Duration) -> Result<u16, String> {
        self.allowed(url)?;
        let timeout = timeout.min(HTTP_VERIFIER_MAX_TIMEOUT);
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(timeout)
            .connect_timeout(timeout)
            .build()
            .map_err(|e| format!("no HTTP client: {e}"))?;
        let resp = client.get(url).send().map_err(|e| {
            if e.is_timeout() {
                format!("no answer within {} s", timeout.as_secs())
            } else if e.is_connect() {
                "unreachable (connection failed)".to_string()
            } else {
                "unreachable".to_string()
            }
        })?;
        Ok(resp.status().as_u16())
    }
}

/// SHA-256 of files inside one session's folder grants.
pub struct GrantFileDigest {
    grants: Arc<SessionGrants>,
}

impl GrantFileDigest {
    pub fn new(grants: Arc<SessionGrants>) -> Self {
        GrantFileDigest { grants }
    }
}

impl FileDigest for GrantFileDigest {
    fn sha256_hex(&self, path: &str) -> Result<String, String> {
        let p = Path::new(path);
        if !p.is_absolute() {
            return Err("the path must be absolute".into());
        }
        let (canonical, _) = self
            .grants
            .check(p, Op::Read)
            .map_err(|why| format!("outside the folder grants: {why}"))?;
        let file = std::fs::File::open(&canonical).map_err(|e| format!("cannot open: {e}"))?;
        let meta = file.metadata().map_err(|e| format!("cannot stat: {e}"))?;
        if !meta.is_file() {
            return Err("not a regular file".into());
        }
        if meta.len() > MAX_HASH_BYTES {
            return Err(format!("larger than {MAX_HASH_BYTES} bytes"));
        }
        let mut hasher = Sha256::new();
        let mut reader = file.take(MAX_HASH_BYTES + 1);
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| format!("cannot read: {e}"))?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            if total > MAX_HASH_BYTES {
                return Err(format!("larger than {MAX_HASH_BYTES} bytes"));
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }
}

/// The verifier hosts for one session: HTTP always (loopback or consented origins), hashing only
/// when the session has folder grants.
pub fn env_for(
    browser: Option<Arc<BrowserService>>,
    grants: Option<Arc<SessionGrants>>,
) -> VerifierEnv {
    VerifierEnv {
        http: Some(Arc::new(SessionHttpProbe::new(browser))),
        files: grants.map(|g| Arc::new(GrantFileDigest::new(g)) as Arc<dyn FileDigest>),
    }
}
