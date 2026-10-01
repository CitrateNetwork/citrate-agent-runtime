//! `read_url`: one capped fetch, then local extraction (or the opted-in Jina Reader).

use crate::extract::extract_markdown;
use crate::net::{check_target_static, parse_target, resolve_checked};
use crate::SearchError;
use reqwest::Url;
use std::io::Read;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const USER_AGENT: &str = "CitrateHermes/0.5 (read_url; +https://citrate.ai)";

/// Limits and the address policy for one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadUrlConfig {
    /// Most response body bytes read; the rest is dropped and the page is marked truncated.
    pub max_bytes: usize,
    /// Wall-clock limit for the whole read, redirects included.
    pub timeout: Duration,
    /// Connect limit per hop.
    pub connect_timeout: Duration,
    /// Most redirects followed.
    pub max_redirects: usize,
    /// Non-public addresses that may still be fetched. Empty in production; tests use it for a
    /// loopback fixture server.
    pub allow_private: Vec<IpAddr>,
}

impl Default for ReadUrlConfig {
    fn default() -> Self {
        ReadUrlConfig {
            max_bytes: 2 * 1024 * 1024,
            timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(5),
            max_redirects: 5,
            allow_private: Vec::new(),
        }
    }
}

/// The opted-in Jina Reader: the target URL is sent to `endpoint` (a third party), which fetches
/// the page and returns markdown.
#[derive(Clone, PartialEq, Eq)]
pub struct JinaReader {
    /// `https://r.jina.ai/` by default; the target URL is appended.
    pub endpoint: String,
    pub api_key: Option<String>,
}

impl std::fmt::Debug for JinaReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JinaReader")
            .field("endpoint", &self.endpoint)
            .field("api_key", &self.api_key.as_ref().map(|_| "<set>"))
            .finish()
    }
}

/// How pages are turned into markdown.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ReaderBackend {
    /// Fetch here and extract locally (the default; nothing leaves the machine but the fetch).
    #[default]
    Local,
    /// Explicit opt-in: send the URL to the Jina Reader.
    Jina(JinaReader),
}

/// Which reader produced a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderKind {
    Local,
    Jina,
}

/// One page, as markdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPage {
    /// The URL that was finally read (after redirects); for Jina, the requested URL.
    pub final_url: String,
    pub title: Option<String>,
    pub markdown: String,
    /// The body was longer than `max_bytes` and was cut.
    pub truncated: bool,
    pub content_type: String,
    pub reader: ReaderKind,
    /// Where the URL was sent when a third party read it.
    pub egress: Option<String>,
}

fn remaining(deadline: Instant) -> Result<Duration, SearchError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(SearchError::Timeout)
}

fn map_reqwest(e: reqwest::Error) -> SearchError {
    if e.is_timeout() {
        SearchError::Timeout
    } else if e.is_connect() {
        SearchError::Network("could not connect".into())
    } else {
        SearchError::Network("the transfer failed".into())
    }
}

fn client_for(
    url: &Url,
    addr: std::net::SocketAddr,
    cfg: &ReadUrlConfig,
    left: Duration,
) -> Result<reqwest::blocking::Client, SearchError> {
    let mut b = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(USER_AGENT)
        .connect_timeout(cfg.connect_timeout.min(left))
        .timeout(left);
    if let Some(host) = url.host_str() {
        // Pin the connection to the address that was checked (no second DNS lookup).
        if url.domain().is_some() {
            b = b.resolve(host, addr);
        }
    }
    b.build()
        .map_err(|_| SearchError::Network("HTTP client unavailable".into()))
}

/// Read at most `max` bytes; report whether more was available.
fn read_capped(
    resp: reqwest::blocking::Response,
    max: usize,
    deadline: Instant,
) -> Result<(Vec<u8>, bool), SearchError> {
    let mut body = Vec::new();
    let mut limited = resp.take(max as u64 + 1);
    let mut buf = [0u8; 16 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(SearchError::Timeout);
        }
        let n = match limited.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Err(SearchError::Timeout),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                if Instant::now() >= deadline {
                    return Err(SearchError::Timeout);
                }
                return Err(SearchError::Network("the transfer failed".into()));
            }
        };
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    let truncated = body.len() > max;
    body.truncate(max);
    Ok((body, truncated))
}

fn media_type(ct: &str) -> String {
    ct.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Cut `s` to at most `max` bytes on a char boundary.
fn cut(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut i = max;
        while !s.is_char_boundary(i) {
            i -= 1;
        }
        s.truncate(i);
    }
    s
}

/// Read one URL into markdown.
pub fn read_url(
    cfg: &ReadUrlConfig,
    reader: &ReaderBackend,
    raw: &str,
) -> Result<ReadPage, SearchError> {
    let url = parse_target(raw)?;
    match reader {
        ReaderBackend::Local => read_local(cfg, url),
        ReaderBackend::Jina(j) => read_jina(cfg, j, url),
    }
}

fn read_local(cfg: &ReadUrlConfig, start: Url) -> Result<ReadPage, SearchError> {
    let deadline = Instant::now() + cfg.timeout;
    let mut url = start;
    let mut hops = 0usize;
    loop {
        let addr = resolve_checked(&url, &cfg.allow_private)?;
        let left = remaining(deadline)?;
        let client = client_for(&url, addr, cfg, left)?;
        let resp = client
            .get(url.clone())
            .header(
                "Accept",
                "text/html,application/xhtml+xml,text/plain;q=0.9,text/markdown;q=0.9",
            )
            .send()
            .map_err(map_reqwest)?;
        let status = resp.status();
        if status.is_redirection() {
            if hops >= cfg.max_redirects {
                return Err(SearchError::TooManyRedirects);
            }
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| SearchError::BadResponse("a redirect without a location".into()))?;
            let next = url
                .join(loc)
                .map_err(|_| SearchError::BadResponse("a redirect to an invalid URL".into()))?;
            url = parse_target(next.as_str())?;
            hops += 1;
            continue;
        }
        if !status.is_success() {
            return Err(SearchError::Http(status.as_u16()));
        }
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(media_type)
            .unwrap_or_else(|| "text/html".into());
        let is_html = ct == "text/html" || ct == "application/xhtml+xml";
        let is_text = ct == "text/plain" || ct == "text/markdown" || ct == "text/x-markdown";
        if !is_html && !is_text {
            return Err(SearchError::UnsupportedContent(ct));
        }
        let (body, truncated) = read_capped(resp, cfg.max_bytes, deadline)?;
        let text = String::from_utf8_lossy(&body).into_owned();
        let (title, markdown) = if is_html {
            let ex = extract_markdown(&text, Some(url.as_str()));
            (ex.title, ex.markdown)
        } else {
            (None, text)
        };
        return Ok(ReadPage {
            final_url: url.to_string(),
            title,
            markdown: cut(markdown, cfg.max_bytes),
            truncated,
            content_type: ct,
            reader: crate::ReaderKind::Local,
            egress: None,
        });
    }
}

/// The Jina endpoint must be https, unless it is an allowlisted non-public literal (tests).
fn jina_endpoint(j: &JinaReader, cfg: &ReadUrlConfig) -> Result<Url, SearchError> {
    let ep = Url::parse(j.endpoint.trim())
        .map_err(|_| SearchError::InvalidUrl("the reader endpoint is not a URL".into()))?;
    let literal_allowed = match ep.host() {
        Some(url::Host::Ipv4(v4)) => cfg.allow_private.contains(&IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => cfg.allow_private.contains(&IpAddr::V6(v6)),
        _ => false,
    };
    if ep.scheme() != "https" && !(ep.scheme() == "http" && literal_allowed) {
        return Err(SearchError::InvalidUrl(
            "the reader endpoint must use https".into(),
        ));
    }
    if !ep.username().is_empty() || ep.password().is_some() || ep.query().is_some() {
        return Err(SearchError::InvalidUrl(
            "the reader endpoint must be a plain base URL".into(),
        ));
    }
    Ok(ep)
}

fn read_jina(cfg: &ReadUrlConfig, j: &JinaReader, target: Url) -> Result<ReadPage, SearchError> {
    let ep = jina_endpoint(j, cfg)?;
    // The third party fetches the target, so it cannot be checked by resolving here; refuse
    // literal non-public addresses and local names anyway.
    check_target_static(&target, &cfg.allow_private)?;
    let base = ep.as_str().trim_end_matches('/');
    let full = format!("{base}/{}", target.as_str());
    let req_url = Url::parse(&full)
        .map_err(|_| SearchError::InvalidUrl("could not build the reader URL".into()))?;
    let addr = resolve_checked(&req_url, &cfg.allow_private)?;
    let deadline = Instant::now() + cfg.timeout;
    let client = client_for(&req_url, addr, cfg, remaining(deadline)?)?;
    let mut rb = client
        .get(req_url)
        .header("Accept", "text/plain")
        .header("X-Return-Format", "markdown");
    if let Some(k) = j.api_key.as_deref().filter(|k| !k.is_empty()) {
        rb = rb.bearer_auth(k);
    }
    let resp = rb.send().map_err(map_reqwest)?;
    let status = resp.status();
    if !status.is_success() {
        return Err(SearchError::Http(status.as_u16()));
    }
    let (body, truncated) = read_capped(resp, cfg.max_bytes, deadline)?;
    let markdown = String::from_utf8_lossy(&body).into_owned();
    let title = markdown
        .lines()
        .find_map(|l| l.strip_prefix("Title:"))
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    Ok(ReadPage {
        final_url: target.to_string(),
        title,
        markdown: cut(markdown, cfg.max_bytes),
        truncated,
        content_type: "text/markdown".into(),
        reader: ReaderKind::Jina,
        egress: Some(ep.host_str().unwrap_or("the reader endpoint").to_string()),
    })
}
