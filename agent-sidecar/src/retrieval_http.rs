//! HUP-S1.2 / US-1.4 AC1 — the transports behind tokenizer-true budgets and embedding retrieval.
//!
//! - [`LlamaTokenizer`]: llama-server `POST /tokenize` (`{"content", "add_special": false}` →
//!   `{"tokens": [...]}`), on the same loopback server the session chats with.
//! - [`HttpEmbedder`]: an OpenAI-compatible `POST /v1/embeddings` (`{"input": [...]}` →
//!   `{"data": [{"index", "embedding"}]}`), served by llama-server started with `--embeddings`
//!   (for example a BGE model). `CITRATE_HERMES_EMBED_URL` names a dedicated one; without it the
//!   session tries its own loopback chat server, which answers 501 unless it embeds, and the
//!   session then ranks lexically and says so. `CITRATE_HERMES_EMBED_KEY_FILE` names a file holding
//!   that endpoint's API key (the embedding llama-server citrate-core starts requires one).
//!
//! The wire mapping is pure and tested; each call builds its blocking `reqwest` client inside the
//! call (always on the blocking pool), like [`crate::llm_http::OpenAiCompatClient`]. Errors are
//! coarse and never carry the endpoint, a bearer, or the text.

use citrate_agent_loop::retrieval::{Embedder, Tokenizer};
use serde_json::{json, Value};
use std::time::Duration;

/// Env: a dedicated embedding endpoint (`http://<loopback>[:port][/v1]` or `https://…`).
pub const EMBED_URL_ENV: &str = "CITRATE_HERMES_EMBED_URL";
/// Env (US-1.4): the PATH of a file holding the API key of the endpoint named by
/// [`EMBED_URL_ENV`] (citrate-core writes it `0600` for the embedding llama-server it starts). The
/// key itself never travels in the environment, and is sent only to that endpoint.
pub const EMBED_KEY_FILE_ENV: &str = "CITRATE_HERMES_EMBED_KEY_FILE";
/// Longest key accepted from [`EMBED_KEY_FILE_ENV`] (bytes).
const MAX_EMBED_KEY: usize = 512;

/// Read the embedding endpoint's key from `path`: the file's first line, trimmed. Errors are
/// coarse (never the path's contents).
pub fn read_embed_key(path: &std::path::Path) -> Result<String, String> {
    let raw = std::fs::read(path).map_err(|_| format!("{EMBED_KEY_FILE_ENV} could not be read"))?;
    if raw.len() > MAX_EMBED_KEY {
        return Err(format!("{EMBED_KEY_FILE_ENV} is too long to be a key"));
    }
    let text = String::from_utf8(raw).map_err(|_| format!("{EMBED_KEY_FILE_ENV} is not text"))?;
    let key = text.lines().next().unwrap_or("").trim().to_string();
    if key.is_empty() || key.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!("{EMBED_KEY_FILE_ENV} holds no usable key"));
    }
    Ok(key)
}

/// How long one tokenize call may take. A prompt is a few thousand tokens at most; loopback is
/// fast, so a slow answer means the server is busy or gone, and the session falls back.
pub const TOKENIZE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one embedding call may take (a tool catalog is embedded once per session, then cached).
pub const EMBED_TIMEOUT: Duration = Duration::from_secs(20);
/// Largest response body read from either endpoint.
const MAX_BODY: usize = 16 * 1024 * 1024;

/// The server root of an OpenAI-style base URL: `http://h:p/v1` → `http://h:p`.
pub fn server_root(base_url: &str) -> String {
    let t = base_url.trim_end_matches('/');
    t.strip_suffix("/v1").unwrap_or(t).to_string()
}

/// llama-server's `/tokenize` for an OpenAI-style base URL.
pub fn tokenize_url(base_url: &str) -> String {
    format!("{}/tokenize", server_root(base_url))
}

/// The OpenAI-compatible embeddings URL for a base URL with or without `/v1`.
pub fn embeddings_url(base_url: &str) -> String {
    format!("{}/v1/embeddings", server_root(base_url))
}

/// Whether `url` is plain http to a loopback host (the bundled llama-server).
pub fn is_loopback_http(url: &str) -> bool {
    url.starts_with("http://") && crate::sessions::validate_endpoint(url).is_ok()
}

/// The token count in a `/tokenize` answer.
pub fn parse_tokenize(body: &str) -> Result<usize, String> {
    let v: Value = serde_json::from_str(body).map_err(|_| "the tokenizer answered non-JSON")?;
    v.get("tokens")
        .and_then(Value::as_array)
        .map(Vec::len)
        .ok_or_else(|| "the tokenizer's answer has no tokens array".to_string())
}

/// The vectors in an embeddings answer, ordered by `index`, exactly `n` of them.
pub fn parse_embeddings(body: &str, n: usize) -> Result<Vec<Vec<f32>>, String> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| "the embedding endpoint answered non-JSON")?;
    let data = v
        .get("data")
        .and_then(Value::as_array)
        .ok_or("the embedding answer has no data array")?;
    let mut out: Vec<Option<Vec<f32>>> = vec![None; n];
    for (pos, item) in data.iter().enumerate() {
        let idx = item
            .get("index")
            .and_then(Value::as_u64)
            .map(|i| i as usize)
            .unwrap_or(pos);
        let vec = item
            .get("embedding")
            .and_then(Value::as_array)
            .ok_or("an embedding entry has no vector")?
            .iter()
            .map(|x| x.as_f64().map(|f| f as f32))
            .collect::<Option<Vec<f32>>>()
            .ok_or("an embedding vector holds a non-number")?;
        let slot = out
            .get_mut(idx)
            .ok_or("the embedding answer has an index out of range")?;
        if slot.is_some() {
            return Err("the embedding answer repeats an index".into());
        }
        *slot = Some(vec);
    }
    out.into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| format!("the embedding answer has fewer than {n} vectors"))
}

/// Read at most `cap` bytes of a response body as UTF-8; a longer body is refused without reading
/// past `cap + 1` bytes.
pub fn read_capped<R: std::io::Read>(r: R, cap: usize) -> Result<String, String> {
    use std::io::Read;
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut buf = Vec::new();
    r.take(limit)
        .read_to_end(&mut buf)
        .map_err(|_| "could not read the response".to_string())?;
    if buf.len() > cap {
        return Err("the response is too large".into());
    }
    String::from_utf8(buf).map_err(|_| "the response is not UTF-8".to_string())
}

/// One blocking POST of a JSON body; the response text or a coarse error.
fn post_json(url: &str, bearer: &str, timeout: Duration, body: &Value) -> Result<String, String> {
    let http = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(timeout)
        .build()
        .map_err(|_| "HTTP client unavailable".to_string())?;
    let mut rb = http.post(url).json(body);
    if !bearer.is_empty() {
        rb = rb.bearer_auth(bearer);
    }
    let resp = rb.send().map_err(|e| {
        if e.is_timeout() {
            "timed out".to_string()
        } else if e.is_connect() {
            "could not connect".to_string()
        } else {
            "request failed".to_string()
        }
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status.as_u16()));
    }
    read_capped(resp, MAX_BODY)
}

/// llama-server's tokenizer, over HTTP.
pub struct LlamaTokenizer {
    url: String,
    bearer: String,
    timeout: Duration,
}

impl LlamaTokenizer {
    /// `base_url` like `http://127.0.0.1:18080/v1` (the session's chat endpoint).
    pub fn new(base_url: &str, bearer: &str) -> Self {
        LlamaTokenizer {
            url: tokenize_url(base_url),
            bearer: bearer.to_string(),
            timeout: TOKENIZE_TIMEOUT,
        }
    }
}

impl Tokenizer for LlamaTokenizer {
    fn token_count(&self, text: &str) -> Result<usize, String> {
        let body = json!({ "content": text, "add_special": false });
        let text = post_json(&self.url, &self.bearer, self.timeout, &body)
            .map_err(|e| format!("the model's tokenizer did not answer ({e})"))?;
        parse_tokenize(&text)
    }
}

/// An OpenAI-compatible embeddings endpoint, over HTTP.
pub struct HttpEmbedder {
    url: String,
    bearer: String,
    timeout: Duration,
}

impl HttpEmbedder {
    pub fn new(base_url: &str, bearer: &str) -> Self {
        HttpEmbedder {
            url: embeddings_url(base_url),
            bearer: bearer.to_string(),
            timeout: EMBED_TIMEOUT,
        }
    }
}

impl Embedder for HttpEmbedder {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let body = json!({ "input": texts, "model": "embedding", "encoding_format": "float" });
        let text = post_json(&self.url, &self.bearer, self.timeout, &body)
            .map_err(|e| format!("the embedding endpoint did not answer ({e})"))?;
        parse_embeddings(&text, texts.len())
    }
}
