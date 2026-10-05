//! # citrate-agent-search: private search and page reading for Hermes (HUP-S5.2, D-13)
//!
//! Two sidecar-hosted tools, both read-only and both **untrusted** (their output taints the
//! session under the HUP-S2.7 taint rule):
//!
//! - **`read_url`** fetches one http(s) page with hard caps (bytes, wall-clock time, redirects),
//!   refuses any target that resolves to a loopback, private, link-local or otherwise non-public
//!   address (each redirect hop is re-checked, and the connection is pinned to the checked
//!   address), and turns HTML into markdown **locally** with a readability pass
//!   ([`extract`]). No third-party service sees the URL by default. The Jina Reader
//!   ([`JinaReader`]) is an explicit opt-in; when used, the output says so.
//! - **`web_search`** queries a local SearXNG instance that [`SearxngSupervisor`] starts from a
//!   configured install path on first use, bound to 127.0.0.1 with a generated private settings
//!   file. When no SearXNG is installed the tool says "not installed" and searches nothing.
//!   SearXNG itself forwards queries to its configured upstream engines; bundling and engine
//!   policy are HUP-S5.5's job.
//!
//! Nothing here holds a key or signs (Rule 3). The Jina API key, when the member supplies one, is
//! read from a file and sent only to the configured Jina endpoint.

mod error;
mod extract;
mod fetch;
mod host;
mod net;
mod searxng;

pub use error::SearchError;
pub use extract::{extract_markdown, Extracted};
pub use fetch::{read_url, JinaReader, ReadPage, ReadUrlConfig, ReaderBackend, ReaderKind};
pub use host::{
    SearchConfig, SearchHost, DEFAULT_READ_CHARS, MAX_QUERY_CHARS, MAX_READ_CHARS, READ_URL_TOOL,
    TOOL_NAMES, WEB_SEARCH_TOOL,
};
pub use net::{is_public_ip, JINA_DEFAULT_ENDPOINT};
pub use searxng::{
    engine_name_ok, parse_search_results, SearchHit, SearxngConfig, SearxngState,
    SearxngSupervisor, DEFAULT_ENGINES, MAX_ENGINES,
};
