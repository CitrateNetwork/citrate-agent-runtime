//! Errors. Messages are coarse: they never carry a key, a request body, or page content.

/// Why a search or read did not produce content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchError {
    /// The URL is not an absolute http(s) URL without credentials.
    InvalidUrl(String),
    /// The target is not a public internet address.
    Blocked(String),
    /// The wall-clock limit passed.
    Timeout,
    /// The server could not be reached or the transfer failed.
    Network(String),
    /// The server answered with a non-success status.
    Http(u16),
    /// More redirects than the limit.
    TooManyRedirects,
    /// The page is not text, HTML or markdown.
    UnsupportedContent(String),
    /// No SearXNG is installed or configured.
    NotInstalled(String),
    /// SearXNG is configured but could not be started or queried.
    Unavailable(String),
    /// The response could not be understood.
    BadResponse(String),
}

impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchError::InvalidUrl(m) => write!(f, "not a readable URL: {m}"),
            SearchError::Blocked(m) => write!(f, "refused: {m}"),
            SearchError::Timeout => write!(f, "timed out"),
            SearchError::Network(m) => write!(f, "network error: {m}"),
            SearchError::Http(code) => write!(f, "the server answered HTTP {code}"),
            SearchError::TooManyRedirects => write!(f, "too many redirects"),
            SearchError::UnsupportedContent(ct) => {
                write!(
                    f,
                    "unsupported content type {ct:?} (only text, HTML and markdown are read)"
                )
            }
            SearchError::NotInstalled(m) => write!(f, "web search is not installed: {m}"),
            SearchError::Unavailable(m) => write!(f, "web search is unavailable: {m}"),
            SearchError::BadResponse(m) => write!(f, "unexpected response: {m}"),
        }
    }
}

impl std::error::Error for SearchError {}
