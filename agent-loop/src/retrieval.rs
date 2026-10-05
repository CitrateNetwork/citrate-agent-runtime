//! # HUP-S1.2 / US-1.4 AC1 — tokenizer-true budgets and embedding-assisted retrieval
//!
//! Two pieces the sidecar plugs into a session, both with an honest fallback:
//!
//! - [`ModelTokenCounter`]: counts tokens with the model's own tokenizer (the sidecar backs it with
//!   llama-server `POST /tokenize`), caches the counts, and falls back to [`CharTokenCounter`]
//!   when the tokenizer does not answer. Once it falls back it stays on the estimate for the rest
//!   of the session (counts within one session never mix the two), and [`ModelTokenCounter::mode`]
//!   says so: `model` or `estimated` with the reason.
//! - [`HybridRetriever`]: ranks tools ([`ToolSelector`]) and skills ([`SkillRanker`]) by cosine
//!   similarity of embeddings (llama-server `/v1/embeddings`, for example a BGE model) blended with
//!   the keyword score (tools) or BM25 (skills). When the embedding endpoint does not answer, it
//!   ranks exactly like [`KeywordSelector`] and [`Bm25Ranker`], and [`HybridRetriever::mode`] says
//!   `lexical` with the reason.
//!
//! Neither piece holds a key or reaches anything but the endpoints it was built with; the
//! transports live in the sidecar.

use crate::skills::{bm25_scores, Bm25Ranker, SkillRanker};
use crate::{
    keyword_scores, CharTokenCounter, KeywordSelector, TokenCounter, ToolSelector, ToolSpec,
};
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

/// Most cached entries (token counts or embeddings) per counter or retriever. The cache is cleared
/// when it fills, which only costs a recount.
const CACHE_CAP: usize = 4096;

/// Cache key: the text's hash and its length.
fn key(text: &str) -> (u64, usize) {
    let mut h = DefaultHasher::new();
    text.hash(&mut h);
    (h.finish(), text.len())
}

// ---------------------------------------------------------------------------------------------
// Token counting
// ---------------------------------------------------------------------------------------------

/// The model's tokenizer. `token_count` returns how many tokens `text` is, without special tokens.
pub trait Tokenizer: Send + Sync {
    fn token_count(&self, text: &str) -> Result<usize, String>;
}

/// How a session's tokens are counted (reported in the session's metadata).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum TokenCounting {
    /// Nothing has been counted yet.
    Unprobed,
    /// Every count so far came from the model's tokenizer.
    Model,
    /// Counts are the four-characters-per-token estimate, for this reason.
    Estimated { reason: String },
}

/// A [`TokenCounter`] backed by the model's tokenizer, with a cache and an honest fallback.
pub struct ModelTokenCounter {
    backend: Option<Arc<dyn Tokenizer>>,
    cache: Mutex<HashMap<(u64, usize), usize>>,
    state: Mutex<TokenCounting>,
}

impl ModelTokenCounter {
    /// Count with `backend`; fall back to the estimate the first time it fails.
    pub fn new(backend: Arc<dyn Tokenizer>) -> Self {
        ModelTokenCounter {
            backend: Some(backend),
            cache: Mutex::new(HashMap::new()),
            state: Mutex::new(TokenCounting::Unprobed),
        }
    }

    /// No tokenizer is reachable: every count is the estimate, reported with `reason`.
    pub fn estimated(reason: impl Into<String>) -> Self {
        ModelTokenCounter {
            backend: None,
            cache: Mutex::new(HashMap::new()),
            state: Mutex::new(TokenCounting::Estimated {
                reason: reason.into(),
            }),
        }
    }

    /// How counts are made right now.
    pub fn mode(&self) -> TokenCounting {
        self.state
            .lock()
            .map(|s| s.clone())
            .unwrap_or(TokenCounting::Estimated {
                reason: "the counter's state could not be read".into(),
            })
    }

    /// Count one short probe so [`ModelTokenCounter::mode`] is known before the first turn.
    pub fn probe(&self) -> TokenCounting {
        let _ = self.count("Hermes counts tokens with the model's tokenizer.");
        self.mode()
    }

    fn fall_back(&self, reason: String) {
        if let Ok(mut s) = self.state.lock() {
            if !matches!(*s, TokenCounting::Estimated { .. }) {
                *s = TokenCounting::Estimated { reason };
            }
        }
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }
}

impl TokenCounter for ModelTokenCounter {
    fn count(&self, s: &str) -> usize {
        if s.is_empty() {
            return 0;
        }
        let backend = match (&self.backend, self.mode()) {
            (Some(b), TokenCounting::Unprobed | TokenCounting::Model) => b,
            _ => return CharTokenCounter.count(s),
        };
        let k = key(s);
        if let Some(n) = self.cache.lock().ok().and_then(|c| c.get(&k).copied()) {
            return n;
        }
        match backend.token_count(s) {
            Ok(n) => {
                if let Ok(mut st) = self.state.lock() {
                    if *st == TokenCounting::Unprobed {
                        *st = TokenCounting::Model;
                    }
                }
                if let Ok(mut c) = self.cache.lock() {
                    if c.len() >= CACHE_CAP {
                        c.clear();
                    }
                    c.insert(k, n);
                }
                n
            }
            Err(e) => {
                self.fall_back(e);
                CharTokenCounter.count(s)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Embedding-assisted retrieval
// ---------------------------------------------------------------------------------------------

/// An embedding model: one vector per input text, all of the same length.
pub trait Embedder: Send + Sync {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String>;
}

/// How a session's tools and skills are ranked (reported in the session's metadata).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum RetrievalMode {
    /// Nothing has been ranked yet.
    Unprobed,
    /// Embedding similarity blended with the lexical score.
    Embedding,
    /// The lexical score alone, for this reason.
    Lexical { reason: String },
}

/// Weight of embedding similarity in the blended score (the lexical score has the rest).
pub const EMBEDDING_WEIGHT: f32 = 0.6;
/// A skill that shares no term with the request is surfaced only when its embedding similarity
/// reaches this (cosine). BGE-class models put unrelated English text well below it.
pub const SKILL_MIN_SIMILARITY: f32 = 0.6;

/// Ranks tools and skills by embedding similarity plus the lexical score, falling back to the
/// lexical score alone when the embedder fails (and staying there for the rest of the session).
pub struct HybridRetriever {
    embedder: Option<Arc<dyn Embedder>>,
    cache: Mutex<HashMap<(u64, usize), Vec<f32>>>,
    state: Mutex<RetrievalMode>,
}

impl HybridRetriever {
    pub fn new(embedder: Arc<dyn Embedder>) -> Self {
        HybridRetriever {
            embedder: Some(embedder),
            cache: Mutex::new(HashMap::new()),
            state: Mutex::new(RetrievalMode::Unprobed),
        }
    }

    /// No embedding endpoint is configured: rank lexically, reported with `reason`.
    pub fn lexical(reason: impl Into<String>) -> Self {
        HybridRetriever {
            embedder: None,
            cache: Mutex::new(HashMap::new()),
            state: Mutex::new(RetrievalMode::Lexical {
                reason: reason.into(),
            }),
        }
    }

    pub fn mode(&self) -> RetrievalMode {
        self.state
            .lock()
            .map(|s| s.clone())
            .unwrap_or(RetrievalMode::Lexical {
                reason: "the retriever's state could not be read".into(),
            })
    }

    /// Embed one short probe so [`HybridRetriever::mode`] is known before the first turn.
    pub fn probe(&self) -> RetrievalMode {
        let _ = self.embed_all("Hermes ranks tools and skills by meaning.", &[]);
        self.mode()
    }

    fn fall_back(&self, reason: String) {
        if let Ok(mut s) = self.state.lock() {
            if !matches!(*s, RetrievalMode::Lexical { .. }) {
                *s = RetrievalMode::Lexical { reason };
            }
        }
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }

    /// The query's vector and one per doc, or `None` (after falling back) when the embedder is
    /// absent, fails, or answers with the wrong shape. Doc vectors are cached; the query's is not.
    fn embed_all(&self, query: &str, docs: &[String]) -> Option<(Vec<f32>, Vec<Vec<f32>>)> {
        let embedder = match (&self.embedder, self.mode()) {
            (Some(e), RetrievalMode::Unprobed | RetrievalMode::Embedding) => e,
            _ => return None,
        };
        let cached: Vec<Option<Vec<f32>>> = {
            let c = self.cache.lock().ok()?;
            docs.iter().map(|d| c.get(&key(d)).cloned()).collect()
        };
        let mut ask: Vec<String> = vec![query.to_string()];
        let missing: Vec<usize> = (0..docs.len()).filter(|i| cached[*i].is_none()).collect();
        ask.extend(missing.iter().map(|i| docs[*i].clone()));
        let got = match embedder.embed(&ask) {
            Ok(v) => v,
            Err(e) => {
                self.fall_back(e);
                return None;
            }
        };
        let dim = got.first().map(Vec::len).unwrap_or(0);
        if got.len() != ask.len() || dim == 0 || got.iter().any(|v| v.len() != dim) {
            self.fall_back(format!(
                "the embedding endpoint answered {} vectors for {} texts, or vectors of unequal length",
                got.len(),
                ask.len()
            ));
            return None;
        }
        let mut got = got.into_iter();
        let q = got.next()?;
        let mut out: Vec<Option<Vec<f32>>> = cached;
        if let Ok(mut c) = self.cache.lock() {
            if c.len() + missing.len() > CACHE_CAP {
                c.clear();
            }
            for (i, v) in missing.iter().zip(got) {
                c.insert(key(&docs[*i]), v.clone());
                out[*i] = Some(v);
            }
        }
        let vecs: Option<Vec<Vec<f32>>> = out.into_iter().collect();
        let vecs = vecs?;
        if vecs.iter().any(|v| v.len() != dim) {
            self.fall_back("cached and fresh embeddings have different lengths".into());
            return None;
        }
        if let Ok(mut s) = self.state.lock() {
            if *s == RetrievalMode::Unprobed {
                *s = RetrievalMode::Embedding;
            }
        }
        Some((q, vecs))
    }
}

/// Cosine similarity (0 when either vector is all zeros).
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let (mut dot, mut na, mut nb) = (0f32, 0f32, 0f32);
    for (x, y) in a.iter().zip(b) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na.sqrt() * nb.sqrt())
    }
}

fn tool_doc(s: &ToolSpec) -> String {
    format!("{}: {}", s.name.replace('_', " "), s.description)
}

fn skill_doc(name: &str, desc: &str) -> String {
    format!("{}: {}", name.replace('-', " "), desc)
}

impl ToolSelector for HybridRetriever {
    fn select(&self, query: &str, specs: &[ToolSpec], k: usize) -> Vec<ToolSpec> {
        if k == 0 || specs.is_empty() {
            return Vec::new();
        }
        let docs: Vec<String> = specs.iter().map(tool_doc).collect();
        let Some((q, vecs)) = self.embed_all(query, &docs) else {
            return KeywordSelector.select(query, specs, k);
        };
        let kw = keyword_scores(query, specs);
        let max_kw = kw.iter().copied().max().unwrap_or(0) as f32;
        let mut scored: Vec<(usize, f32)> = vecs
            .iter()
            .zip(&kw)
            .enumerate()
            .map(|(i, (v, kw))| {
                let lex = if max_kw > 0.0 {
                    *kw as f32 / max_kw
                } else {
                    0.0
                };
                let sim = cosine(&q, v).max(0.0);
                (i, EMBEDDING_WEIGHT * sim + (1.0 - EMBEDDING_WEIGHT) * lex)
            })
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        scored
            .into_iter()
            .take(k)
            .map(|(i, _)| specs[i].clone())
            .collect()
    }
}

impl SkillRanker for HybridRetriever {
    fn method(&self) -> &'static str {
        match self.mode() {
            RetrievalMode::Lexical { .. } => "bm25-lexical",
            RetrievalMode::Unprobed | RetrievalMode::Embedding => "hybrid-embedding-bm25",
        }
    }

    fn rank(&self, query: &str, docs: &[(&str, &str)], k: usize) -> Vec<usize> {
        if k == 0 || docs.is_empty() {
            return Vec::new();
        }
        let texts: Vec<String> = docs.iter().map(|(n, d)| skill_doc(n, d)).collect();
        let Some((q, vecs)) = self.embed_all(query, &texts) else {
            return Bm25Ranker.rank(query, docs, k);
        };
        let bm = bm25_scores(query, docs);
        let max_bm = bm.iter().copied().fold(0.0f64, f64::max);
        let mut scored: Vec<(usize, f32)> = vecs
            .iter()
            .zip(&bm)
            .enumerate()
            .filter_map(|(i, (v, b))| {
                let sim = cosine(&q, v).max(0.0);
                if *b <= 0.0 && sim < SKILL_MIN_SIMILARITY {
                    return None;
                }
                let lex = if max_bm > 0.0 {
                    (*b / max_bm) as f32
                } else {
                    0.0
                };
                Some((i, EMBEDDING_WEIGHT * sim + (1.0 - EMBEDDING_WEIGHT) * lex))
            })
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        scored.into_iter().take(k).map(|(i, _)| i).collect()
    }
}
