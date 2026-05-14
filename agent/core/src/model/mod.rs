//! Model resolver — RFC-CIT-AGENT-0001 §3.1 "Model Resolver".
//!
//! Lands in CIT-AGENT-3 (alongside the capsule loader) per planset
//! [`.agentile/planset/2026-05-14-citrate-agent/08_SPRINT_SEQUENCE.md`].
//!
//! Will contain: `pub trait Model + ResolvedModel`, local Ollama
//! discovery (port 11434), local llama.cpp server (8080, 8000),
//! embedded llama-cpp-4 with bundled GGUF (Gemma 4 E2B), and SHA-256
//! verification of model files vs manifest declaration (NIST SI-7).
