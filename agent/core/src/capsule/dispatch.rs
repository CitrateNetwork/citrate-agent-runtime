//! CIT-AGENT-9c-shell-wire-prep — `CapsuleDispatch` helper.
//!
//! Encapsulates the production wire-up for a fleet of capsules:
//! load capsule archives from a directory at startup, build their
//! per-capsule linkers eagerly, and expose a single `call_raw`
//! method that invokes a named export on a named capsule.
//!
//! The defense_prime-shell consumes this through a per-tool adapter that
//! translates the chat tool's JSON args into the capsule's WIT
//! types + formats the returned `Val` into a chat-displayable
//! string. Adapter code stays in the consumer crate — this struct
//! is the library boundary.

use crate::capsule::dispatcher::{ApprovalGate, EthCallDispatcher, EthSendDispatcher};
use crate::capsule::manifest::Manifest;
use crate::capsule::wasm::EngineFactory;
use crate::capsule::{archive, bundled_key, Capsule};
use crate::error::AgentError;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Interval between `engine.increment_epoch()` advances. With the per-call
/// `set_epoch_deadline(600)` armed in `call_raw`, this gives a ~30 s
/// wall-clock compute budget per capsule call (600 × 50 ms).
const EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(50);

/// RM-E.2 / AGENT_RUNTIME-002: the background epoch ticker.
///
/// `EngineFactory::build` enables `Config::epoch_interruption(true)` and
/// `call_raw` arms `set_epoch_deadline(600)`, but that deadline is INERT
/// unless something advances the engine's epoch counter — otherwise a
/// capsule that enters `(loop (br 0))` runs forever on the worker thread
/// (fuel is disabled), a persistent DoS. This ticker advances the counter
/// on a fixed interval for the lifetime of the owning `CapsuleDispatch`,
/// so the armed deadline actually traps. Stops cleanly on `Drop`.
struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    fn spawn(engine: &wasmtime::Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        // `Engine` is `Arc`-backed and `Send + Sync`; the clone shares the
        // same epoch counter the call path observes.
        let engine = engine.clone();
        let handle = std::thread::Builder::new()
            .name("capsule-epoch-ticker".to_string())
            .spawn(move || {
                while !stop_for_thread.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_TICK_INTERVAL);
                    engine.increment_epoch();
                }
            })
            .ok();
        if handle.is_none() {
            // Fail loud (not closed-but-silent): if the OS refuses the
            // thread, the compute-DoS bound is NOT in effect. Operators
            // must see this rather than discover an inert deadline later.
            eprintln!(
                "[citrate-agent-core] WARNING: failed to spawn capsule epoch ticker; \
                 per-call compute-time bound (AGENT_RUNTIME-002) is INACTIVE"
            );
        }
        Self { stop, handle }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // Joins within one tick interval; bounded and cheap.
            let _ = handle.join();
        }
    }
}

// prior-001 (SECREM-02): the former `capsule_body_verified` / `is_placeholder_
// content_hash` helpers were REMOVED. They recomputed a content_hash over a body
// whose inputs (wasm + the declared hash) are fully controlled by whoever wrote
// the loose dir, so they could never authorize execution — keeping them invited
// the integrity-downgrade reading the audit flagged. Loose-dir capsules are now
// unconditionally `unverified` and only the signed `.cps` path can run.

/// Pre-loaded fleet of capsules sharing one engine + one set of
/// production dispatchers + one approval gate. Build once at
/// startup; call `call_raw(name, ...)` per tool invocation.
pub struct CapsuleDispatch {
    engine: wasmtime::Engine,
    capsules: HashMap<String, Capsule>,
    /// Names of loose-dir capsules that FAILED integrity verification at load
    /// (placeholder or mismatched content_hash, and no signed `.cps`). `call_raw`
    /// refuses to instantiate these — fail-closed, with no override (CIT-AGENT-3e).
    unverified: HashSet<String>,
    eth_call_dispatcher: Option<Arc<dyn EthCallDispatcher>>,
    eth_send_dispatcher: Option<Arc<dyn EthSendDispatcher>>,
    approval_gate: Option<Arc<dyn ApprovalGate>>,
    // RM-E.2 / AGENT_RUNTIME-002: keeps the epoch ticker alive for the
    // dispatch's lifetime so the per-call `set_epoch_deadline` traps
    // runaway capsules. Dropped (stopping the thread) with the dispatch.
    _epoch_ticker: EpochTicker,
}

impl CapsuleDispatch {
    /// Scan `dir` for `<capsule-name>/{manifest.toml,capsule.wasm}`
    /// pairs and load each into the dispatch fleet. Subdirectories
    /// without both files are silently skipped (allows the
    /// directory to coexist with non-capsule scaffolding like the
    /// `wit/` and `gherkin/` companion dirs documented in
    /// planset 03).
    pub fn load_from_dir(
        dir: &Path,
        eth_call_dispatcher: Option<Arc<dyn EthCallDispatcher>>,
        eth_send_dispatcher: Option<Arc<dyn EthSendDispatcher>>,
        approval_gate: Option<Arc<dyn ApprovalGate>>,
    ) -> Result<Self, AgentError> {
        let engine = EngineFactory::build()?;
        // RM-E.2 / AGENT_RUNTIME-002: arm the background epoch ticker so the
        // per-call deadline in `call_raw` is no longer inert.
        let _epoch_ticker = EpochTicker::spawn(&engine);
        let mut capsules = HashMap::new();
        let mut unverified = HashSet::new();
        let registry = bundled_key::registry();
        let entries = std::fs::read_dir(dir)
            .map_err(|e| AgentError::Capsule(format!("read capsule dir {dir:?}: {e}")))?;
        for entry in entries {
            let entry = entry.map_err(|e| AgentError::Capsule(format!("read_dir entry: {e}")))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // CIT-AGENT-3e: prefer the signed `.cps` archive. It loads through the FULL
            // verified path — content_hash + ed25519 publisher signature under the
            // bundled-tier key + WIT/capability cross-check — with NO env override. A
            // present-but-invalid archive is a hard error, never a silent downgrade to
            // the loose-dir path (that would be an integrity-downgrade attack).
            let dir_name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let cps_path = path.join(format!("{dir_name}.cps"));
            if cps_path.exists() {
                let file = std::fs::File::open(&cps_path)
                    .map_err(|e| AgentError::Capsule(format!("open {cps_path:?}: {e}")))?;
                let capsule = Capsule::from_archive_verified(file, &registry)?;
                capsules.insert(capsule.manifest.capsule.name.clone(), capsule);
                continue;
            }
            // Loose-dir fallback (development only): manifest + wasm, NO signature.
            // prior-001 (CRITICAL, SECREM-02): a loose dir carries no publisher
            // signature, and the `content_hash` it declares is computed by — and
            // fully under the control of — whoever wrote the dir, so it can NEVER
            // authorize execution. Load the capsule for listing/introspection but
            // ALWAYS mark it unverified; `call_raw` refuses to instantiate an
            // unverified capsule, with no override. Only the signed `.cps` path
            // (above) produces a runnable capsule.
            let manifest_path = path.join("manifest.toml");
            let wasm_path = path.join("capsule.wasm");
            if !manifest_path.exists() || !wasm_path.exists() {
                continue;
            }
            let manifest_str = std::fs::read_to_string(&manifest_path)
                .map_err(|e| AgentError::Capsule(format!("read manifest: {e}")))?;
            let manifest = Manifest::parse(&manifest_str)?;
            let wasm = std::fs::read(&wasm_path)
                .map_err(|e| AgentError::Capsule(format!("read wasm: {e}")))?;
            unverified.insert(manifest.capsule.name.clone());
            let capsule = Capsule {
                manifest: manifest.clone(),
                archive: archive::ArchiveContents {
                    wasm,
                    ..Default::default()
                },
            };
            capsules.insert(manifest.capsule.name.clone(), capsule);
        }
        Ok(Self {
            engine,
            capsules,
            unverified,
            eth_call_dispatcher,
            eth_send_dispatcher,
            approval_gate,
            _epoch_ticker,
        })
    }

    /// Names of every loaded capsule, alphabetized. Used by the
    /// defense_prime-shell startup smoke ("the fleet has all 7 capsules
    /// I expect") + by the doctor pre-flight check.
    pub fn capsule_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.capsules.keys().cloned().collect();
        names.sort();
        names
    }

    /// Whether `capsule_name` is in the fleet.
    pub fn has(&self, capsule_name: &str) -> bool {
        self.capsules.contains_key(capsule_name)
    }

    /// Low-level invocation: instantiate the named capsule, look
    /// up `iface.func`, call with the given Vals, return the
    /// single result Val. The defense_prime-shell adapter does the JSON
    /// → Val + Val → chat-string translation per-tool.
    pub fn call_raw(
        &self,
        capsule_name: &str,
        iface_name: &str,
        func_name: &str,
        args: &[wasmtime::component::Val],
    ) -> Result<wasmtime::component::Val, AgentError> {
        let capsule = self
            .capsules
            .get(capsule_name)
            .ok_or_else(|| AgentError::Capsule(format!("capsule {capsule_name:?} not loaded")))?;

        // CIT-AGENT-3e (closes RM-A WP-AGENT_RUNTIME-2026-05-31-001): fail-closed
        // integrity gate with NO escape hatch. A loose-dir capsule that is not bound to
        // a valid manifest content_hash is refused outright. The shipped fleet now loads
        // through the verified `.cps` path (signed content_hash), so the interim
        // CITRATE_ALLOW_UNVERIFIED_CAPSULES opt-in has been REMOVED.
        if self.unverified.contains(capsule_name) {
            return Err(AgentError::Capsule(format!(
                "refusing to instantiate unverified capsule {capsule_name:?}: it is not bound to a \
                 valid manifest content_hash + publisher signature. Pack and sign it with \
                 cit-capsule-pack (CIT-AGENT-3e)."
            )));
        }

        let linker = capsule.prepare_linker(&self.engine)?.into_linker();
        let (mut store, instance) = capsule.instantiate_with_write_path(
            &self.engine,
            &linker,
            self.eth_call_dispatcher.clone(),
            self.eth_send_dispatcher.clone(),
            self.approval_gate.clone(),
        )?;
        // REM-12 (wasmtime 26 → 45): `Instance::get_export` now returns
        // `(ComponentItem, ComponentExportIndex)`. The second `get_export`
        // call (looking up a func within an iface) takes only the index,
        // not the tuple — so we pluck `.1` from the iface lookup before
        // passing it through. `Instance::get_func` likewise wants the
        // index alone now (the `InstanceExportLookup` trait is impl'd
        // for `ComponentExportIndex`, not the tuple).
        let iface = instance
            .get_export(&mut store, None, iface_name)
            .ok_or_else(|| {
                AgentError::Capsule(format!(
                    "capsule {capsule_name:?} missing interface {iface_name:?}"
                ))
            })?;
        let (_, iface_idx) = iface;
        let func_export = instance
            .get_export(&mut store, Some(&iface_idx), func_name)
            .ok_or_else(|| {
                AgentError::Capsule(format!(
                    "capsule {capsule_name:?} interface {iface_name:?} missing func {func_name:?}"
                ))
            })?;
        let (_, func_idx) = func_export;
        let func = instance.get_func(&mut store, func_idx).ok_or_else(|| {
            AgentError::Capsule(format!(
                "capsule {capsule_name:?} func {func_name:?} resolve failed"
            ))
        })?;

        // REM-12b (2026-05-20): arm the per-call epoch deadline.
        // EngineFactory::build set Config::epoch_interruption(true)
        // (REM-12a); this is the per-call deadline. After N epoch
        // ticks the call traps (caller sees Err). The background
        // ticker that advances the engine's epoch counter must be
        // wired separately (TODO: spawn a tokio task per Dispatch
        // that ticks the engine.increment_epoch() every 50ms).
        // Until the ticker is wired this deadline is inert; the
        // deadline is set here so wiring the ticker is a one-line
        // change. See REM-12a in 06_REMEDIATION_PLAN.md.
        store.set_epoch_deadline(/* ticks */ 600); // 600 * 50ms = 30s budget when ticker is on

        // REM-12b CLOSED (2026-05-23, wasmtime-45 bump): bound capsule
        // resource appetite per call. The previous (wasmtime-26)
        // OnceLock<StoreLimits> placeholder returned a `&StoreLimits`
        // where the `Store::limiter` API expects `&mut dyn
        // ResourceLimiter`; that was a documented "doc-only intent"
        // gap waiting for the wasmtime bump.
        //
        // The bump lands the real binding by hoisting StoreLimits to
        // a `HostCtx::store_limits` field. The limiter closure now
        // returns `&mut state.store_limits` where `state: &mut HostCtx`
        // is the closure's per-call argument — which lives as long as
        // the Store and is independently borrow-checkable. This is the
        // canonical wasmtime pattern (see wasmtime::Store::limiter
        // docs).
        //
        // Numbers chosen conservatively for the current capsule set
        // (largest in-tree capsule ~16 MiB heap, single table, single
        // instance per call). Revisit when capsule diversity grows.
        // AR-B-004: 64 MiB heap is the DoS-relevant cap; the structural caps
        // are generous headroom for legitimate component-model capsules (a
        // single core module already needs 2 instances). Kept in sync with
        // `HostCtx::empty` so `instantiate_*` (which arms the limiter from
        // `store_limits`) and `call_raw` agree.
        store.data_mut().store_limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(64 * 1024 * 1024) // 64 MiB hard cap (per memory)
            .tables(100)
            .table_elements(1_000_000)
            .instances(1_000)
            .build();
        store.limiter(|state| &mut state.store_limits);

        let mut results = [wasmtime::component::Val::Bool(false)];

        // REM-12c (2026-05-20): catch_unwind around func.call.
        // F-04 RUSTSEC-2026-0085 + 2026-0092 panic during host-side
        // lift / transcode. Without catch_unwind, the panic propagates
        // through the dispatcher and aborts the entire agent-runtime
        // process. Wrapping degrades it to a per-call AgentError so
        // a single hostile capsule cannot kill the runtime. See
        // F-04_FP_CHECK.md §8 and REM-12c.
        //
        // NOTE: this catches host-Rust panics. WASM-level traps come
        // back as Err from func.call (already handled below) and
        // don't unwind, so catch_unwind is a no-op for them.
        let call_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            func.call(&mut store, args, &mut results)
        }));
        match call_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(AgentError::Capsule(format!("capsule call: {e}"))),
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".to_string());
                return Err(AgentError::Capsule(format!(
                    "capsule call panicked (host-side lift/transcode panic; \
                     see RUSTSEC-2026-0085, 2026-0092 and F-04 in the audit): {msg}"
                )));
            }
        }
        // REM-12 (wasmtime 26 → 45): `Func::post_return` is now a
        // documented no-op (per the v45 deprecation notice on the
        // method: "no longer needs to be called; this function has
        // no effect"). The component-model runtime handles the
        // post-return state internally. Removing the call eliminates
        // the deprecation warning without behavior change.
        Ok(std::mem::replace(
            &mut results[0],
            wasmtime::component::Val::Bool(false),
        ))
    }

    /// Invoke a capsule from JSON — the Hermes-sidecar (agent-sidecar) entry point (ADR-001,
    /// Option A). The caller passes only the capsule name + a JSON object of args; this discovers the
    /// capsule's single exported interface + function and its param types **from the component itself**
    /// (the WIT is the type source of truth — no hand-maintained schema to drift), maps the JSON args
    /// to typed `Val`s in signature order, calls through the vetted [`Self::call_raw`] (so the
    /// integrity gate, resource limits, epoch deadline, panic guard, and the **ApprovalGate** all
    /// apply — every chain effect still surfaces for human approval), and maps the result back to
    /// JSON. Fail-closed: a missing arg, a type this mapper does not cover, or a capsule that does not
    /// export exactly one interface-function is a typed error, never a wrong call.
    pub fn call_json(
        &self,
        capsule_name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, AgentError> {
        let capsule = self
            .capsules
            .get(capsule_name)
            .ok_or_else(|| AgentError::Capsule(format!("capsule {capsule_name:?} not loaded")))?;
        // AR-B-008: refuse an unverified capsule BEFORE any of its bytes reach
        // `Component::from_binary` (full Cranelift compilation — the largest
        // untrusted-parsing surface in the crate). RFC §4.5 requires manifest
        // signature verification to succeed before WASM parsing begins. The gate
        // in `call_raw` runs too late: `discover_single_entry` below already
        // compiled the component. Mirror the `call_raw` gate here at the top.
        if self.unverified.contains(capsule_name) {
            return Err(AgentError::Capsule(format!(
                "refusing to instantiate unverified capsule {capsule_name:?}: it is not bound to a \
                 valid manifest content_hash + publisher signature. Pack and sign it with \
                 cit-capsule-pack (CIT-AGENT-3e)."
            )));
        }
        // Discover the single (interface, function, params) from the component's own type.
        let component =
            wasmtime::component::Component::from_binary(&self.engine, &capsule.archive.wasm)
                .map_err(|e| AgentError::Capsule(format!("component parse: {e}")))?;
        let (iface, func, params) = discover_single_entry(&self.engine, &component, capsule_name)?;
        // Map JSON (an object keyed by the WIT param names) to Vals in signature order.
        let obj = args.as_object().ok_or_else(|| {
            AgentError::Capsule(format!("args for {capsule_name} must be a JSON object"))
        })?;
        let mut vals = Vec::with_capacity(params.len());
        for (name, ty) in &params {
            let v = obj.get(name).ok_or_else(|| {
                AgentError::Capsule(format!("missing arg {name:?} for {capsule_name}"))
            })?;
            vals.push(json_to_val(ty, v, name)?);
        }
        // Reuse the vetted call path (integrity gate + limits + epoch + panic guard + ApprovalGate).
        let result = self.call_raw(capsule_name, &iface, &func, &vals)?;
        Ok(val_to_json(&result))
    }

    /// Inspection accessor for the host context history (audit +
    /// tests). Note: each call to `call_raw` creates a fresh store,
    /// so the history is per-invocation; the defense_prime-shell adapter
    /// should drain the history via the linker's post-call inspection
    /// if it wants to retain it.
    pub fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }
}

// ── call_json helpers (ADR-001, Option A) — WIT is the type source of truth ──────────────────────

/// Discover a capsule's single exported interface + function + typed params from the component type.
/// Skills export exactly one interface with one function (verified across the catalog); if a capsule
/// exports none, that is a fail-closed error (never guess a call).
#[allow(clippy::type_complexity)]
fn discover_single_entry(
    engine: &wasmtime::Engine,
    component: &wasmtime::component::Component,
    capsule_name: &str,
) -> Result<
    (
        String,
        String,
        Vec<(String, wasmtime::component::types::Type)>,
    ),
    AgentError,
> {
    use wasmtime::component::types::ComponentItem;
    // wasmtime 46: `exports()` now yields `ComponentExtern` values whose
    // component-type is on the `.ty` field (previously the iterator
    // yielded `ComponentItem` directly).
    for (iface_name, item) in component.component_type().exports(engine) {
        if let ComponentItem::ComponentInstance(inst) = item.ty {
            for (func_name, fitem) in inst.exports(engine) {
                if let ComponentItem::ComponentFunc(cf) = fitem.ty {
                    let params = cf.params().map(|(n, t)| (n.to_string(), t)).collect();
                    return Ok((iface_name.to_string(), func_name.to_string(), params));
                }
            }
        }
    }
    Err(AgentError::Capsule(format!(
        "capsule {capsule_name:?} exports no interface function — call_json needs one exported \
         interface with a function"
    )))
}

/// Map one JSON value to a typed `Val` by the WIT param type. Fail-closed: a shape mismatch or a
/// type this mapper does not cover is an error, never a coerced/wrong value. Covers the types the
/// skill catalog uses (string / bool / u8 / u16 / u32 / u64 / `list<u8>` as a hex string or byte array).
fn json_to_val(
    ty: &wasmtime::component::types::Type,
    v: &serde_json::Value,
    name: &str,
) -> Result<wasmtime::component::Val, AgentError> {
    use wasmtime::component::types::Type;
    use wasmtime::component::Val;
    let err = |want: &str| AgentError::Capsule(format!("arg {name:?}: expected {want}"));
    match ty {
        Type::String => v
            .as_str()
            .map(|s| Val::String(s.to_string()))
            .ok_or_else(|| err("string")),
        Type::Bool => v.as_bool().map(Val::Bool).ok_or_else(|| err("bool")),
        Type::U8 => v
            .as_u64()
            .map(|n| Val::U8(n as u8))
            .ok_or_else(|| err("u8")),
        Type::U16 => v
            .as_u64()
            .map(|n| Val::U16(n as u16))
            .ok_or_else(|| err("u16")),
        Type::U32 => v
            .as_u64()
            .map(|n| Val::U32(n as u32))
            .ok_or_else(|| err("u32")),
        Type::U64 => v.as_u64().map(Val::U64).ok_or_else(|| err("u64")),
        Type::List(list) if matches!(list.ty(), Type::U8) => {
            let bytes: Vec<u8> = if let Some(s) = v.as_str() {
                hex::decode(s.trim_start_matches("0x")).map_err(|_| err("hex byte string"))?
            } else if let Some(arr) = v.as_array() {
                arr.iter()
                    .map(|n| n.as_u64().map(|x| x as u8).ok_or_else(|| err("byte array")))
                    .collect::<Result<Vec<u8>, _>>()?
            } else {
                return Err(err("hex string or byte array"));
            };
            Ok(Val::List(bytes.into_iter().map(Val::U8).collect()))
        }
        other => Err(AgentError::Capsule(format!(
            "arg {name:?}: WIT type {other:?} not supported by call_json (skills use \
             string/bool/uN/list<u8>)"
        ))),
    }
}

/// Map a `Val` result back to JSON. `list<u8>` → a `0x` hex string; `result<_, e>` → `{ok}`/`{err}`;
/// records → objects. Unmapped variants degrade to their debug string rather than failing (the
/// result is informational to the caller; the effect already happened through the gate).
fn val_to_json(v: &wasmtime::component::Val) -> serde_json::Value {
    use serde_json::Value;
    use wasmtime::component::Val;
    match v {
        Val::Bool(b) => Value::from(*b),
        Val::S8(n) => Value::from(*n),
        Val::U8(n) => Value::from(*n),
        Val::S16(n) => Value::from(*n),
        Val::U16(n) => Value::from(*n),
        Val::S32(n) => Value::from(*n),
        Val::U32(n) => Value::from(*n),
        Val::S64(n) => Value::from(*n),
        Val::U64(n) => Value::from(*n),
        Val::Float32(f) => Value::from(*f),
        Val::Float64(f) => Value::from(*f),
        Val::Char(c) => Value::from(c.to_string()),
        Val::String(s) => Value::from(s.clone()),
        Val::List(items) => {
            if !items.is_empty() && items.iter().all(|x| matches!(x, Val::U8(_))) {
                let bytes: Vec<u8> = items
                    .iter()
                    .filter_map(|x| if let Val::U8(b) = x { Some(*b) } else { None })
                    .collect();
                Value::from(format!("0x{}", hex::encode(bytes)))
            } else {
                Value::Array(items.iter().map(val_to_json).collect())
            }
        }
        Val::Record(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), val_to_json(v)))
                .collect(),
        ),
        Val::Tuple(items) => Value::Array(items.iter().map(val_to_json).collect()),
        Val::Result(r) => match r {
            Ok(inner) => {
                serde_json::json!({ "ok": inner.as_deref().map(val_to_json).unwrap_or(Value::Null) })
            }
            Err(inner) => {
                serde_json::json!({ "err": inner.as_deref().map(val_to_json).unwrap_or(Value::Null) })
            }
        },
        Val::Option(o) => o.as_deref().map(val_to_json).unwrap_or(Value::Null),
        Val::Enum(name) => Value::from(name.clone()),
        Val::Flags(flags) => Value::from(flags.clone()),
        Val::Variant(name, payload) => serde_json::json!({
            "variant": name,
            "value": payload.as_deref().map(val_to_json).unwrap_or(Value::Null),
        }),
        other => Value::from(format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn capsules_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
    }

    /// RM-E.2 / AGENT_RUNTIME-002 tripwire: a CapsuleDispatch built via the
    /// production constructor MUST have a live background epoch ticker, so
    /// the per-call `set_epoch_deadline(600)` armed in `call_raw` actually
    /// traps a runaway guest. We prove the mechanism on the dispatch's OWN
    /// engine: a `(loop (br 0))` module with a tiny deadline must trap within
    /// a few ticker intervals. Pre-fix (deadline armed but no ticker) the
    /// call never returns and this test fails on the 5s timeout.
    #[test]
    fn tripwire_002_dispatch_epoch_ticker_bounds_busy_loop() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dispatch = CapsuleDispatch::load_from_dir(&capsules_root(), None, None, None)
            .expect("dispatch loads");
        let engine = dispatch.engine().clone();

        let wasm = wat::parse_str(r#"(module (func (export "spin") (loop (br 0))))"#)
            .expect("wat compiles");
        let module = wasmtime::Module::new(&engine, &wasm).expect("module builds");

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut store = wasmtime::Store::new(&engine, ());
            // Tiny deadline — a couple of ticker intervals (~100ms at 50ms/tick).
            store.set_epoch_deadline(2);
            let instance = match wasmtime::Instance::new(&mut store, &module, &[]) {
                Ok(i) => i,
                Err(e) => {
                    let _ = tx.send(Err(format!("instantiate: {e}")));
                    return;
                }
            };
            let spin = instance
                .get_typed_func::<(), ()>(&mut store, "spin")
                .expect("typed func");
            let _ = tx.send(Ok(spin.call(&mut store, ()).is_err()));
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(true)) => {} // trapped — the dispatch's ticker advanced the epoch
            Ok(Ok(false)) => panic!("busy loop returned Ok — epoch deadline never tripped"),
            Ok(Err(e)) => panic!("tripwire setup failed: {e}"),
            Err(_) => panic!(
                "busy loop never returned within 5s — epoch ticker not wired (AGENT_RUNTIME-002)"
            ),
        }
    }

    /// Loading the full BFR-INT-12 fleet from disk: all 7 capsules
    /// present + correctly named.
    #[test]
    fn load_full_fleet() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsules_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules");
        let dispatch = CapsuleDispatch::load_from_dir(&capsules_root, None, None, None)
            .expect("loads cleanly");
        let names = dispatch.capsule_names();
        // 7 BFR-INT-12 tool capsules + 3 supporting/test capsules
        // (hello, echo-chain, eth-sender-test). The fleet has at
        // LEAST the 7 BFR tools; the supporting ones come along
        // as siblings in the same dir.
        for expected in &[
            "list-compliance-posture",
            "query-decisions-by-tenant",
            "query-supplier-status",
            "verify-provenance-chain",
            "provision-user",
            "revoke-role",
            "anchor-session",
        ] {
            assert!(
                dispatch.has(expected),
                "fleet must include {expected}; loaded: {names:?}"
            );
        }
    }

    // ── RM-A WP-AGENT_RUNTIME-001 tripwires (red on the unfixed dispatch) ──

    const PLACEHOLDER_HASH: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn loose_dir_with_matching_hash_is_still_unverified() {
        // prior-001 (CRITICAL, SECREM-02): the old loose-dir path treated a
        // capsule whose declared content_hash matched its own (writer-supplied)
        // wasm as "verified" — i.e. it RAN UNSIGNED WASM. A loose dir carries no
        // publisher signature, so it must NEVER run, even with a self-consistent
        // hash. It is loaded (for listing) but always unverified + refused.
        let root = std::env::temp_dir().join(format!("cit-cap-matchhash-{}", std::process::id()));
        let cap = root.join("matchcap");
        std::fs::create_dir_all(&cap).expect("mkdir");
        let wasm = b"\x00asm\x01\x00\x00\x00".to_vec();
        // The attacker computes a content_hash that matches their own body.
        let real = archive::compute_content_hash(&archive::ArchiveContents {
            wasm: wasm.clone(),
            ..Default::default()
        });
        let manifest = format!(
            r#"[capsule]
name = "matchcap"
version = "0.1.0"
content_hash = "{real}"
[capability]
network = "none"
subagent_spawn = false
[data_class]
[risk]
tier = "low"
break_glass_eligible = false
[overlay]
[provenance]
publisher = "did:citrate:test"
build_reproducible = true
agentile_sprint = "cit-agent-3e"
[signing]
tier = "bundled"
"#
        );
        std::fs::write(cap.join("manifest.toml"), manifest).expect("write manifest");
        std::fs::write(cap.join("capsule.wasm"), &wasm).expect("write wasm");

        let dispatch = CapsuleDispatch::load_from_dir(&root, None, None, None).expect("loads");
        assert!(
            dispatch.unverified.contains("matchcap"),
            "a loose dir with a matching hash must STILL be unverified (no signature)"
        );
        assert!(
            dispatch.call_raw("matchcap", "iface", "func", &[]).is_err(),
            "an unverified loose-dir capsule must be refused fail-closed"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shipped_fleet_loads_verified_no_override() {
        // CIT-AGENT-3e: the in-tree fleet is now packed + signed (.cps), so it loads
        // through the verified path with an EMPTY unverified set and no env override.
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsules_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to repo root")
            .join("capsules");
        let dispatch = CapsuleDispatch::load_from_dir(&capsules_root, None, None, None)
            .expect("signed fleet loads cleanly");
        assert!(
            dispatch.unverified.is_empty(),
            "the signed .cps fleet must load fully verified; unverified: {:?}",
            dispatch.unverified
        );
        assert!(
            dispatch.has("hello"),
            "fleet loaded via the verified .cps path"
        );
    }

    #[test]
    fn unverified_loose_dir_capsule_refused_fail_closed() {
        // A loose-dir capsule with a placeholder hash and NO signed .cps is refused
        // with no escape hatch (the CITRATE_ALLOW_UNVERIFIED_CAPSULES opt-in is gone).
        let root = std::env::temp_dir().join(format!("cit-cap-unverified-{}", std::process::id()));
        let cap = root.join("placeholdercap");
        std::fs::create_dir_all(&cap).expect("mkdir");
        let manifest = format!(
            r#"[capsule]
name = "placeholdercap"
version = "0.1.0"
content_hash = "{PLACEHOLDER_HASH}"
[capability]
network = "none"
subagent_spawn = false
[data_class]
[risk]
tier = "low"
break_glass_eligible = false
[overlay]
[provenance]
publisher = "did:citrate:test"
build_reproducible = true
agentile_sprint = "cit-agent-3e"
[signing]
tier = "bundled"
"#
        );
        std::fs::write(cap.join("manifest.toml"), manifest).expect("write manifest");
        std::fs::write(cap.join("capsule.wasm"), b"\x00asm\x01\x00\x00\x00").expect("write wasm");

        let dispatch = CapsuleDispatch::load_from_dir(&root, None, None, None).expect("loads");
        assert!(
            dispatch.unverified.contains("placeholdercap"),
            "placeholder loose-dir capsule must be flagged unverified"
        );
        let err = dispatch
            .call_raw("placeholdercap", "iface", "func", &[])
            .expect_err("unverified capsule must be refused, fail-closed");
        assert!(
            err.to_string().to_lowercase().contains("unverified"),
            "refusal must cite the missing integrity proof, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn call_json_refuses_unverified_before_wasm_parse() {
        // AR-B-008: `call_json` must reject an unverified loose-dir capsule at
        // the TOP — before its bytes reach `Component::from_binary` (Cranelift
        // compilation). Pre-fix, `call_json` compiled the component first, so an
        // unverified capsule with parseable-looking bytes reached the largest
        // untrusted-parsing surface in the crate; the error surfaced as
        // "component parse", not "unverified".
        let root = std::env::temp_dir().join(format!("cit-cap-cj-unverified-{}", std::process::id()));
        let cap = root.join("placeholdercap");
        std::fs::create_dir_all(&cap).expect("mkdir");
        let manifest = format!(
            r#"[capsule]
name = "placeholdercap"
version = "0.1.0"
content_hash = "{PLACEHOLDER_HASH}"
[capability]
network = "none"
subagent_spawn = false
[data_class]
[risk]
tier = "low"
break_glass_eligible = false
[overlay]
[provenance]
publisher = "did:citrate:test"
build_reproducible = true
agentile_sprint = "cit-agent-3e"
[signing]
tier = "bundled"
"#
        );
        std::fs::write(cap.join("manifest.toml"), manifest).expect("write manifest");
        std::fs::write(cap.join("capsule.wasm"), b"\x00asm\x01\x00\x00\x00").expect("write wasm");

        let dispatch = CapsuleDispatch::load_from_dir(&root, None, None, None).expect("loads");
        assert!(dispatch.unverified.contains("placeholdercap"));
        let err = dispatch
            .call_json("placeholdercap", &serde_json::json!({}))
            .expect_err("call_json on an unverified capsule must be refused");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unverified"),
            "must fail the integrity gate, not the wasm parser; got: {err}"
        );
        assert!(
            !msg.contains("component parse"),
            "unverified bytes must NOT reach Component::from_binary; got: {err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── call_json mapping (ADR-001, Option A) ──────────────────────────────────────────────

    #[test]
    fn json_to_val_maps_scalars_and_fails_closed_on_mismatch() {
        use wasmtime::component::types::Type;
        use wasmtime::component::Val;
        assert!(
            matches!(json_to_val(&Type::String, &serde_json::json!("hi"), "a"), Ok(Val::String(s)) if s == "hi")
        );
        assert!(matches!(
            json_to_val(&Type::Bool, &serde_json::json!(true), "a"),
            Ok(Val::Bool(true))
        ));
        assert!(matches!(
            json_to_val(&Type::U8, &serde_json::json!(7), "a"),
            Ok(Val::U8(7))
        ));
        assert!(matches!(
            json_to_val(&Type::U32, &serde_json::json!(9000), "a"),
            Ok(Val::U32(9000))
        ));
        assert!(matches!(
            json_to_val(&Type::U64, &serde_json::json!(1u64 << 40), "a"),
            Ok(Val::U64(_))
        ));
        // fail-closed: wrong JSON shape for the declared type is an error, never a coerced value.
        assert!(json_to_val(&Type::U8, &serde_json::json!("not-a-number"), "a").is_err());
        assert!(json_to_val(&Type::String, &serde_json::json!(5), "a").is_err());
    }

    #[test]
    fn val_to_json_maps_bytes_to_hex_and_result_records() {
        use wasmtime::component::Val;
        // list<u8> → 0x hex
        let bytes = Val::List(vec![Val::U8(0xde), Val::U8(0xad)]);
        assert_eq!(val_to_json(&bytes), serde_json::json!("0xdead"));
        // result<record, string> Ok
        let rec = Val::Record(vec![
            ("posture".into(), Val::U8(3)),
            ("expired".into(), Val::Bool(false)),
        ]);
        let ok = Val::Result(Ok(Some(Box::new(rec))));
        assert_eq!(
            val_to_json(&ok),
            serde_json::json!({ "ok": { "posture": 3, "expired": false } })
        );
        // result Err(string)
        let err = Val::Result(Err(Some(Box::new(Val::String("nope".into())))));
        assert_eq!(val_to_json(&err), serde_json::json!({ "err": "nope" }));
        // plain scalars
        assert_eq!(val_to_json(&Val::U64(42)), serde_json::json!(42));
        assert_eq!(
            val_to_json(&Val::String("x".into())),
            serde_json::json!("x")
        );
    }
}
