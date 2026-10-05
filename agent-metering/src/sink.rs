//! The EventSink adapter that derives metering records from the loop's event stream.

use crate::clock::Clock;
use crate::measures::{
    EnergyModel, Generation, ResourceSampler, SelfReview, TurnSampling, DEFAULT_ENERGY_MODEL,
};
use crate::record::{ToolTally, TurnOutcome, TurnRecord, VerifierOutcome};
use citrate_agent_loop::{Event, EventSink, TokenUsage};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

/// The bucket for tool names the session does not offer. A model can invent any name, including
/// one made of conversation text, so such names are never recorded verbatim.
pub const UNKNOWN_TOOL: &str = "(unknown tool)";

struct Open {
    rec: TurnRecord,
    started_mono: u64,
    /// call id -> tool bucket, so a `tool_result` lands on the right tally.
    calls: HashMap<String, String>,
    /// Model calls that reported usage so far in this turn (the first one sets the TTFT).
    model_calls: u32,
    /// D-27: the machine sampling running for this turn, if the host supplied a sampler.
    sampling: Option<Box<dyn TurnSampling>>,
}

#[derive(Default)]
struct State {
    open: Option<Open>,
    done: Vec<TurnRecord>,
    next_turn: u32,
}

/// Wraps a session's event sink: forwards every event unchanged and keeps one [`TurnRecord`] per
/// loop turn.
///
/// Turn boundaries come from the loop: a turn opens on its first event and closes on `done`.
/// `verifier` events are emitted by the workflow runner *after* the attempt's `done`, so they
/// attach to the turn that just closed (the attempt they judge).
///
/// Token counts are not in the event stream; the session's model client reports them through
/// [`MeteringSink::record_usage`]. Without that they stay `None` (unknown), never zero.
pub struct MeteringSink {
    session_id: String,
    model: String,
    known_tools: BTreeSet<String>,
    clock: Arc<dyn Clock>,
    inner: Option<Arc<dyn EventSink>>,
    sampler: Option<Arc<dyn ResourceSampler>>,
    energy: EnergyModel,
    state: Mutex<State>,
}

impl MeteringSink {
    /// `known_tools` are the registered tool names (anything else is pooled as [`UNKNOWN_TOOL`]).
    pub fn new(
        session_id: impl Into<String>,
        model: impl Into<String>,
        known_tools: impl IntoIterator<Item = String>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        MeteringSink {
            session_id: session_id.into(),
            model: model.into(),
            known_tools: known_tools.into_iter().collect(),
            clock,
            inner: None,
            sampler: None,
            energy: DEFAULT_ENERGY_MODEL,
            state: Mutex::new(State {
                next_turn: 1,
                ..State::default()
            }),
        }
    }

    /// Forward every event to `inner` after metering it (builder).
    pub fn forwarding_to(mut self, inner: Arc<dyn EventSink>) -> Self {
        self.inner = Some(inner);
        self
    }

    /// D-27: sample the machine while each turn runs (builder). Without a sampler, resource peaks
    /// and the energy estimate stay unknown.
    pub fn sampling_with(mut self, sampler: Arc<dyn ResourceSampler>) -> Self {
        self.sampler = Some(sampler);
        self
    }

    /// D-27: the nominal watts behind the energy estimate (builder; default
    /// [`DEFAULT_ENERGY_MODEL`]).
    pub fn with_energy_model(mut self, model: EnergyModel) -> Self {
        self.energy = model;
        self
    }

    // Metering is observational, not a gate: a poisoned lock keeps the data it has.
    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn bucket(&self, name: &str) -> String {
        if self.known_tools.contains(name) {
            name.to_string()
        } else {
            UNKNOWN_TOOL.to_string()
        }
    }

    fn open_turn(&self, st: &mut State) {
        if st.open.is_none() {
            let turn = st.next_turn;
            st.next_turn = st.next_turn.saturating_add(1);
            st.open = Some(Open {
                rec: TurnRecord::new(&self.session_id, turn, &self.model, self.clock.unix_ms()),
                started_mono: self.clock.monotonic_ms(),
                calls: HashMap::new(),
                model_calls: 0,
                sampling: self.sampler.as_ref().map(|s| s.begin()),
            });
        }
    }

    /// Add one model call's usage to the open turn. Returns false (and records nothing) when no
    /// turn is open, so usage is never attributed to the wrong turn.
    pub fn record_usage(&self, tokens_in: u64, tokens_out: u64) -> bool {
        self.record_model_call(&TokenUsage {
            prompt_tokens: tokens_in,
            completion_tokens: tokens_out,
            generation_ms: None,
            prompt_ms: None,
        })
    }

    /// Add one model call's report to the open turn: its tokens, and (D-27) the server's timings.
    /// The turn's time to first token is its **first** call's `prompt_ms`; a first call without one
    /// leaves it unknown (a later call's is not substituted). Generation time and the completion
    /// tokens it covers are summed over the calls that reported one. Returns false (and records
    /// nothing) when no turn is open.
    pub fn record_model_call(&self, usage: &TokenUsage) -> bool {
        let mut st = self.lock();
        match st.open.as_mut() {
            Some(o) => {
                o.model_calls = o.model_calls.saturating_add(1);
                let r = &mut o.rec;
                r.tokens_in = Some(r.tokens_in.unwrap_or(0).saturating_add(usage.prompt_tokens));
                r.tokens_out = Some(
                    r.tokens_out
                        .unwrap_or(0)
                        .saturating_add(usage.completion_tokens),
                );
                if o.model_calls == 1 {
                    r.ttft_ms = usage.prompt_ms;
                }
                if let Some(ms) = usage.generation_ms {
                    let g = r.generation.get_or_insert(Generation { tokens: 0, ms: 0 });
                    g.tokens = g.tokens.saturating_add(usage.completion_tokens);
                    g.ms = g.ms.saturating_add(ms);
                }
                true
            }
            None => false,
        }
    }

    /// Completed turns so far.
    pub fn records(&self) -> Vec<TurnRecord> {
        self.lock().done.clone()
    }

    /// Completed turns so far, removing them. Drain after a workflow returns: verifier verdicts
    /// for the last attempt arrive after its `done`.
    pub fn take_records(&self) -> Vec<TurnRecord> {
        std::mem::take(&mut self.lock().done)
    }

    fn observe(&self, ev: &Event) {
        let mut st = self.lock();
        if let Event::Verifier {
            step, name, passed, ..
        } = ev
        {
            let v = VerifierOutcome {
                step: step.clone(),
                name: name.clone(),
                passed: *passed,
            };
            if let Some(o) = st.open.as_mut() {
                o.rec.verifiers.push(v);
            } else if let Some(last) = st.done.last_mut() {
                last.verifiers.push(v);
            }
            return;
        }
        // US-1.3 AC2: the model's self-review is an opinion recorded in the session's event log.
        // It arrives after the attempt's `done` and decides nothing, so it must not open a turn of
        // its own. D-27: its PASS/FAIL claim (never its text) is kept on the attempt it reviews,
        // labelled "opinion".
        if let Event::SelfReview { text, .. } = ev {
            let review = SelfReview::from_text(text);
            if let Some(o) = st.open.as_mut() {
                o.rec.self_review = Some(review);
            } else if let Some(last) = st.done.last_mut() {
                last.self_review = Some(review);
            }
            return;
        }
        // A workflow's plan is bookkeeping emitted before its first attempt. It opens no turn: a
        // run stopped before that attempt (or with no steps) would otherwise leave a turn open,
        // with its sampling running, and the next turn would inherit its start time.
        if let Event::Plan { .. } = ev {
            return;
        }
        self.open_turn(&mut st);
        let now_mono = self.clock.monotonic_ms();
        let Some(o) = st.open.as_mut() else {
            return;
        };
        match ev {
            Event::StepStart { step } => o.rec.steps = o.rec.steps.max(*step),
            Event::ToolCall { call, hic, .. } => {
                let bucket = self.bucket(&call.name);
                let t = o.rec.tool_calls.entry(bucket.clone()).or_default();
                t.calls = t.calls.saturating_add(1);
                if hic.is_some() {
                    t.hic_required = t.hic_required.saturating_add(1);
                }
                o.calls.insert(call.id.clone(), bucket);
            }
            Event::ToolResult {
                call_id, status, ..
            } => {
                let bucket = o
                    .calls
                    .get(call_id)
                    .cloned()
                    .unwrap_or_else(|| UNKNOWN_TOOL.to_string());
                let t: &mut ToolTally = o.rec.tool_calls.entry(bucket).or_default();
                match *status {
                    "ok" => t.ok = t.ok.saturating_add(1),
                    "denied" => t.denied = t.denied.saturating_add(1),
                    _ => t.error = t.error.saturating_add(1),
                }
            }
            Event::Tainted { .. } => o.rec.tainted = true,
            Event::Done { outcome } => {
                o.rec.outcome = TurnOutcome::from_label(outcome);
                o.rec.latency_ms = now_mono.saturating_sub(o.started_mono);
                if let Some(mut o) = st.open.take() {
                    if let Some(peaks) = o.sampling.take().and_then(|s| s.finish()) {
                        o.rec.energy_estimate =
                            Some(self.energy.estimate(&peaks, o.rec.latency_ms));
                        o.rec.resources = Some(peaks);
                    }
                    st.done.push(o.rec);
                }
            }
            // Content-bearing or boundary-only events: nothing to count.
            Event::StepEnd { .. }
            | Event::AssistantDelta { .. }
            | Event::Final { .. }
            | Event::Error { .. } => {}
            Event::Verifier { .. } | Event::SelfReview { .. } | Event::Plan { .. } => {}
            // Usage reaches the record through the metered client (`record_usage`). Counting it
            // here would double it.
            Event::Usage { .. } => {}
        }
    }
}

impl EventSink for MeteringSink {
    fn emit(&self, ev: Event) {
        self.observe(&ev);
        if let Some(inner) = &self.inner {
            inner.emit(ev);
        }
    }
}
