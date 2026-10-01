---------------------------- MODULE TaintDowngrade ----------------------------
(***************************************************************************)
(* HUP-S2.7 — taint tracking and the HIC downgrade, at the level of        *)
(* citrate-agent-loop `run_turn_with` (one tool call per step of the        *)
(* model) and `TaintState`. Refines the abstract `TaintDowngrade` of        *)
(* citrate-core src-tauri/formal/AgentLoop.tla with the real annotations:  *)
(*                                                                          *)
(*   effect  in {none, write, spend, sign, unknown}  (unknown = effectful)  *)
(*   trust   in {trusted, untrusted, unknown}        (unknown = untrusted)  *)
(*   host honors explicit approval?  (sidecar: CoreHost iff hicAware)       *)
(*   outcome in {ok, untrusted, error, denied}                              *)
(*   loopErr: unknown tool / bad JSON / over cap / no host (nothing runs)   *)
(*                                                                          *)
(* A call takes one of four paths:                                          *)
(*   "ordinary"  host's normal gates (which may auto-approve / use budgets) *)
(*   "explicit"  host asks a person; no automatic path                      *)
(*   "refused"   the loop declines; the host never sees it                  *)
(*   "none"      a loop-generated error; nothing runs                       *)
(*                                                                          *)
(* Properties:                                                              *)
(*   NoUnapprovedEffectAfterTaint  no effectful call takes the ordinary     *)
(*                                 path while the session is tainted        *)
(*   TaintedEffectNeedsHIC         a tainted effectful call is explicit or  *)
(*                                 refused (never ordinary)                 *)
(*   UntaintedUnchanged            an untainted call that runs at all takes *)
(*                                 the ordinary path (behaviour unchanged)  *)
(*   TaintSound                    untrusted content ingested since the     *)
(*                                 last member clear ⇒ tainted              *)
(*   TaintMonotone (action)        taint only ever goes away by MemberClear *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS MaxCalls, MaxClears

Effects   == {"none", "write", "spend", "sign", "unknown"}
Trusts    == {"trusted", "untrusted", "unknown"}
Outcomes  == {"ok", "untrusted", "error", "denied"}
Paths     == {"ordinary", "explicit", "refused", "none", "-"}

VARIABLES
    tainted,          \* BOOLEAN — TaintState::is_tainted
    ingested,         \* BOOLEAN — untrusted content ingested since the last member clear
    calls,            \* tool calls so far
    clears,           \* member clears so far
    unapproved,       \* effectful calls on the ordinary path while tainted (must stay 0)
    lastPath,         \* path of the most recent call ("-" before any)
    lastEffectful,    \* was the most recent call effectful?
    lastTaintedBefore,\* was the session tainted when it was proposed?
    lastLoopErr,      \* was it a loop-generated error?
    lastAct           \* "init" | "call" | "clear"

vars == <<tainted, ingested, calls, clears, unapproved, lastPath, lastEffectful,
          lastTaintedBefore, lastLoopErr, lastAct>>

TypeOK ==
    /\ tainted \in BOOLEAN /\ ingested \in BOOLEAN
    /\ calls \in 0..MaxCalls /\ clears \in 0..MaxClears
    /\ unapproved \in Nat
    /\ lastPath \in Paths
    /\ lastEffectful \in BOOLEAN /\ lastTaintedBefore \in BOOLEAN /\ lastLoopErr \in BOOLEAN
    /\ lastAct \in {"init", "call", "clear"}

Init ==
    /\ tainted = FALSE /\ ingested = FALSE
    /\ calls = 0 /\ clears = 0 /\ unapproved = 0
    /\ lastPath = "-" /\ lastEffectful = FALSE /\ lastTaintedBefore = FALSE
    /\ lastLoopErr = FALSE /\ lastAct = "init"

\* ---- ground truth (what the properties are stated in) ----
\* Only a tool explicitly annotated `effect: none` is known not to change anything.
MayChangeState(e) == e # "none"
\* Content that ran and came back is outside content unless the tool is known-trusted, or the host
\* flagged this one result untrusted. A declined call brought nothing in.
CarriesOutsideContent(t, o, ran) ==
    ran /\ o # "denied" /\ (o = "untrusted" \/ t # "trusted")

\* ---- the implementation (what the code does; mutations target these) ----
\* ToolAnnotations::is_effectful / output_untrusted — the safe side for unknowns.
IsEffectful(e)    == e # "none"
OutputUntrusted(t) == t # "trusted"

\* run_turn_with: hic_reason is Some iff the call is effectful and the session is tainted.
NeedsHIC(e) == IsEffectful(e) /\ tainted

PathOf(e, honors, loopErr) ==
    IF loopErr THEN "none"
    ELSE IF NeedsHIC(e) /\ ~honors THEN "refused"
    ELSE IF NeedsHIC(e) THEN "explicit"
    ELSE "ordinary"

ToolCall ==
    /\ calls < MaxCalls
    /\ \E e \in Effects, t \in Trusts, honors \in BOOLEAN, out \in Outcomes, loopErr \in BOOLEAN :
        LET path == PathOf(e, honors, loopErr)
            ran  == path \in {"ordinary", "explicit"}
            \* only a host that ran can return anything; a refused/loop-error call is "denied"/"error"
            o    == IF ran THEN out ELSE IF path = "refused" THEN "denied" ELSE "error"
            ingest == ran /\ (o = "untrusted" \/ (o \in {"ok", "error"} /\ OutputUntrusted(t)))
        IN
        /\ unapproved' = IF path = "ordinary" /\ MayChangeState(e) /\ tainted
                         THEN unapproved + 1 ELSE unapproved
        /\ tainted' = (tainted \/ ingest)
        /\ ingested' = (ingested \/ CarriesOutsideContent(t, o, ran))
        /\ lastPath' = path
        /\ lastEffectful' = MayChangeState(e)
        /\ lastTaintedBefore' = tainted
        /\ lastLoopErr' = loopErr
    /\ calls' = calls + 1
    /\ lastAct' = "call"
    /\ UNCHANGED clears

\* TaintState::clear_by_member — the only way out, and only with a member's MemberClear.
MemberClear ==
    /\ tainted /\ clears < MaxClears
    /\ tainted' = FALSE /\ ingested' = FALSE
    /\ clears' = clears + 1
    /\ lastAct' = "clear"
    /\ UNCHANGED <<calls, unapproved, lastPath, lastEffectful, lastTaintedBefore, lastLoopErr>>

Done == calls = MaxCalls /\ UNCHANGED vars

Next == ToolCall \/ MemberClear \/ Done

Spec == Init /\ [][Next]_vars

\* ---- properties ----
NoUnapprovedEffectAfterTaint == unapproved = 0

TaintedEffectNeedsHIC ==
    (lastAct = "call" /\ lastTaintedBefore /\ lastEffectful /\ ~lastLoopErr)
        => lastPath \in {"explicit", "refused"}

UntaintedUnchanged ==
    (lastAct = "call" /\ ~lastTaintedBefore /\ ~lastLoopErr) => lastPath = "ordinary"

TaintSound == ingested => tainted

TaintMonotone == [][(tainted /\ ~tainted') => (lastAct' = "clear" /\ clears' = clears + 1)]_vars
================================================================================
