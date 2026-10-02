------------------------- MODULE ContradictionResolve -------------------------
(***************************************************************************)
(* HUP-S3.4 (fan-out 5): the member resolves a contradiction between       *)
(* learned memories. Memories on one key that disagree are accepted as     *)
(* Belnap `both` (core's ledger marks every side). The member keeps one    *)
(* and retracts another: the sidecar records the HIC-1 decision first,     *)
(* then retracts; core applies the resolution to its ledger from the       *)
(* route's answer or, if that answer was lost, from the proposal list      *)
(* (a retracted proposal names the one that was kept). Any save of the     *)
(* proposals file can be lost, so on restart the file is reconciled with   *)
(* the decision log.                                                       *)
(*                                                                         *)
(* Rust counterparts:                                                      *)
(*   Accept       = Learner::accept + core Ledger::accept_record           *)
(*   ResolveGuard = Learner::resolve (both persisted, distinct)            *)
(*   Resolve      = record_decision, then the Retracted state              *)
(*   CoreApply    = core Ledger::apply_resolution (route answer or sync)   *)
(*   CoreSettle   = core Ledger::sync_with_sidecar (no contradiction left) *)
(*   Reconcile    = Learner::open -> reconcile_with_log                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Mems, MaxCrashes

None == "none"

VARIABLES
    up,        \* the sidecar is running
    mem,       \* learner state per memory: "none" | "persisted" | "again" | "retracted"
               \* ("again" = persist_failed: an accept recorded before a lost save, offered again)
    kept,      \* learner: for a retracted memory, the one kept instead (else None)
    fileMem,   \* the proposals file (may lag)
    fileKept,
    accepts,   \* the decision log's accept records (memories)
    resolves,  \* the decision log's resolve records: set of <<retracted, kept>>
    led,       \* core ledger Belnap value: "none" | "true" | "both" | "false"
    con,       \* core ledger: the memories each one contradicts
    everBoth,  \* ghost: memories that were ever `both` in the ledger
    crashes

vars == <<up, mem, kept, fileMem, fileKept, accepts, resolves, led, con, everBoth, crashes>>

Standing == {"persisted", "again"}

----------------------------------------------------------------------------
(* The implementation's guards and recovery. *)

ResolveGuard(k, d) == k # d /\ mem[k] = "persisted" /\ mem[d] = "persisted"

\* Core applies a resolution only once the sidecar shows it (route answer or list sync).
CoreGuard(d, k) == up /\ mem[d] = "retracted" /\ kept[d] = k /\ led[d] # "false"

RecordedFor(d) == {k \in Mems : <<d, k>> \in resolves}

\* A recorded resolution retracts whatever the file says (it needed a completed accept); a
\* recorded accept the file lost is offered again; otherwise the file stands.
Reconcile(m) ==
    IF RecordedFor(m) # {} THEN "retracted"
    ELSE IF fileMem[m] = "none" /\ m \in accepts THEN "again"
    ELSE fileMem[m]

ReconcileKept(m) ==
    IF RecordedFor(m) # {}
    THEN CHOOSE k \in RecordedFor(m) : TRUE
    ELSE fileKept[m]

----------------------------------------------------------------------------
Init ==
    /\ up = TRUE
    /\ mem = [m \in Mems |-> "none"]
    /\ kept = [m \in Mems |-> None]
    /\ fileMem = [m \in Mems |-> "none"]
    /\ fileKept = [m \in Mems |-> None]
    /\ accepts = {}
    /\ resolves = {}
    /\ led = [m \in Mems |-> "none"]
    /\ con = [m \in Mems |-> {}]
    /\ everBoth = {}
    /\ crashes = 0

\* The member accepts a memory (acknowledging every contradiction). Core's ledger marks it and
\* every standing memory it contradicts as `both`. A memory offered again after a lost save
\* ("again") counts as standing: its accept was recorded and core may already hold it.
Accept(m) ==
    /\ up /\ mem[m] = "none"
    /\ LET others == {o \in Mems : mem[o] \in Standing}
       IN /\ mem' = [mem EXCEPT ![m] = "persisted"]
          /\ led' = [o \in Mems |->
                        IF o = m THEN (IF others = {} THEN "true" ELSE "both")
                        ELSE IF o \in others THEN "both" ELSE led[o]]
          /\ con' = [o \in Mems |->
                        IF o = m THEN others
                        ELSE IF o \in others THEN con[o] \cup {m} ELSE con[o]]
          /\ everBoth' = everBoth \cup (IF others = {} THEN {} ELSE others \cup {m})
    /\ accepts' = accepts \cup {m}
    /\ UNCHANGED <<up, kept, fileMem, fileKept, resolves, crashes>>

\* Accepting again after a lost save: core keys records by proposal id, so its ledger is unchanged.
AcceptAgain(m) ==
    /\ up /\ mem[m] = "again"
    /\ mem' = [mem EXCEPT ![m] = "persisted"]
    /\ UNCHANGED <<up, kept, fileMem, fileKept, accepts, resolves, led, con, everBoth, crashes>>

\* The member keeps k and retracts d: recorded first, then the learner's state changes.
Resolve(k, d) ==
    /\ up /\ ResolveGuard(k, d)
    /\ resolves' = resolves \cup {<<d, k>>}
    /\ mem' = [mem EXCEPT ![d] = "retracted"]
    /\ kept' = [kept EXCEPT ![d] = k]
    /\ UNCHANGED <<up, fileMem, fileKept, accepts, led, con, everBoth, crashes>>

\* Core applies a resolution it can see. The retracted memory becomes `false` and every memory
\* that contradicted it drops it. Only the KEPT memory can become `true` again, and only when it
\* is still `both` with nothing left to contradict: another memory may itself be retracted by a
\* resolution core has not applied yet (its answer was lost), so it must not be promoted here.
CoreApply(d, k) ==
    /\ CoreGuard(d, k)
    /\ LET con2 == [o \in Mems |-> IF o = d THEN {} ELSE con[o] \ {d}]
       IN /\ con' = con2
          /\ led' = [o \in Mems |->
                        IF o = d THEN "false"
                        ELSE IF o = k /\ led[o] = "both" /\ con2[o] = {} THEN "true"
                        ELSE led[o]]
    /\ UNCHANGED <<up, mem, kept, fileMem, fileKept, accepts, resolves, everBoth, crashes>>

\* Core's sync (after a resolve, and whenever the panel loads) also settles a memory that is
\* still `both` with nothing left to contradict, but only one the sidecar shows standing.
SettleGuard(o) == up /\ led[o] = "both" /\ con[o] = {} /\ mem[o] \in Standing

CoreSettle(o) ==
    /\ SettleGuard(o)
    /\ led' = [led EXCEPT ![o] = "true"]
    /\ UNCHANGED <<up, mem, kept, fileMem, fileKept, accepts, resolves, con, everBoth, crashes>>

Save ==
    /\ up /\ (fileMem # mem \/ fileKept # kept)
    /\ fileMem' = mem /\ fileKept' = kept
    /\ UNCHANGED <<up, mem, kept, accepts, resolves, led, con, everBoth, crashes>>

Crash ==
    /\ up /\ crashes < MaxCrashes
    /\ up' = FALSE /\ crashes' = crashes + 1
    /\ UNCHANGED <<mem, kept, fileMem, fileKept, accepts, resolves, led, con, everBoth>>

Restart ==
    /\ ~up
    /\ mem' = [m \in Mems |-> Reconcile(m)]
    /\ kept' = [m \in Mems |-> ReconcileKept(m)]
    /\ up' = TRUE
    /\ UNCHANGED <<fileMem, fileKept, accepts, resolves, led, con, everBoth, crashes>>

Next ==
    \/ \E m \in Mems : Accept(m) \/ AcceptAgain(m) \/ CoreSettle(m)
    \/ \E k, d \in Mems : Resolve(k, d) \/ CoreApply(d, k)
    \/ Save \/ Crash \/ Restart

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Properties, over ground truth. *)

TypeOK ==
    /\ mem \in [Mems -> {"none", "persisted", "again", "retracted"}]
    /\ led \in [Mems -> {"none", "true", "both", "false"}]
    /\ resolves \subseteq (Mems \X Mems)

\* A retracted memory was retracted by a recorded member decision, naming what was kept.
RetractRecorded ==
    \A m \in Mems : mem[m] = "retracted" => <<m, kept[m]>> \in resolves

\* Resolving never leaves a key with nothing standing: at least one accepted memory stays.
OneStanding ==
    (up /\ \E m \in Mems : mem[m] # "none") => \E m \in Mems : mem[m] \in Standing

\* A recorded resolution is final: no restart or lost save brings the retracted memory back.
ResolveFinal ==
    up => \A d, k \in Mems : <<d, k>> \in resolves => mem[d] = "retracted"

\* Core never settles a contradiction on its own: `false` only after a recorded retraction,
\* and a memory that was `both` is `true` again only after a recorded resolution involving it.
NoSilentMerge ==
    /\ \A m \in Mems : led[m] = "false" => RecordedFor(m) # {}
    /\ \A m \in Mems : (m \in everBoth /\ led[m] = "true") =>
           \E d \in Mems : <<d, m>> \in resolves

\* Core and the learner agree on what was retracted, and core never calls a retracted memory
\* settled (`true`), whatever order the resolutions reach it in.
LedgerFalseIsRetracted ==
    up => \A m \in Mems : led[m] = "false" => mem[m] = "retracted"

LedgerTrueIsStanding ==
    up => \A m \in Mems : led[m] = "true" => mem[m] \in Standing

=============================================================================
