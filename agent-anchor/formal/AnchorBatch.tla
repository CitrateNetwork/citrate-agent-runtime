----------------------------- MODULE AnchorBatch -----------------------------
(***************************************************************************)
(* HUP-S7.3: the nightly anchor batch over the local decision records, at  *)
(* the level of citrate-agent-anchor `plan_day` / `prove` and              *)
(* `AnchorLedger`.                                                         *)
(*                                                                          *)
(* A record is a seq i (its index in `recs`) with the UTC day it was       *)
(* written on and a content version (bumped by a consistent rewrite of the *)
(* whole log by someone with disk access, which the hash chain alone       *)
(* cannot detect; the anchor is what catches it).                          *)
(*                                                                          *)
(*   Append      a record joins the CURRENT day (timestamps never go       *)
(*               backwards, so a closed day never gains a record)          *)
(*   Tick        the UTC day advances                                      *)
(*   Prune       the oldest retained record is dropped (retention)         *)
(*   Rewrite     a retained record's content changes (environment)         *)
(*   Batch(d)    plan_day for a closed day with no ledger entry:           *)
(*               partly pruned  -> recorded "incomplete" (reported)        *)
(*               otherwise      -> recorded "batched" with its root        *)
(*               (refused if its seqs overlap another entry)               *)
(*   ReBatch(d)  plan_day for a batched day whose records changed:         *)
(*               refused with Conflict (an alarm), the ledger is unchanged *)
(*                                                                          *)
(* The root is modelled as an injective commitment to the day and to the   *)
(* (seq, content) pairs, i.e. SHA-256 is assumed collision resistant.      *)
(*                                                                          *)
(* Invariants:                                                             *)
(*   BatchedHaveValidProof  every record of a batched day whose day is     *)
(*                          untouched gets a proof that verifies against   *)
(*                          the anchored root                              *)
(*   ProofsSound            `prove` never returns a proof that fails to     *)
(*                          verify against the anchored root               *)
(*   RootCoversExactlyDay   a batch's leaves are exactly the records of    *)
(*                          its day                                        *)
(*   NoDoubleAnchor         no record is in two ledger entries             *)
(*   NoRebatchDifferentRoot a day is never recorded with two roots         *)
(*   IncompleteNeverAnchored a partly pruned day never gets a root         *)
(* Liveness:                                                               *)
(*   EveryRecordEventuallyBatchedOrReported                                *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS MaxDay, MaxRecords, MaxPrune, MaxRewrite

Days == 0..MaxDay

VARIABLES clock, recs, pruned, rewrites, ledger, history, alarms
vars == <<clock, recs, pruned, rewrites, ledger, history, alarms>>

Seqs == 1..Len(recs)
Retained == {i \in Seqs : i > pruned}
DayRecs(d) == {i \in Seqs : recs[i].day = d}
RetainedDay(d) == DayRecs(d) \cap Retained
\* Some record of day d was pruned (records are pruned oldest first).
Partial(d) == \E i \in 1..pruned : recs[i].day = d

Content(S) == {<<i, recs[i].ver>> : i \in S}
Commit(d, S) == <<d, Content(S)>>
NoRoot == <<MaxDay + 1, {}>>
Empty == [st |-> "none", leaves |-> {}, root |-> NoRoot]

\* What `prove(seq)` returns for a retained record of a batched day.
ProveResult(i) ==
    LET d == recs[i].day IN
    IF ~(i \in Retained) \/ Partial(d) THEN "unavailable"
    ELSE IF Commit(d, RetainedDay(d)) = ledger[d].root THEN "valid"
    ELSE "conflict"
\* The proof `prove` builds: the leaf and the tree it rebuilt from the records.
MkProof(i) == [day |-> recs[i].day, leaf |-> <<i, recs[i].ver>>,
               set |-> Content(RetainedDay(recs[i].day))]
\* `verify_proof`: the header commits to the anchored value and the leaf is in the tree.
Verify(p, root) == root = <<p.day, p.set>> /\ p.leaf \in p.set

TypeOK ==
    /\ clock \in Days
    /\ recs \in Seq([day : Days, ver : 0..MaxRewrite])
    /\ Len(recs) <= MaxRecords
    /\ pruned \in 0..MaxPrune
    /\ rewrites \in 0..MaxRewrite
    /\ \A d \in Days : ledger[d].st \in {"none", "batched", "incomplete"}
    /\ alarms \subseteq Days

Init ==
    /\ clock = 0
    /\ recs = << >>
    /\ pruned = 0
    /\ rewrites = 0
    /\ ledger = [d \in Days |-> Empty]
    /\ history = {}
    /\ alarms = {}

AppendRec ==
    /\ Len(recs) < MaxRecords
    /\ clock < MaxDay
    /\ recs' = Append(recs, [day |-> clock, ver |-> 0])
    /\ UNCHANGED <<clock, pruned, rewrites, ledger, history, alarms>>

Tick ==
    /\ clock < MaxDay
    /\ clock' = clock + 1
    /\ UNCHANGED <<recs, pruned, rewrites, ledger, history, alarms>>

Prune ==
    /\ pruned < Len(recs)
    /\ pruned < MaxPrune
    /\ pruned' = pruned + 1
    /\ UNCHANGED <<clock, recs, rewrites, ledger, history, alarms>>

Rewrite(i) ==
    /\ rewrites < MaxRewrite
    /\ i \in Retained
    /\ recs' = [recs EXCEPT ![i].ver = @ + 1]
    /\ rewrites' = rewrites + 1
    /\ UNCHANGED <<clock, pruned, ledger, history, alarms>>

Batch(d) ==
    LET S == RetainedDay(d) IN
    /\ d < clock                       \* only closed days (DayNotClosed otherwise)
    /\ ledger[d].st = "none"
    /\ S # {}                          \* empty / fully pruned day: nothing recorded
    /\ \A e \in Days : ledger[e].leaves \cap S = {}   \* Overlap refused
    /\ IF Partial(d)
         THEN /\ ledger' = [ledger EXCEPT ![d] =
                              [st |-> "incomplete", leaves |-> S, root |-> NoRoot]]
              /\ UNCHANGED history
         ELSE /\ ledger' = [ledger EXCEPT ![d] =
                              [st |-> "batched", leaves |-> S, root |-> Commit(d, S)]]
              /\ history' = history \cup {<<d, Commit(d, S)>>}
    /\ UNCHANGED <<clock, recs, pruned, rewrites, alarms>>

ReBatch(d) ==
    LET S == RetainedDay(d) IN
    /\ d < clock
    /\ ledger[d].st = "batched"
    /\ ~Partial(d)
    /\ S # {}
    /\ Commit(d, S) # ledger[d].root
    /\ d \notin alarms
    /\ alarms' = alarms \cup {d}       \* Conflict: refused and reported
    /\ UNCHANGED <<clock, recs, pruned, rewrites, ledger, history>>

Next ==
    \/ AppendRec
    \/ Tick
    \/ Prune
    \/ \E i \in Seqs : Rewrite(i)
    \/ \E d \in Days : Batch(d)
    \/ \E d \in Days : ReBatch(d)

Spec == Init /\ [][Next]_vars /\ WF_vars(Tick) /\ \A d \in Days : WF_vars(Batch(d))

-----------------------------------------------------------------------------
Batched(d) == ledger[d].st = "batched"
Untouched(d) == ~Partial(d) /\ \A i \in DayRecs(d) : recs[i].ver = 0

BatchedHaveValidProof ==
    \A d \in Days : Batched(d) /\ Untouched(d) =>
        \A i \in ledger[d].leaves :
            /\ ProveResult(i) = "valid"
            /\ Verify(MkProof(i), ledger[d].root)

ProofsSound ==
    \A d \in Days : Batched(d) =>
        \A i \in ledger[d].leaves \cap Retained :
            ProveResult(i) = "valid" => Verify(MkProof(i), ledger[d].root)

RootCoversExactlyDay ==
    \A d \in Days : Batched(d) => ledger[d].leaves = DayRecs(d)

NoDoubleAnchor ==
    \A d1, d2 \in Days : d1 # d2 => ledger[d1].leaves \cap ledger[d2].leaves = {}

NoRebatchDifferentRoot ==
    \A h1, h2 \in history : h1[1] = h2[1] => h1 = h2

IncompleteNeverAnchored ==
    \A d \in Days : ledger[d].st = "incomplete" => \A h \in history : h[1] # d

Covered(i) ==
    /\ i <= Len(recs)
    /\ \/ ledger[recs[i].day].st # "none"
       \/ RetainedDay(recs[i].day) = {}

EveryRecordEventuallyBatchedOrReported ==
    \A i \in 1..MaxRecords : [](i <= Len(recs) => <>Covered(i))
=============================================================================
