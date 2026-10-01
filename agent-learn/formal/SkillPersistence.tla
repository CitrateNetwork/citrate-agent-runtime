-------------------------- MODULE SkillPersistence --------------------------
(***************************************************************************)
(* HUP-S3.4: verified self-learning. Proposal -> verifier -> member ->     *)
(* store -> publish, for a set of independent proposals.                   *)
(*                                                                         *)
(* Ground truth (what really happened) is kept apart from the guards the   *)
(* implementation evaluates, so that mutating a guard is detectable:       *)
(*   truth:  verdict, claim, acceptedEver, conflict, approved, diskOk      *)
(*   guards: CanPropose, PersistGuard, PublishGuard                        *)
(*                                                                         *)
(* Rust counterpart: agent-learn/src/{evidence,learner}.rs                 *)
(*   CanPropose    = run_verified_workflow returns a VerifiedRun only on   *)
(*                   WorkflowOutcome::Succeeded + recorded passing verdicts*)
(*   PersistGuard  = Learner::accept (state, member, blocking, acks)       *)
(*   PublishGuard  = Learner::prepare_publish (state, approval, re-read)   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Props,     \* proposal slots
          MaxSteps   \* bound on environment moves (world changes, tampering)

States   == {"idle", "proposed", "rejected", "persistfailed", "persisted", "prepared"}
Awaiting == {"proposed", "persistfailed"}
Saved    == {"persisted", "prepared"}

VARIABLES
    verdict,       \* truth: "none" | "pass" | "fail" (every verifier of every step passed?)
    claim,         \* truth: what the model says about success (never evidence)
    state,         \* the learner's state per proposal
    pressed,       \* the member pressed accept and the learner has not acted on it yet
    acked,         \* the acknowledgement that came with that press
    acceptedEver,  \* truth (ghost): the member accepted this proposal at some point
    conflict,      \* truth, current: "none" | "soft" (needs ack) | "hard" (never overwritten)
    approved,      \* truth: the member gave an explicit publish approval for this proposal
    diskOk,        \* truth: the saved SKILL.md still has the accepted content hash
    persistedEver, \* ghost: something was written
    mergedBad,     \* ghost: a write happened over a hard conflict or an unacknowledged one
    published,     \* ghost: a publish payload was built
    publishedBad,  \* ghost: a payload was built for content that no longer matched
    recAccept,     \* the accept decision is in the decision log
    recReject,     \* the reject decision is in the decision log
    steps

vars == <<verdict, claim, state, pressed, acked, acceptedEver, conflict, approved, diskOk,
          persistedEver, mergedBad, published, publishedBad, recAccept, recReject, steps>>

----------------------------------------------------------------------------
(* The implementation's guards. *)

CanPropose(p)   == verdict[p] = "pass"
PersistGuard(p) == /\ state[p] \in Awaiting
                   /\ pressed[p]
                   /\ conflict[p] # "hard"
                   /\ (conflict[p] = "soft" => acked[p])
PublishGuard(p) == /\ state[p] \in Saved
                   /\ approved[p]
                   /\ diskOk[p]

----------------------------------------------------------------------------
Init ==
    /\ verdict = [p \in Props |-> "none"]
    /\ claim = [p \in Props |-> FALSE]
    /\ state = [p \in Props |-> "idle"]
    /\ pressed = [p \in Props |-> FALSE]
    /\ acked = [p \in Props |-> FALSE]
    /\ acceptedEver = [p \in Props |-> FALSE]
    /\ conflict \in [Props -> {"none", "soft", "hard"}]
    /\ approved = [p \in Props |-> FALSE]
    /\ diskOk = [p \in Props |-> TRUE]
    /\ persistedEver = [p \in Props |-> FALSE]
    /\ mergedBad = [p \in Props |-> FALSE]
    /\ published = [p \in Props |-> FALSE]
    /\ publishedBad = [p \in Props |-> FALSE]
    /\ recAccept = [p \in Props |-> FALSE]
    /\ recReject = [p \in Props |-> FALSE]
    /\ steps = 0

\* A workflow runs; verifiers decide; the model says whatever it says.
RunWorkflow(p) ==
    /\ verdict[p] = "none"
    /\ \E v \in {"pass", "fail"}, c \in BOOLEAN :
         /\ verdict' = [verdict EXCEPT ![p] = v]
         /\ claim' = [claim EXCEPT ![p] = c]
    /\ UNCHANGED <<state, pressed, acked, acceptedEver, conflict, approved, diskOk,
                   persistedEver, mergedBad, published, publishedBad, recAccept, recReject, steps>>

Propose(p) ==
    /\ state[p] = "idle"
    /\ verdict[p] # "none"
    /\ CanPropose(p)
    /\ state' = [state EXCEPT ![p] = "proposed"]
    /\ UNCHANGED <<verdict, claim, pressed, acked, acceptedEver, conflict, approved, diskOk,
                   persistedEver, mergedBad, published, publishedBad, recAccept, recReject, steps>>

\* The member presses accept, with or without acknowledging the conflicts shown. A press can
\* arrive for any proposal (a stale card, a replayed request); the learner's guard decides.
MemberAccept(p) ==
    /\ state[p] # "idle"
    /\ ~pressed[p]
    /\ \E a \in BOOLEAN : acked' = [acked EXCEPT ![p] = a]
    /\ pressed' = [pressed EXCEPT ![p] = TRUE]
    /\ acceptedEver' = [acceptedEver EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<verdict, claim, state, conflict, approved, diskOk, persistedEver, mergedBad,
                   published, publishedBad, recAccept, recReject, steps>>

MemberReject(p) ==
    /\ state[p] \in Awaiting
    /\ state' = [state EXCEPT ![p] = "rejected"]
    /\ recReject' = [recReject EXCEPT ![p] = TRUE]
    /\ pressed' = [pressed EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<verdict, claim, acked, acceptedEver, conflict, approved, diskOk,
                   persistedEver, mergedBad, published, publishedBad, recAccept, steps>>

\* The learner acts on a press: record the decision (write-ahead), then write. The write can fail.
Persist(p) ==
    /\ PersistGuard(p)
    /\ recAccept' = [recAccept EXCEPT ![p] = TRUE]
    /\ pressed' = [pressed EXCEPT ![p] = FALSE]
    /\ \/ /\ state' = [state EXCEPT ![p] = "persisted"]
          /\ persistedEver' = [persistedEver EXCEPT ![p] = TRUE]
          /\ diskOk' = [diskOk EXCEPT ![p] = TRUE]
          /\ mergedBad' = [mergedBad EXCEPT ![p] =
                 @ \/ conflict[p] = "hard" \/ (conflict[p] = "soft" /\ ~acked[p])]
       \/ /\ state' = [state EXCEPT ![p] = "persistfailed"]
          /\ UNCHANGED <<persistedEver, diskOk, mergedBad>>
    /\ UNCHANGED <<verdict, claim, acked, acceptedEver, conflict, approved, published,
                   publishedBad, recReject, steps>>

\* The learner refuses a press it cannot honour (blocked or unacknowledged). Nothing is recorded.
Refuse(p) ==
    /\ pressed[p]
    /\ ~PersistGuard(p)
    /\ pressed' = [pressed EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<verdict, claim, state, acked, acceptedEver, conflict, approved, diskOk,
                   persistedEver, mergedBad, published, publishedBad, recAccept, recReject, steps>>

\* The member approves publishing (an HIC-1 card). May happen at any time; the guard decides.
Approve(p) ==
    /\ ~approved[p]
    /\ approved' = [approved EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<verdict, claim, state, pressed, acked, acceptedEver, conflict, diskOk,
                   persistedEver, mergedBad, published, publishedBad, recAccept, recReject, steps>>

\* Build the calldata. Nothing is signed or sent here: that is the core ceremony.
PreparePublish(p) ==
    /\ PublishGuard(p)
    /\ state' = [state EXCEPT ![p] = "prepared"]
    /\ published' = [published EXCEPT ![p] = TRUE]
    /\ publishedBad' = [publishedBad EXCEPT ![p] = @ \/ ~diskOk[p]]
    /\ UNCHANGED <<verdict, claim, pressed, acked, acceptedEver, conflict, approved, diskOk,
                   persistedEver, mergedBad, recAccept, recReject, steps>>

\* Environment: other items appear or go away; the saved file is edited outside Hermes.
WorldChange(p) ==
    /\ steps < MaxSteps
    /\ \E c \in {"none", "soft", "hard"} : conflict' = [conflict EXCEPT ![p] = c]
    /\ steps' = steps + 1
    /\ UNCHANGED <<verdict, claim, state, pressed, acked, acceptedEver, approved, diskOk,
                   persistedEver, mergedBad, published, publishedBad, recAccept, recReject>>

Tamper(p) ==
    /\ steps < MaxSteps
    /\ state[p] \in Saved
    /\ diskOk[p]
    /\ diskOk' = [diskOk EXCEPT ![p] = FALSE]
    /\ steps' = steps + 1
    /\ UNCHANGED <<verdict, claim, state, pressed, acked, acceptedEver, conflict, approved,
                   persistedEver, mergedBad, published, publishedBad, recAccept, recReject>>

Next ==
    \E p \in Props :
        \/ RunWorkflow(p) \/ Propose(p) \/ MemberAccept(p) \/ MemberReject(p)
        \/ Persist(p) \/ Refuse(p) \/ Approve(p) \/ PreparePublish(p)
        \/ WorldChange(p) \/ Tamper(p)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Properties, over ground truth. *)

TypeOK ==
    /\ verdict \in [Props -> {"none", "pass", "fail"}]
    /\ state \in [Props -> States]
    /\ conflict \in [Props -> {"none", "soft", "hard"}]
    /\ steps \in 0..MaxSteps

\* Nothing is proposed unless every verifier passed (the model's claim never counts).
NothingProposedWithoutVerifiers ==
    \A p \in Props : state[p] # "idle" => verdict[p] = "pass"

\* Nothing persists without a passing verification and the member's accept, and the accept is
\* in the decision log.
PersistImpliesVerifiedAndAccepted ==
    \A p \in Props : persistedEver[p] => /\ verdict[p] = "pass"
                                         /\ acceptedEver[p]
                                         /\ recAccept[p]

\* Contradictions are never silently merged: no write over a hard conflict, and no write over a
\* soft one the member did not acknowledge.
NoSilentMerge == \A p \in Props : ~mergedBad[p]

\* A reject is recorded and final: a rejected proposal never persists and never leaves "rejected".
RejectRecordedAndFinal ==
    \A p \in Props : /\ state[p] = "rejected" => recReject[p]
                     /\ recReject[p] => state[p] = "rejected" /\ ~persistedEver[p]

\* Publish only after persist, only with the member's explicit approval (HIC-1), and only for the
\* content that was accepted.
PublishImpliesHIC1 ==
    \A p \in Props : published[p] => /\ persistedEver[p]
                                     /\ approved[p]
                                     /\ ~publishedBad[p]

=============================================================================
