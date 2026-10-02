---------------------------- MODULE LearnRestart ----------------------------
(***************************************************************************)
(* HUP-S3.4 wiring: one skill proposal across sidecar crashes and          *)
(* restarts. The learner keeps proposals in memory, rewrites the proposals *)
(* file after every change, and writes the decision log before every       *)
(* effect. Any save can be lost (a failed write, or a crash before it), so *)
(* on restart the file can be one decision behind the log.                 *)
(*                                                                         *)
(* Rust counterpart: agent-learn/src/learner.rs                            *)
(*   Propose         = Learner::propose (save, or roll back and refuse)    *)
(*   AcceptGuard     = Learner::accept: awaiting, and no skill folder with  *)
(*                     that name on disk (AlreadyKnown / SameNameSkill)    *)
(*   Record/Write/Close = record_decision, persist_skill, record_outcome   *)
(*   Save            = Learner::save (may never happen before a crash)     *)
(*   Reconcile       = Learner::open -> reconcile_with_log                 *)
(*   Crash recovery of the log closes an open accept as outcome_unknown.   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANT MaxCrashes

Awaiting == {"proposed", "persistfailed"}

VARIABLES
    up,          \* the sidecar process is running
    mem,         \* the learner's in-memory state of the proposal
    phase,       \* "idle" | "write" (decision recorded, effect next) | "close" (effect done)
    file,        \* the state saved in the proposals file
    lastDec,     \* the latest decision in the log: "none" | "accept" | "reject"
    outcome,     \* outcome of the latest accept: "none" | "completed" | "failed" | "unknown"
    disk,        \* truth: the skill folder exists
    writes,      \* truth: how many times the skill was written
    acked,       \* ghost: propose returned success to the caller
    acceptRec,   \* ghost: an accept was ever recorded
    rejectRec,   \* ghost: a reject was ever recorded
    acceptAfterReject, \* ghost: an accept was recorded after a reject
    crashes

vars == <<up, mem, phase, file, lastDec, outcome, disk, writes, acked, acceptRec, rejectRec,
          acceptAfterReject, crashes>>

----------------------------------------------------------------------------
(* The implementation's guards and recovery. *)

AcceptGuard == mem \in Awaiting /\ ~disk

Reconcile(f, oc) ==
    IF f \in Awaiting
    THEN CASE lastDec = "reject" -> "rejected"
           [] lastDec = "accept" /\ oc = "completed" /\ disk -> "persisted"
           [] lastDec = "accept" -> "persistfailed"
           [] OTHER -> f
    ELSE f

----------------------------------------------------------------------------
Init ==
    /\ up = TRUE
    /\ mem = "none"
    /\ phase = "idle"
    /\ file = "none"
    /\ lastDec = "none"
    /\ outcome = "none"
    /\ disk = FALSE
    /\ writes = 0
    /\ acked = FALSE
    /\ acceptRec = FALSE
    /\ rejectRec = FALSE
    /\ acceptAfterReject = FALSE
    /\ crashes = 0

\* Save immediately; if the save fails, forget the proposal and refuse (nothing was decided).
Propose ==
    /\ up /\ mem = "none" /\ phase = "idle"
    /\ \/ /\ mem' = "proposed" /\ file' = "proposed" /\ acked' = TRUE
       \/ /\ UNCHANGED <<mem, file, acked>>
    /\ UNCHANGED <<up, phase, lastDec, outcome, disk, writes, acceptRec, rejectRec,
                   acceptAfterReject, crashes>>

\* Accept, step 1: the decision goes to the log before any effect.
Record ==
    /\ up /\ phase = "idle" /\ AcceptGuard
    /\ lastDec' = "accept" /\ outcome' = "none" /\ phase' = "write"
    /\ acceptRec' = TRUE
    /\ acceptAfterReject' = (acceptAfterReject \/ rejectRec)
    /\ UNCHANGED <<up, mem, file, disk, writes, acked, rejectRec, crashes>>

\* Accept, step 2: write the skill folder. The write can fail.
Write ==
    /\ up /\ phase = "write"
    /\ \/ /\ disk' = TRUE /\ writes' = writes + 1 /\ mem' = "persisted"
       \/ /\ UNCHANGED <<disk, writes>> /\ mem' = "persistfailed"
    /\ phase' = "close"
    /\ UNCHANGED <<up, file, lastDec, outcome, acked, acceptRec, rejectRec, acceptAfterReject,
                   crashes>>

\* Accept, step 3: close the decision with its outcome.
Close ==
    /\ up /\ phase = "close"
    /\ outcome' = IF mem = "persisted" THEN "completed" ELSE "failed"
    /\ phase' = "idle"
    /\ UNCHANGED <<up, mem, file, lastDec, disk, writes, acked, acceptRec, rejectRec,
                   acceptAfterReject, crashes>>

Reject ==
    /\ up /\ phase = "idle" /\ mem \in Awaiting
    /\ lastDec' = "reject" /\ mem' = "rejected" /\ rejectRec' = TRUE
    /\ UNCHANGED <<up, phase, file, outcome, disk, writes, acked, acceptRec, acceptAfterReject,
                   crashes>>

\* The proposals file catches up (the next successful save). It may never run before a crash.
Save ==
    /\ up /\ phase = "idle" /\ file # mem
    /\ file' = mem
    /\ UNCHANGED <<up, mem, phase, lastDec, outcome, disk, writes, acked, acceptRec, rejectRec,
                   acceptAfterReject, crashes>>

Crash ==
    /\ up /\ crashes < MaxCrashes
    /\ up' = FALSE /\ crashes' = crashes + 1
    /\ UNCHANGED <<mem, phase, file, lastDec, outcome, disk, writes, acked, acceptRec, rejectRec,
                   acceptAfterReject>>

\* Restart: log recovery closes an open accept as outcome_unknown; then the learner loads the
\* file and reconciles it with the log.
Restart ==
    /\ ~up
    /\ LET oc == IF lastDec = "accept" /\ outcome = "none" THEN "unknown" ELSE outcome
       IN /\ outcome' = oc
          /\ mem' = Reconcile(file, oc)
    /\ up' = TRUE /\ phase' = "idle"
    /\ UNCHANGED <<file, lastDec, disk, writes, acked, acceptRec, rejectRec, acceptAfterReject,
                   crashes>>

Next == Propose \/ Record \/ Write \/ Close \/ Reject \/ Save \/ Crash \/ Restart

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Properties, over ground truth. *)

TypeOK ==
    /\ mem \in {"none", "proposed", "rejected", "persistfailed", "persisted"}
    /\ file \in {"none", "proposed", "rejected", "persistfailed", "persisted"}
    /\ phase \in {"idle", "write", "close"}
    /\ writes \in 0..3

\* The skill is never written twice, whatever crashes and lost saves happen.
AtMostOneWrite == writes <= 1

\* Every write was decided by the member first (write-ahead).
WriteImpliesRecorded == writes > 0 => acceptRec

\* A reject is final across restarts: no accept is ever recorded after one.
RejectFinal == ~acceptAfterReject

\* A proposal the caller was told about is never lost by a restart while undecided.
AckedNotLost == (acked /\ up /\ ~acceptRec /\ ~rejectRec) => mem = "proposed"

\* The learner never claims a skill is saved when it is not on disk.
PersistedIsTrue == (up /\ mem = "persisted") => disk

=============================================================================
