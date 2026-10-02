----------------------------- MODULE DecideEgress -----------------------------
(***************************************************************************)
(* HUP-S5.3: which backend the decide() slot uses, at the level of         *)
(* citrate-agent-loop `Decider::resolve` / `Decider::jev_permission`.      *)
(*                                                                          *)
(* Settings (fixed per run, every combination explored):                    *)
(*   localOK      a local model endpoint was supplied                       *)
(*   jevOn        the member turned Jev on            (DecidePolicy)        *)
(*   jevKey       a Jev backend is configured (key file read)               *)
(*   nonWeb       Jev may answer decisions with no web origin               *)
(* A request:                                                               *)
(*   origin in {"none", "allowed", "other", "invalid"}                      *)
(*   cookie, attach  (the origin has a session cookie / attach mode)        *)
(*   pref in {"auto", "local", "jev"}                                       *)
(* Outcome in {"local", "jev", "refused", "unconfigured"}.                 *)
(*                                                                          *)
(* The properties are stated over the member's rules (GROUND TRUTH); the    *)
(* guard is modelled separately as the implementation (Permitted, Resolve)  *)
(* in the order the Rust code checks things, so a mutant in the guard is    *)
(* visible to the properties.                                               *)
(*                                                                          *)
(*   JevNeedsOptIn         Jev answers only when the member turned it on    *)
(*                         and a key is configured                          *)
(*   JevOnlyAllowedOrigins a web decision goes to Jev only for an origin    *)
(*                         on the member's allowlist                        *)
(*   NeverCookieOrAttach   never for an origin with a session cookie or in  *)
(*                         attach mode                                      *)
(*   NonWebNeedsOwnOptIn   a decision with no origin goes to Jev only with  *)
(*                         the separate non-web opt-in                      *)
(*   NoSilentFallback      asking for Jev yields Jev or a refusal, never a  *)
(*                         quiet local answer                               *)
(*   LocalNeverEgress      asking for local never reaches Jev               *)
(*   EveryEgressNoticed    every Jev decision carries an egress notice      *)
(*   AutoUsesPermittedJev  auto picks Jev exactly when the rules allow it   *)
(*                         (guards against an over-restrictive guard)       *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS MaxDecisions

Origins  == {"none", "allowed", "other", "invalid"}
Prefs    == {"auto", "local", "jev"}
Outcomes == {"local", "jev", "refused", "unconfigured"}

VARIABLES localOK, jevOn, jevKey, nonWeb, history, notices

vars == <<localOK, jevOn, jevKey, nonWeb, history, notices>>

Requests == [origin : Origins, cookie : BOOLEAN, attach : BOOLEAN, pref : Prefs]

(* ---------------- the implementation (Decider::jev_permission) --------- *)
Permitted(r) ==
    IF ~jevKey THEN FALSE                       \* "the Jev backend is not configured"
    ELSE IF ~jevOn THEN FALSE                   \* "the Jev backend is off (opt-in)"
    ELSE IF r.origin = "none" THEN nonWeb
    ELSE IF r.attach THEN FALSE
    ELSE IF r.cookie THEN FALSE
    ELSE IF r.origin = "invalid" THEN FALSE     \* normalize_origin -> None
    ELSE r.origin = "allowed"                   \* exact normalized match

(* ---------------- the implementation (Decider::resolve) ---------------- *)
Resolve(r) ==
    CASE r.pref = "local" -> (IF localOK THEN "local" ELSE "unconfigured")
      [] r.pref = "jev"   -> (IF Permitted(r) THEN "jev" ELSE "refused")
      [] r.pref = "auto"  -> (IF Permitted(r) THEN "jev"
                              ELSE IF localOK THEN "local" ELSE "unconfigured")

(* ---------------- the member's rules (ground truth) -------------------- *)
RulesAllowJev(r) ==
    /\ jevOn
    /\ jevKey
    /\ IF r.origin = "none" THEN nonWeb
       ELSE r.origin = "allowed" /\ ~r.cookie /\ ~r.attach

Init ==
    /\ localOK \in BOOLEAN
    /\ jevOn \in BOOLEAN
    /\ jevKey \in BOOLEAN
    /\ nonWeb \in BOOLEAN
    /\ history = <<>>
    /\ notices = 0

Decide(r) ==
    LET out == Resolve(r) IN
    /\ Len(history) < MaxDecisions
    /\ history' = Append(history, [req |-> r, out |-> out])
    /\ notices' = IF out = "jev" THEN notices + 1 ELSE notices
    /\ UNCHANGED <<localOK, jevOn, jevKey, nonWeb>>

Next == \E r \in Requests : Decide(r)

Spec == Init /\ [][Next]_vars

(* ---------------- properties ------------------------------------------ *)
TypeOK ==
    /\ localOK \in BOOLEAN /\ jevOn \in BOOLEAN /\ jevKey \in BOOLEAN /\ nonWeb \in BOOLEAN
    /\ notices \in 0..MaxDecisions
    /\ \A i \in 1..Len(history) : history[i].req \in Requests /\ history[i].out \in Outcomes

H == history

JevNeedsOptIn ==
    \A i \in 1..Len(H) : H[i].out = "jev" => jevOn /\ jevKey

JevOnlyAllowedOrigins ==
    \A i \in 1..Len(H) : (H[i].out = "jev" /\ H[i].req.origin # "none")
                            => H[i].req.origin = "allowed"

NeverCookieOrAttach ==
    \A i \in 1..Len(H) : (H[i].out = "jev" /\ H[i].req.origin # "none")
                            => ~H[i].req.cookie /\ ~H[i].req.attach

NonWebNeedsOwnOptIn ==
    \A i \in 1..Len(H) : (H[i].out = "jev" /\ H[i].req.origin = "none") => nonWeb

NoSilentFallback ==
    \A i \in 1..Len(H) : H[i].req.pref = "jev" => H[i].out \in {"jev", "refused"}

LocalNeverEgress ==
    \A i \in 1..Len(H) : H[i].req.pref = "local" => H[i].out # "jev"

EveryEgressNoticed ==
    notices = Len(SelectSeq(H, LAMBDA e : e.out = "jev"))

AutoUsesPermittedJev ==
    \A i \in 1..Len(H) : H[i].req.pref = "auto" =>
        (H[i].out = "jev" <=> RulesAllowJev(H[i].req))

=============================================================================
