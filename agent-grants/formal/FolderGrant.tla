----------------------------- MODULE FolderGrant -----------------------------
(***************************************************************************)
(* HUP-S2.1: folder grants, at the level of citrate-agent-grants           *)
(* `FolderGrants::{grant, revoke, check}`.                                  *)
(*                                                                          *)
(* The filesystem is a small tree of folders. A request is what the agent   *)
(* wrote (`lex`, the location a lexical `..`-first normalization reaches)   *)
(* and where the kernel really lands (`res`, symlinks followed where met).  *)
(* The request set covers a plain path, a symlink inside a grant into the   *)
(* deny list, `link/..` (lexically inside the grant, really its parent),    *)
(* a symlink out of a grant, a symlink into a grant from outside, a name    *)
(* that is lexically in the deny list but resolves somewhere harmless, and  *)
(* `.env` files inside and outside a project.                               *)
(*                                                                          *)
(* A grant is [root, access, scope, full, at, exp, revoked]; exp = 0 means  *)
(* "until revoked" (folder grants only). Time is a discrete clock.          *)
(*                                                                          *)
(* The properties are stated over GROUND TRUTH (`SpecUnder`, `SpecSecret`,  *)
(* `SpecCovers`, `SpecLive`) about the resolved target; the checker is     *)
(* modelled separately as THE IMPLEMENTATION (`ImplUnder`, `ImplSecret`,    *)
(* `GuardDenies`, `ImplCovers`, `ImplActive`, `Decide`), so mutating the    *)
(* implementation is detectable.                                            *)
(*                                                                          *)
(* Invariants:                                                              *)
(*   NoParentEscape          allowed => the resolved target is the grant's  *)
(*                           root or below it (one level for shallow)       *)
(*   SecretsNeverReadable    allowed => the resolved target is not in the   *)
(*                           deny list (the deny list always wins)          *)
(*   ExpiredGrantInert       allowed => the grant was live at the check:    *)
(*                           not revoked and the clock before its expiry    *)
(*   NoAccessOutsideActiveGrant  the three above together                   *)
(*   ReadNotImpliesWrite     allowed => the grant's access is the op's      *)
(*                           (a read grant never writes, and vice versa)    *)
(*   DotEnvOnlyViaFolderGrant  an allowed `.env` comes from a folder grant  *)
(*   FullAccessReadOnly      every full-access grant is read-only           *)
(*   FullAccessBounded       every full-access grant expires within FullTTL *)
(*   NoGrantRootedInDenyList no grant's root is in the deny list            *)
(* Liveness (weak fairness on Tick):                                        *)
(*   FullAccessExpires       a live full-access grant eventually is not     *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS MaxGrants, MaxClock, FullTTL, FolderTTLs

ASSUME MaxGrants \in Nat /\ MaxClock \in Nat /\ FullTTL \in Nat \ {0}
ASSUME FolderTTLs \subseteq Nat   \* 0 = until revoked

\* ---------------------------------------------------------------- the tree
Nodes == {"root", "home", "proj", "src", "penv", "ssh", "key", "other", "oenv"}
Parent == [n \in Nodes |->
             CASE n = "root"  -> "root"
               [] n = "home"  -> "root"
               [] n = "proj"  -> "home"
               [] n = "src"   -> "proj"
               [] n = "penv"  -> "proj"     \* proj/.env
               [] n = "ssh"   -> "home"     \* ~/.ssh (deny list)
               [] n = "key"   -> "ssh"
               [] n = "other" -> "home"
               [] n = "oenv"  -> "other"]   \* other/.env
DenyRoots == {"ssh"}
EnvFiles  == {"penv", "oenv"}
GrantRoots == {"root", "home", "proj", "src", "other", "ssh"}

\* ------------------------------------------------------------ ground truth
RECURSIVE UpSet(_, _)
UpSet(n, k) == IF k = 0 THEN {n} ELSE {n} \cup UpSet(Parent[n], k - 1)
AncOrSelf(n) == UpSet(n, Cardinality(Nodes))
RECURSIVE Depth(_)
Depth(n) == IF n = "root" THEN 0 ELSE 1 + Depth(Parent[n])

SpecUnder(a, n)  == a \in AncOrSelf(n)
SpecSecret(n)    == \E d \in DenyRoots : SpecUnder(d, n)
SpecCovers(g, n) == SpecUnder(g.root, n) /\ (g.scope = "shallow" => Depth(n) <= Depth(g.root) + 1)
SpecLive(g, t)   == ~g.revoked /\ (g.exp = 0 \/ t < g.exp)

\* ------------------------------------------------------------- requests
Requests == {
    [lex |-> "src",   res |-> "src"],    \* plain path
    [lex |-> "src",   res |-> "key"],    \* proj/src/k -> ~/.ssh/key
    [lex |-> "proj",  res |-> "home"],   \* proj/out/.. where out -> ~/other
    [lex |-> "proj",  res |-> "other"],  \* proj/out -> ~/other
    [lex |-> "other", res |-> "src"],    \* other/in -> proj/src
    [lex |-> "key",   res |-> "key"],    \* ~/.ssh/key
    [lex |-> "ssh",   res |-> "other"],  \* a ".ssh" name that is a link to other
    [lex |-> "home",  res |-> "home"],
    [lex |-> "penv",  res |-> "penv"],   \* proj/.env
    [lex |-> "oenv",  res |-> "oenv"]    \* other/.env
}
Ops == {"read", "write"}

\* -------------------------------------------------------- implementation
\* agent-guard walks up the folded components of every location it visits.
RECURSIVE ParentN(_, _)
ParentN(n, k) == IF k = 0 THEN n ELSE ParentN(Parent[n], k - 1)
ImplUnder(a, n) == \E k \in 0..4 : ParentN(n, k) = a
ImplSecret(n)   == \E d \in DenyRoots : ImplUnder(d, n)
\* `check_path` checks the request as written AND the resolved location; a
\* `.env` passes only strictly inside a project root.
GuardDenies(r, projectRoots) ==
    \/ ImplSecret(r.lex)
    \/ ImplSecret(r.res)
    \/ (r.res \in EnvFiles /\ ~\E p \in projectRoots : ImplUnder(p, Parent[r.res]))
ImplActive(g, t) == ~g.revoked /\ (g.exp = 0 \/ t < g.exp)
ImplCovers(g, n) ==
    IF g.scope = "subtree" THEN ImplUnder(g.root, n)
    ELSE n = g.root \/ Parent[n] = g.root

VARIABLES grants, nGrants, clock
vars == <<grants, nGrants, clock>>

NoGrant == [root |-> "none", access |-> "none", scope |-> "none", full |-> FALSE,
            at |-> 0, exp |-> 0, revoked |-> FALSE]

Used == 1..nGrants

Init ==
    /\ grants = [i \in 1..MaxGrants |-> NoGrant]
    /\ nGrants = 0
    /\ clock = 0

\* FolderGrants::grant: request validation as implemented.
GrantA(root, access, scope, full, ttl) ==
    /\ nGrants < MaxGrants
    /\ ~ImplSecret(root)                              \* RootDenied
    /\ ~(access = "write" /\ root = "root")           \* WriteOnFilesystemRoot
    /\ full => (access = "read" /\ ttl \in 1..FullTTL)
    \* Model bound only: real time keeps going past MaxClock.
    /\ full => clock + ttl <= MaxClock
    /\ grants' = [grants EXCEPT ![nGrants + 1] =
                    [root |-> root, access |-> access, scope |-> scope, full |-> full,
                     at |-> clock, exp |-> IF ttl = 0 THEN 0 ELSE clock + ttl,
                     revoked |-> FALSE]]
    /\ nGrants' = nGrants + 1
    /\ UNCHANGED clock

Grant ==
    \/ \E root \in GrantRoots, access \in Ops, scope \in {"subtree", "shallow"},
          ttl \in FolderTTLs :
            GrantA(root, access, scope, FALSE, ttl)
    \* Members may ask for anything; GrantA's guard is what refuses.
    \/ \E root \in GrantRoots, access \in Ops, ttl \in 0..(FullTTL + 1) :
            GrantA(root, access, "subtree", TRUE, ttl)

\* FolderGrants::revoke: immediate and final.
Revoke ==
    \E i \in Used :
        /\ ~grants[i].revoked
        /\ grants' = [grants EXCEPT ![i].revoked = TRUE]
        /\ UNCHANGED <<nGrants, clock>>

Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED <<grants, nGrants>>

Next == Grant \/ Revoke \/ Tick

Spec == Init /\ [][Next]_vars /\ WF_vars(Tick)

\* FolderGrants::check(r, op, clock), a pure function of the state (so every
\* request is checked in every reachable state without a history variable).
\* Two phases:
\*  1. live folder grants for the op; their roots are the guard's project
\*     roots; allowed only if one of them covers the target;
\*  2. otherwise live full-access grants, guard re-run with no project roots.
\* The first draft was one phase with folder roots as project roots for every
\* grant; TLC found that a shallow folder grant then let full access read a
\* `.env` it does not cover (DotEnvOnlyViaFolderGrant).
Live(op, full) == {i \in Used : ImplActive(grants[i], clock)
                                /\ grants[i].access = op
                                /\ grants[i].full = full}
Decide(r, op) ==
    LET folderRoots == {grants[i].root : i \in Live(op, FALSE)}
        fCover == {i \in Live(op, FALSE) : ImplCovers(grants[i], r.res)}
        aCover == {i \in Live(op, TRUE) : ImplCovers(grants[i], r.res)}
        okF == ~GuardDenies(r, folderRoots) /\ fCover # {}
        okA == ~GuardDenies(r, folderRoots) /\ fCover = {}
               /\ ~GuardDenies(r, {}) /\ aCover # {}
    IN IF okF THEN [allowed |-> TRUE, g |-> grants[CHOOSE i \in fCover : TRUE]]
       ELSE IF okA THEN [allowed |-> TRUE, g |-> grants[CHOOSE i \in aCover : TRUE]]
       ELSE [allowed |-> FALSE, g |-> NoGrant]

\* ------------------------------------------------------------ properties
TypeOK ==
    /\ nGrants \in 0..MaxGrants
    /\ clock \in 0..MaxClock
    /\ \A i \in Used : grants[i].access \in Ops

\* For every request and operation, in every reachable state:
Allowed(P(_, _, _)) ==
    \A r \in Requests, op \in Ops :
        LET d == Decide(r, op) IN d.allowed => P(r, op, d.g)

NoParentEscapeP(r, op, g)       == SpecCovers(g, r.res)
SecretsNeverReadableP(r, op, g) == ~SpecSecret(r.res)
ExpiredGrantInertP(r, op, g)    == SpecLive(g, clock)
ReadNotImpliesWriteP(r, op, g)  == g.access = op
DotEnvP(r, op, g)               == r.res \in EnvFiles => ~g.full

NoParentEscape       == Allowed(NoParentEscapeP)
SecretsNeverReadable == Allowed(SecretsNeverReadableP)
ExpiredGrantInert    == Allowed(ExpiredGrantInertP)
NoAccessOutsideActiveGrant ==
    NoParentEscape /\ SecretsNeverReadable /\ ExpiredGrantInert
ReadNotImpliesWrite  == Allowed(ReadNotImpliesWriteP)
DotEnvOnlyViaFolderGrant == Allowed(DotEnvP)

FullAccessReadOnly ==
    \A i \in Used : grants[i].full => grants[i].access = "read"

NoGrantRootedInDenyList ==
    \A i \in Used : ~SpecSecret(grants[i].root)

FullAccessBounded ==
    \A i \in Used : grants[i].full =>
        (grants[i].exp # 0 /\ grants[i].exp <= grants[i].at + FullTTL)

\* Non-vacuity witnesses (expected to be VIOLATED; see README): some request
\* is allowed, some write is allowed, some read is allowed via full access.
SomethingAllowedNever == ~\E r \in Requests, op \in Ops : Decide(r, op).allowed
FullReadNever == ~\E r \in Requests : Decide(r, "read").allowed /\ Decide(r, "read").g.full
EnvAllowedNever == ~\E r \in Requests : r.res \in EnvFiles /\ Decide(r, "read").allowed

FullLive(i) == i \in Used /\ grants[i].full /\ SpecLive(grants[i], clock)

FullAccessExpires ==
    \A i \in 1..MaxGrants : [](FullLive(i) => <>~FullLive(i))
=============================================================================
