---
created: 2026-10-01
branch: hup/n4-personas
author: Larry Klosowski + Claude Opus 5.5
status: active (persona names pending owner sign-off)
---

# Personas, tracks and track workflows (HUP-S3.3 + S3.7)

Code: [`src/personas.rs`](src/personas.rs), [`src/workflows.rs`](src/workflows.rs),
[`src/interview.rs`](src/interview.rs) (tracks). Data: [`personas/personas.toml`](personas/personas.toml),
[`tracks/workflows.toml`](tracks/workflows.toml), `tracks/*.toml`. Tests:
[`tests/persona_tests.rs`](tests/persona_tests.rs),
[`tests/track_workflow_bdd_tests.rs`](tests/track_workflow_bdd_tests.rs) and
`agent-sidecar/src/personas_route_tests.rs`. Planset: citrate-core
`.agentile/planset/2026-09-30-hermes-upskill/` (US-3.3 in `04_FEATURES_BDD.md`, D-9 and D-10 in
`00_OVERVIEW.md`, names in `09_PERSONAS_DRAFT.md`).

## The model

- A **persona** is a voice: writing-style rules rendered into a system-prompt fragment, a default
  track and workflow, a tool emphasis, a skill allowlist, and an optional TTS voice id.
- A **track** is a goal. It owns an interview and a **workflow family**. Any persona can run any
  track.
- A **workflow** is a list of steps, each judged by verifiers. Only verifiers say done.

## Persona names: placeholders pending owner sign-off

| id | Role | Placeholder name | Default track | Default workflow |
|---|---|---|---|---|
| `builder` | Builder | Graft | full-project | hello-mint |
| `auditor` | Auditor | Pith | smart-contract | audit-a-contract |
| `maker` | Maker | Zest | creative | creative-project |
| `steward` | Steward | Trellis | project-management | project-plan |
| `guide` | Guide | Sprout | full-project | launch-checklist |
| `operator` | Operator | Crew | project-management | status-note |

Each name is the first candidate in the draft that does not collide with an existing brand or
product name. "Ledger" (Steward) and "Hive" (Operator) were skipped for that reason. To rename,
change the one `name = "..."` line in `personas/personas.toml` and set `name_status` to
`owner-approved`. The id does not change, so a member's saved choice survives the rename.

Guide and Operator have no dedicated track among the five launch tracks; they default to the
nearest family (the hello-mint path as a learning checklist, and the status note). This is an
owner call to confirm.

No persona sets `tts_voice`. Unset means the system voice. A value is a voice id the platform's
existing speech engine knows; personas add no speech engine. Nothing passes it to the speech
engine yet, so clients show a set value as stored, not used.

## The fragment

`Persona::prompt_fragment()` renders a fixed template: the name, role summary, voice, tone, the
style rules as a list, the tool emphasis, and a closing line that the persona shapes tone and
wording only and never changes approval, gate, safety or signing rules. Clients append it after
their own system prompt. Member text in a custom persona is collapsed to one line per field, so it
cannot open a new heading.

## Custom personas (US-3.3 AC3)

`CustomPersona::check()` validates a member-defined persona: id `custom-<slug>`, a name that is not
a shipped persona's name, 1 to 12 style rules of at most 300 characters, a bundled default track,
identifier-shaped tool names and slug skill names. Its default workflow is its track's default.
The sidecar exposes it as `POST /personas/check`; citrate-core stores the accepted persona with the
member's local settings.

## Sidecar routes (bearer-gated)

| Route | Returns |
|---|---|
| `GET /personas` | every shipped persona, its `prompt_fragment`, `name_pending_sign_off` |
| `POST /personas/check` `{persona}` | the custom persona's view with its fragment, or 422 with the reason |
| `GET /workflows` | every track's workflows: steps, verifier names, tools, `evidence`, `is_default` |

## Track workflows

| Track | Workflows (default first) | Evidence |
|---|---|---|
| Creative | creative-project, copy-pass | answer-shape |
| Code | code-change, solidity-red-green | answer-shape, tool-report |
| Smart contract + business logic | contract-build, audit-a-contract | tool-report |
| Project management | project-plan, status-note | answer-shape, tool-report |
| Full project | hello-mint, launch-checklist | tool-report, answer-shape |

`tool-report` workflows are judged by the toolchain's own reports (forge, slither, aderyn, medusa)
or a tool's result. `answer-shape` workflows check the answer's structure and guard tools that
must not run (no deploy, no journal write before approval); they are weaker by design, and the app
labels them. No session route runs workflows yet, so each track keeps `workflow_available = false`.
The hello-mint anvil-fork dry run and deploy belong to the deploy gate (HUP-S6.4), not this list.

## BDD, one scenario group per track

```gherkin
Feature: Personas and tracks (US-3.3)

  Background:
    Given the shipped personas and the five launch tracks

  Scenario: Creative, the Maker offers directions and waits for review
    Given the member picks the Creative track
    When they take the interview defaults
    Then the brief names the "creative-project" workflow
    And the workflow passes only when the answer offers Option 1, Option 2 and Option 3
    And the draft ends with "Review before publishing"
    And nothing is deployed
    But a model that only says "done" does not finish it

  Scenario: Code, the change starts from a named failing test
    Given the member picks the Code track
    When they take the interview defaults
    Then the brief names the "code-change" workflow
    And the workflow passes only when the plan names the test and the report shows Red and Green
    But a model that only says "done" does not finish it

  Scenario: Smart contract, the toolchain is the judge
    Given the member picks the Smart contract track
    When the model runs forge_test, slither_scan, aderyn_scan and medusa_fuzz
    Then the workflow finishes only when forge reports every test passing,
      slither and aderyn report nothing at High or above, and medusa breaks no invariant
    And a High slither finding fails the workflow whatever the model says
    And contract_deploy is never called inside the workflow

  Scenario: Project management, the plan comes before any write
    Given the member picks the Project management track
    When they take the interview defaults
    Then the brief names the "project-plan" workflow
    And the plan names milestones and gates
    And journal_append is never called before the member approves

  Scenario: Full project, hello-mint ends at the ceremony
    Given the member picks the Full project track
    When the contract is tested, scanned and fuzzed
    Then the last step is a deploy plan that names the SignatureCeremony
    And contract_deploy is never called inside the workflow

  Scenario: A member defines a custom persona
    Given a custom persona "Night Owl" on the Code track
    When it is checked
    Then its fragment carries its voice and rules and the safety line
    And a custom persona cannot take a shipped persona's name
```

Each scenario maps to a test in `tests/track_workflow_bdd_tests.rs` (`track_<id>_...`) or
`tests/persona_tests.rs`. The satisfying run is generated from the workflow's own verifiers, so a
new workflow is covered by `every_secondary_workflow_also_finishes_on_a_satisfying_run` as soon as
it is added to the catalog.
