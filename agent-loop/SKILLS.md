---
created: 2026-09-30
branch: hup/s3-skill-loader
author: Larry Klosowski + Claude Opus 5.5
status: active
---

# Hermes instruction skills (HUP-S3.2)

Code: [`src/skills.rs`](src/skills.rs) (loader, index, `skill_load`) and
`agent-sidecar/src/sessions.rs` (session registration). Planset: citrate-core
`.agentile/planset/2026-09-30-hermes-upskill/02_ARCHITECTURE.md`, "Skill" row.

## What a skill is

An [agentskills.io](https://agentskills.io) directory: `<name>/SKILL.md` with YAML frontmatter
(`name`, `description`, optional `license`, `compatibility`, `metadata`, `allowed-tools`) and a
markdown body, plus optional bundled files (`references/`, `assets/`, `scripts/`).

Skills are instructions only. A skill can tell the model to call a gated tool; it cannot act.

## How Hermes uses them

| Piece | Behaviour |
|---|---|
| Index | One line per skill, `- name: description` (description cut to 120 chars), sorted, inside a token budget (sidecar default 1500). Omitted skills are counted in a final line. |
| `skill_load {name}` | Returns the body, then the skill's readable files and its scripts. |
| `skill_load {name, ref}` | Returns one listed file, at most 128 KiB, UTF-8 only. |
| Scripts | Listed and flagged `[script, not run]`. Never executed, never returned. |
| Pinning | `skill_load` is offered on every request, outside `maxToolsPerRequest`. |

## Configuring the sidecar

`CITRATE_HERMES_SKILLS` is a path list (`:` on unix, `;` on windows) in precedence order: the
first source wins a name clash. Unset or empty means no skills: sessions are unchanged and no
`skill_load` tool is registered. An empty library also registers nothing. While skills are on, a
core-supplied tool may not use the name `skill_load`.

## Validation (refused skills are logged to the sidecar's stderr, never sent to the model)

- Frontmatter must open the file and close with `---`. The whole file is at most 64 KiB.
- `name`: 1-64 chars of `a-z`, `0-9`, single inner hyphens; must equal its directory name.
- `description`: 1-1024 chars. `compatibility`: at most 500.
- Accepted YAML: plain or quoted scalars, `>`/`>-`/`|`/`|-` blocks, one-level maps (`metadata`)
  and lists. Anchors, aliases, tags, nesting, duplicate keys and unknown keys are refused.
  Claude Code extension keys (`argument-hint`, `disable-model-invocation`, `user-invocable`,
  `model`, `type`, `version`) are recorded and otherwise ignored.
- A name twice inside one source is ambiguous: every copy is refused. A name in a later source is
  shadowed and reported.
- Discovery skips hidden directories, stops at depth 6, 4096 directories and 512 skills per source.
- Bundled files: at most 64 listed, up to three directory levels deep. Symlinked directories are not followed; a symlinked
  file is listed only if it resolves inside the skill. A read must name a listed file and must
  still resolve inside the skill's directory at read time.

## Not done here

- Per-turn retrieval of five skills by embedding (planset: BGE index). The full index rides in the
  prompt for now, bounded by its token budget.
- Content hashing and `skills.lock` (S3.6 intake review), the memory-graph `skills` tenant (S3.1),
  and the SkillRegistry publish (S3.4).
- citrate-core's own local skills (`src-tauri/src/skills_local.rs`, flat `<slug>.md` files with
  free-form names) are not yet in this format. Moving them is a core change.
