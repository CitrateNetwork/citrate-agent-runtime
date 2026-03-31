# citrate-agent-cron

Cron scheduling and Standard Operating Procedures (SOPs) for the Citrate agent system.

## Overview

This crate provides time-based job scheduling and multi-step automated workflows.
The `CronScheduler` evaluates 6-field cron expressions (second, minute, hour,
day-of-month, month, day-of-week) and determines which jobs are due on each tick.
The `SOPEngine` registers and executes named sequences of tool invocations with
conditional step logic and optional `ApprovalFlow` enforcement. Built-in Citrate
SOPs provide chain monitoring and health check procedures.

## Modules

- `scheduler` -- `CronScheduler` and `CronJob` with cron expression parsing (wildcards, ranges, steps)
- `sop` -- `SOPEngine`, `SOPDefinition`, `SOPStep`, and `SOPTrigger` (Cron, Webhook, Event, Manual)
- `citrate_sops` -- Pre-configured SOPs for Citrate operations
  - `chain_monitor` -- Chain state monitoring SOP
  - `health_check` -- Node health check SOP

## Usage

```rust
use citrate_agent_cron::scheduler::{CronScheduler, CronJob};
use citrate_agent_cron::sop::{SOPEngine, SOPDefinition, SOPStep, SOPTrigger};

let scheduler = CronScheduler::new();
scheduler.add_job(CronJob {
    id: "health".into(),
    name: "Health Check".into(),
    schedule: "0 */5 * * * *".into(), // every 5 minutes
    tool_name: "check_balance".into(),
    params: serde_json::json!({}),
    enabled: true,
    last_run: None,
}).await?;

let due_jobs = scheduler.tick_now().await;

let engine = SOPEngine::new();
let outcome = engine.execute("my_sop", &registry, &ctx, None).await?;
```

## Tests

```bash
cargo test -p citrate-agent-cron
```

Test count: 36 tests covering scheduler CRUD, cron expression matching (wildcard,
exact, range, step), tick evaluation, disabled job skipping, last_run updates,
SOP registration, sequential execution, failure abort, conditional step skip/pass,
disabled SOP rejection, and trigger serialization.
