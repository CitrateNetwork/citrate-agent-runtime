# citrate-agent-core

Shared agent primitives: tool registry, approval flow, budget tracking, audit trail, and emergency stop.

## Overview

The foundational types and traits for the Citrate agent system.
Every agent crate (`agent-chain`, `agent-code`, `agent-cron`) depends on this crate
and never on each other, keeping them composable. Tools implement the `AgentTool` trait,
register with a shared `ToolRegistry`, and execute through a risk-tiered approval flow.

## Modules

- `tool` -- `AgentTool` trait, `ToolRegistry`, `ToolResult`, `ToolContext`, and `RiskLevel` enum (Low/Medium/High/Critical)
- `approval` -- `ApprovalFlow` with risk-tiered human-in-the-loop gating and `ApprovalHandler` callback trait
- `budget` -- `BudgetTracker` enforcing per-session limits on tokens, cost (microdollars), tool calls, and wall-clock time
- `audit` -- `AuditTrail` append-only log of every tool execution with session filtering and JSON export
- `estop` -- `EmergencyStop` atomic kill switch shared across all agents via `Arc`
- `error` -- `AgentError` enum covering tool-not-found, denied, timeout, budget exceeded, and emergency stop

## Usage

```rust
use citrate_agent_core::tool::{ToolRegistry, AgentTool, RiskLevel, ToolContext, ToolResult};
use citrate_agent_core::budget::{BudgetTracker, BudgetConfig};
use citrate_agent_core::estop::EmergencyStop;
use std::sync::Arc;

let registry = ToolRegistry::new();
registry.register(Arc::new(my_tool)).await;

let estop = EmergencyStop::new();
estop.check()?; // returns Err if kill switch is active

let budget = BudgetTracker::new(BudgetConfig::default());
budget.record_tool_call()?;
```

## Tests

```bash
cargo test -p citrate-agent-core
```

Test count: 26 tests covering tool registration, tool execution, result constructors,
budget enforcement (tokens, cost, tool calls), audit trail recording/trimming/filtering,
emergency stop trigger/reset/clone, and approval flow.
