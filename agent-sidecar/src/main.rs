//! citrate-agent-sidecar — the binary citrate-core spawns as the keyless agent (installed as the
//! `hermes` sidecar). Config is via ENV; the bearer comes as a FILE PATH, never inline:
//!
//!   CITRATE_HERMES_ADDR         loopback control bind, e.g. 127.0.0.1:19700 (required)
//!   CITRATE_HERMES_TOKEN_FILE   path to the 0600 bearer-token file citrate-core wrote (required)
//!   CITRATE_HERMES_CAPSULES     capsule (skill) directory to load; default ./capsules (optional)
//!   CITRATE_HERMES_SKILLS       HUP-S3.2: SKILL.md instruction-skill directories, a path list in
//!                               precedence order (first wins); unset = no skills (optional)
//!   CITRATE_HERMES_TOOLCHAIN    HUP-S6.3: `1` offers forge_test / slither_scan / aderyn_scan /
//!                               medusa_fuzz in every session; anything else = off (optional)
//!   CITRATE_HERMES_TOOLCHAIN_ROOTS  granted project folders for those tools, a path list;
//!                               unset = every toolchain run is refused (optional)
//!   CITRATE_HERMES_TOOLCHAIN_PATH   toolchain search path override, a path list (optional)
//!   CITRATE_HERMES_SOLC         absolute path of the solc forge should use; default: the pinned
//!                               0.8.36 in the per-user svm dir when present (optional)
//!   CITRATE_HERMES_SHELL_SANDBOX  US-2.2 AC1: `preferred` (default) runs the toolchain inside
//!                               the OS sandbox (macOS Seatbelt, Linux bubblewrap) when one works
//!                               here; `required` refuses runs without one; `off` never wraps;
//!                               any other value counts as `required` (optional)
//!   CITRATE_HERMES_SHELL_RUN    US-2.2 AC2: `1` offers shell_run (an exact command the member
//!                               approves, run in the OS sandbox, never without it) in every
//!                               session opened with folder grants; anything else = off (optional)
//!   CITRATE_HERMES_SHELL_PATH   shell_run search path override, a path list (optional)
//!   CITRATE_HERMES_MCP          HUP-S4.1: path to the MCP server allowlist (TOML, or JSON by
//!                               `.json` extension); unset = no MCP (optional)
//!   CITRATE_HERMES_CHECKPOINTS  HUP-S2.9: absolute directory of the undo checkpoint store; set =
//!                               the /checkpoints undo routes are served, and sessions opened with
//!                               a grant document get checkpointed file_write / sheet_write plus
//!                               fs_write / fs_edit / fs_delete / fs_rename on that document; unset
//!                               = no agent file write at all (optional)
//!   CITRATE_HERMES_FILES        HUP-S2.9: `1` also offers the fs_* tools in sessions opened
//!                               without a grant document; needs CITRATE_HERMES_GRANTS and the
//!                               checkpoint store, else off (optional)
//!   CITRATE_HERMES_GRANTS       absolute path of the folder-grants JSON core stores; read on every
//!                               file-tool call (optional)
//!   CITRATE_HERMES_METERING_DIR HUP-S7.5: absolute folder for the metering log (metering.jsonl);
//!                               unset = turn records are kept in memory only (optional)
//!   CITRATE_HERMES_TRAJECTORIES HUP-S9.3: absolute folder for verified, redacted trajectory
//!                               exports at session close; unset = no recording (optional, off)
//!   CITRATE_HERMES_RECORDS_DIR  HUP-S7.3: absolute folder of the HIC decision records to batch
//!   CITRATE_HERMES_ANCHOR_DIR   HUP-S7.3: absolute folder for the anchor ledger; both must be set
//!                               for the /anchor/* routes, else they answer "not configured"
//!                               (HUP-S2.3: POST /records/web-signing writes core's web-signing
//!                               decisions into CITRATE_HERMES_RECORDS_DIR; unset, it answers 404.
//!                               HUP-S2.6: set, the sidecar also records ceremony-bridge resolves,
//!                               browser action decisions, learn decisions and POST /records/core
//!                               (core's grant, full-access, escalation and approval-card events)
//!                               there, through one writer)
//!   CITRATE_HERMES_LEARN_DIR    HUP-S3.4: learn data folder (decision log + proposals file);
//!                               with CITRATE_HERMES_LEARN_SKILLS_DIR, turns on the learn routes
//!                               and the `learn_propose` tool; unset = learning off (optional)
//!   CITRATE_HERMES_LEARN_SKILLS_DIR  the member's skills folder, where an accepted skill is
//!                               written as <name>/SKILL.md (optional, see above)
//!   CITRATE_HERMES_SEARCH       HUP-S5.2: `1` offers web_search + read_url in every session (optional)
//!   CITRATE_HERMES_SEARXNG      absolute path of searxng-run (or its virtualenv); unset = web_search
//!                               reports "not installed" (optional)
//!   CITRATE_HERMES_SEARXNG_DATA folder for SearXNG's generated settings + log (optional)
//!   CITRATE_HERMES_READER       `jina` opts read_url in to the third-party Jina Reader; anything else
//!                               = local readability (optional)
//!   CITRATE_HERMES_JINA_ENDPOINT / CITRATE_HERMES_JINA_KEY_FILE  Jina Reader base URL / key file
//!   CITRATE_HERMES_JEV          HUP-S5.3: `1` turns the opt-in Jev decide() backend on, still per
//!                               origin (CITRATE_HERMES_JEV_ORIGINS, CITRATE_HERMES_JEV_NON_WEB) and
//!                               only with CITRATE_HERMES_JEV_KEY_FILE (optional)
//!   CITRATE_HERMES_DECIDE_LOG   JSONL file for decide() metering (optional)
//!   CITRATE_HERMES_BROWSER      HUP-S5.1: `1` offers the browser_* tools in every session and
//!                               serves the /browser control routes; anything else = off (optional)
//!   CITRATE_BROWSER_CHROMIUM    the managed Chromium executable (installed by the component
//!                               updater); unset = a system Chromium if one exists (optional)
//!
//! HUP-S1.9: `citrate-agent-sidecar --worker toolchain` runs this binary as the toolchain worker
//! process instead (stdio line protocol, started and supervised by the control-plane process; it
//! reads the same `CITRATE_HERMES_TOOLCHAIN*` variables). On SIGTERM or Ctrl-C the control plane
//! stops accepting requests and shuts its workers down cleanly before exiting.

use std::sync::Arc;

use agent_sidecar::{app, load_dispatch, load_skills, AppState};
use citrate_agent_core::hitl::ApprovalQueue;
use citrate_agent_legacy::estop::EmergencyStop;

fn required(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("{key} is required"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(agent_sidecar::workers::WORKER_ARG) {
        let kind = args.get(1).map(String::as_str).unwrap_or("");
        std::process::exit(agent_sidecar::workers::run_worker(kind));
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(control_plane())
}

/// Resolves on SIGTERM (how citrate-core's supervisor stops the sidecar) or Ctrl-C.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn control_plane() -> Result<(), Box<dyn std::error::Error>> {
    let addr = required("CITRATE_HERMES_ADDR")?;
    let token_file = required("CITRATE_HERMES_TOKEN_FILE")?;
    let bearer = std::fs::read_to_string(&token_file)
        .map_err(|e| format!("reading bearer file {token_file}: {e}"))?
        .trim()
        .to_string();
    if bearer.is_empty() {
        return Err("bearer file is empty (fail closed)".into());
    }
    let capsule_dir =
        std::env::var("CITRATE_HERMES_CAPSULES").unwrap_or_else(|_| "capsules".to_string());
    let capsule_path = std::path::Path::new(&capsule_dir);
    let skills = load_skills(capsule_path);
    let queue = Arc::new(ApprovalQueue::new());
    // The dispatch carries the QueuedApprovalGate over `queue`, so a skill's chain effect surfaces on
    // the same queue /approvals + /status read.
    let dispatch = load_dispatch(capsule_path, queue.clone());
    // PBA-L6b-015 / HUP-S2.5: list only skills the dispatch will actually run (a refused or
    // unverified capsule is not a skill; with no dispatch nothing runs).
    let skills = agent_sidecar::runnable_skills(skills, dispatch.as_deref());

    // MCP servers are started and handshaken off the async runtime (blocking I/O).
    let mcp = tokio::task::spawn_blocking(agent_sidecar::mcp_from_env)
        .await
        .ok()
        .flatten();

    let state = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue,
        skills,
        dispatch,
        bearer,
        run_slots: Arc::new(tokio::sync::Semaphore::new(
            agent_sidecar::MAX_CONCURRENT_SKILLS,
        )),
        sessions: agent_sidecar::production_sessions_with(mcp),
    });

    // AR-B-024: the control plane is a bearer-authed LOOPBACK plane by contract.
    // Refuse to bind a non-loopback address (e.g. 0.0.0.0) unless the operator
    // explicitly opts in via CITRATE_HERMES_ALLOW_NONLOOPBACK=1, so a
    // misconfiguration cannot silently expose run_skill/approve to the network.
    let allow_nonloopback = std::env::var("CITRATE_HERMES_ALLOW_NONLOOPBACK").as_deref() == Ok("1");
    agent_sidecar::enforce_loopback_bind(&addr, allow_nonloopback)?;

    eprintln!(
        "citrate-agent-sidecar: {} skills, control on {}",
        state.skills.len(),
        addr
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    // HUP-S1.9: on SIGTERM / Ctrl-C, stop the worker processes first (each gets a shutdown
    // request and a grace period, well inside core's 5 s stop grace), then let the server drain.
    // Off the async runtime: it joins the supervisor threads.
    let sessions = state.sessions.clone();
    let served = axum::serve(listener, app(state.clone()))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = tokio::task::spawn_blocking(move || sessions.shutdown_workers()).await;
        })
        .await;
    // Idempotent: covers a server that ended without a signal.
    let sessions = state.sessions.clone();
    let _ = tokio::task::spawn_blocking(move || sessions.shutdown_workers()).await;
    served?;
    Ok(())
}
