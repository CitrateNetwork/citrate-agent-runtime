//! HUP-S7.5 / US-7.3 AC1 (D-27): sampling the machine while a Hermes turn runs.
//!
//! [`SystemSampler`] is the sidecar's [`ResourceSampler`]: for each turn it starts one background
//! thread that reads the whole machine every [`SAMPLE_INTERVAL`] until the turn's `done`:
//!
//! - CPU busy share and RAM in use from the OS through `sysinfo` (system-wide: the model server
//!   is a separate process, and its load is what a member wants to see);
//! - GPU busy share where the OS reports one: macOS `ioreg` (`IOAccelerator`
//!   `PerformanceStatistics` "Device Utilization %"), elsewhere `nvidia-smi`. A machine with
//!   neither leaves the GPU unknown (never zero), and is not probed again.
//!
//! Read-only: nothing here writes, signs or leaves the machine. A turn shorter than one interval
//! has no samples, so its peaks are unknown rather than guessed.
//!
//! `CITRATE_HERMES_RESOURCE_SAMPLING=0` turns sampling off. `CITRATE_HERMES_ENERGY_WATTS=cpu,gpu`
//! sets the nominal watts behind the energy estimate (defaults pending owner sign-off).

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use citrate_agent_metering::{
    EnergyModel, ResourcePeaks, ResourceSample, ResourceSampler, TurnSampling, BPS_WHOLE,
    DEFAULT_ENERGY_MODEL,
};

/// How often a running turn is sampled.
pub const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);
/// The longest one GPU reading may take before it is abandoned.
pub const GPU_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Environment switch for sampling (`0`, `false` or `off` turn it off).
pub const RESOURCE_SAMPLING_ENV: &str = "CITRATE_HERMES_RESOURCE_SAMPLING";
/// Environment override for the energy estimate's nominal watts, `cpu,gpu` (for example `25,40`).
pub const ENERGY_WATTS_ENV: &str = "CITRATE_HERMES_ENERGY_WATTS";
/// Samples kept per turn (a very long turn keeps its first ones; peaks of the rest are lost).
pub const MAX_SAMPLES_PER_TURN: usize = 7_200;

/// Whether the env value turns sampling on (unset: on).
pub fn sampling_from_value(v: Option<&str>) -> bool {
    !matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

/// The energy model from `cpu,gpu` watts; anything malformed keeps the default.
pub fn energy_model_from_value(v: Option<&str>) -> EnergyModel {
    let parsed = v.and_then(|s| {
        let (c, g) = s.split_once(',')?;
        let c: u32 = c.trim().parse().ok()?;
        let g: u32 = g.trim().parse().ok()?;
        (c <= 2_000 && g <= 2_000).then_some(EnergyModel {
            cpu_watts: c,
            gpu_watts: g,
        })
    });
    parsed.unwrap_or(DEFAULT_ENERGY_MODEL)
}

/// The highest "Device Utilization %" in `ioreg -r -d 1 -c IOAccelerator` output, as basis points.
pub fn parse_ioreg_gpu(out: &str) -> Option<u32> {
    const KEY: &str = "\"Device Utilization %\"=";
    let mut best: Option<u32> = None;
    let mut rest = out;
    while let Some(i) = rest.find(KEY) {
        rest = &rest[i + KEY.len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(pct) = digits.parse::<u32>() {
            let bps = pct.min(100) * 100;
            best = Some(best.map_or(bps, |b| b.max(bps)));
        }
    }
    best
}

/// The highest utilization in `nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits`
/// output (one integer percent per GPU), as basis points.
pub fn parse_nvidia_smi_gpu(out: &str) -> Option<u32> {
    out.lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .map(|pct| pct.min(100) * 100)
        .max()
}

/// Run a read-only probe with a deadline; its stdout when it exits successfully in time.
fn run_probe(program: &str, args: &[&str]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + GPU_READ_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut out = String::new();
                let mut pipe = child.stdout.take()?;
                std::io::Read::read_to_string(&mut pipe, &mut out).ok()?;
                return Some(out);
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// One GPU reading from the OS, in basis points, or `None` when the machine does not report one.
pub fn read_gpu_bps() -> Option<u32> {
    if cfg!(target_os = "macos") {
        run_probe("ioreg", &["-r", "-d", "1", "-c", "IOAccelerator"])
            .and_then(|o| parse_ioreg_gpu(&o))
    } else {
        run_probe(
            "nvidia-smi",
            &[
                "--query-gpu=utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
        )
        .and_then(|o| parse_nvidia_smi_gpu(&o))
    }
}

/// CPU busy percent (0..=100 per the whole machine) as basis points, clamped.
fn pct_to_bps(pct: f32) -> u32 {
    if !pct.is_finite() || pct <= 0.0 {
        return 0;
    }
    let bps = (pct * 100.0).round();
    if bps >= BPS_WHOLE as f32 {
        BPS_WHOLE
    } else {
        bps as u32
    }
}

/// The sidecar's machine sampler (see the module docs).
pub struct SystemSampler {
    interval: Duration,
    /// Cleared after the first GPU read fails, so a machine without a reading is not probed again.
    gpu_readable: Arc<AtomicBool>,
}

impl SystemSampler {
    pub fn new() -> Self {
        Self::with_interval(SAMPLE_INTERVAL)
    }

    pub fn with_interval(interval: Duration) -> Self {
        SystemSampler {
            interval,
            gpu_readable: Arc::new(AtomicBool::new(true)),
        }
    }

    /// The sampler `CITRATE_HERMES_RESOURCE_SAMPLING` asks for (`None` when it is off).
    pub fn from_env() -> Option<Arc<dyn ResourceSampler>> {
        sampling_from_value(std::env::var(RESOURCE_SAMPLING_ENV).ok().as_deref())
            .then(|| Arc::new(SystemSampler::new()) as Arc<dyn ResourceSampler>)
    }
}

impl Default for SystemSampler {
    fn default() -> Self {
        Self::new()
    }
}

struct SystemSampling {
    samples: Arc<Mutex<Vec<ResourceSample>>>,
    stop: Arc<AtomicBool>,
}

// A sampling dropped without `finish` (its sink went away with the turn still open) stops its
// thread too, so no thread reads the machine for a turn nobody will close.
impl Drop for SystemSampling {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl TurnSampling for SystemSampling {
    fn finish(self: Box<Self>) -> Option<ResourcePeaks> {
        // Signal and return without joining: the thread exits on its next tick, and a turn's
        // `done` never waits on a probe.
        self.stop.store(true, Ordering::SeqCst);
        let samples = match self.samples.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        };
        ResourcePeaks::from_samples(&samples)
    }
}

impl SystemSampler {
    /// Start one turn's sampling thread.
    fn start(&self) -> SystemSampling {
        let samples = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (out, flag, gpu_ok, interval) = (
            samples.clone(),
            stop.clone(),
            self.gpu_readable.clone(),
            self.interval,
        );
        // A thread that cannot start leaves this turn unsampled (unknown), never failed.
        let _ = std::thread::Builder::new()
            .name("hermes-metering-sampler".into())
            .spawn(move || sample_until_stopped(&out, &flag, &gpu_ok, interval));
        SystemSampling { samples, stop }
    }
}

impl ResourceSampler for SystemSampler {
    fn begin(&self) -> Box<dyn TurnSampling> {
        Box::new(self.start())
    }
}

fn sample_until_stopped(
    out: &Mutex<Vec<ResourceSample>>,
    stop: &AtomicBool,
    gpu_ok: &AtomicBool,
    interval: Duration,
) {
    let mut sys = sysinfo::System::new();
    // CPU usage is a difference between two refreshes: take the baseline now.
    sys.refresh_cpu_usage();
    let step = Duration::from_millis(25);
    loop {
        let wake = Instant::now() + interval;
        while Instant::now() < wake {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(step);
        }
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        let gpu_bps = if gpu_ok.load(Ordering::SeqCst) {
            let g = read_gpu_bps();
            if g.is_none() {
                gpu_ok.store(false, Ordering::SeqCst);
            }
            g
        } else {
            None
        };
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let s = ResourceSample {
            cpu_bps: pct_to_bps(sys.global_cpu_usage()),
            ram_used_bytes: sys.used_memory(),
            ram_total_bytes: sys.total_memory(),
            gpu_bps,
        };
        let mut v = match out.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if v.len() < MAX_SAMPLES_PER_TURN {
            v.push(s);
        }
    }
}

#[cfg(test)]
#[path = "resources_tests.rs"]
mod tests;
