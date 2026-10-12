//! The OS sandbox layer (US-2.2 AC1): every run can be wrapped in an operating-system sandbox
//! with no network, writes only in the granted folders and a per-run scratch HOME, and reads
//! limited to those folders plus the system and toolchain directories a program needs to start.
//!
//! Backends:
//!
//! - **macOS: Seatbelt** through `/usr/bin/sandbox-exec`. The profile is generated per run
//!   ([`seatbelt_profile`]) and starts from `(deny default)`. It never allows a network
//!   operation. Every path is passed as a `-D` parameter, never spliced into the profile text,
//!   so a folder name cannot change the policy. Writes to `.git/hooks`, `.git/config` and
//!   `.env*` files are denied even inside a granted folder (a hook planted there would run later
//!   outside the sandbox).
//! - **Linux: bubblewrap** (`bwrap`, found only in fixed system directories). The run gets fresh
//!   namespaces with networking unshared (`--unshare-all`), read-only binds of the system and
//!   toolchain directories, writable binds of the granted folders and the scratch HOME, and
//!   read-only masks over `.git/hooks`, `.git/config` and the `.env*` files that exist at the top
//!   of a granted folder ([`bwrap_command`]). A Landlock fallback is not implemented: with no
//!   working `bwrap` the backend is unavailable.
//! - **Windows**: the runner builds and uses a Job Object for bounded process cleanup, but has
//!   no OS sandbox backend. A Job Object is cleanup containment, not a filesystem, network, or
//!   security sandbox, so [`SandboxMode::Required`] refuses the run.
//!
//! Detection ([`detect`]) probes the backend once per process by running `true` inside it, so a
//! `bwrap` that is installed but cannot create namespaces (for example where unprivileged user
//! namespaces are disabled) is reported unavailable with its reason instead of failing at run
//! time.
//!
//! [`SandboxMode::Required`] fails closed: no backend means the run is refused before anything
//! starts. [`SandboxMode::Preferred`] uses a backend when there is one and otherwise runs as
//! before, with the report saying the run was not isolated. [`SandboxMode::Off`] never wraps.

use serde::Serialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Whether runs must, may, or must not be wrapped in the OS sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// Never wrap (the report says the run was not isolated).
    Off,
    /// Wrap when a backend works on this machine; otherwise run as before and say so.
    Preferred,
    /// Wrap, or refuse the run before anything starts (fail closed).
    Required,
}

impl SandboxMode {
    /// `required`, `preferred` or `off` (any case). Anything else is `None`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "required" => Some(SandboxMode::Required),
            "preferred" => Some(SandboxMode::Preferred),
            "off" => Some(SandboxMode::Off),
            _ => None,
        }
    }
}

/// A working sandbox program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// macOS Seatbelt through `sandbox-exec`.
    Seatbelt { exe: PathBuf },
    /// Linux bubblewrap.
    Bwrap { exe: PathBuf },
}

impl Backend {
    /// A short stable name for reports.
    pub fn name(&self) -> &'static str {
        match self {
            Backend::Seatbelt { .. } => "seatbelt",
            Backend::Bwrap { .. } => "bwrap",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Backend::Seatbelt { .. } => "macOS Seatbelt",
            Backend::Bwrap { .. } => "Linux bubblewrap",
        }
    }
}

/// How a [`crate::ShellPolicy`] sandboxes its runs.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    mode: SandboxMode,
    extra_read_roots: Vec<PathBuf>,
    /// `None`: detect the backend on this machine. `Some`: use this answer instead (tests, and
    /// hosts that detected once already).
    backend: Option<Result<Backend, String>>,
}

impl SandboxPolicy {
    pub fn new(mode: SandboxMode) -> Self {
        Self {
            mode,
            extra_read_roots: Vec::new(),
            backend: None,
        }
    }

    /// No sandbox (the default of a [`crate::ShellPolicy`]).
    pub fn off() -> Self {
        Self::new(SandboxMode::Off)
    }

    /// Absolute directories (or files) the sandboxed program may also read, for example a
    /// compiler binary outside the search path. Relative entries are dropped.
    pub fn with_extra_read_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.extra_read_roots = roots.into_iter().filter(|p| p.is_absolute()).collect();
        self
    }

    /// Use this backend answer instead of detecting one.
    pub fn with_backend(mut self, backend: Result<Backend, String>) -> Self {
        self.backend = Some(backend);
        self
    }

    pub fn mode(&self) -> SandboxMode {
        self.mode
    }

    pub fn extra_read_roots(&self) -> &[PathBuf] {
        &self.extra_read_roots
    }

    /// The backend runs would use, or why there is none. `Off` always answers `Err`.
    pub fn backend(&self) -> Result<Backend, String> {
        if self.mode == SandboxMode::Off {
            return Err("the OS sandbox is off by configuration".to_string());
        }
        match &self.backend {
            Some(b) => b.clone(),
            None => detect(),
        }
    }
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self::off()
    }
}

/// What a run's sandbox is (or would be): shown on the approval card and kept in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxSummary {
    /// `seatbelt`, `bwrap`, or `none`.
    pub backend: String,
    /// The run is (or was) wrapped in the OS sandbox.
    pub enforced: bool,
    /// `denied` when enforced, otherwise `allowed`.
    pub network: String,
    /// Folders the program may write (the scratch HOME is listed by name).
    pub writable: Vec<String>,
    /// Directories beyond the system set the program may read (search path, toolchain).
    pub readable_extra: Vec<String>,
    /// One line for a person.
    pub summary: String,
}

/// The scratch HOME as it is listed in [`SandboxSummary::writable`].
pub const SCRATCH_LABEL: &str = "scratch HOME (deleted after the run)";

impl SandboxSummary {
    pub(crate) fn enforced(backend: &Backend, writable: &[PathBuf], extra: &[PathBuf]) -> Self {
        let folders: Vec<String> = writable.iter().map(|p| p.display().to_string()).collect();
        let summary = format!(
            "{}: no network; writes only in {} and a scratch HOME; reads limited to these folders, the system and the toolchain directories",
            backend.label(),
            folders.join(", ")
        );
        let mut w = folders;
        w.push(SCRATCH_LABEL.to_string());
        SandboxSummary {
            backend: backend.name().to_string(),
            enforced: true,
            network: "denied".to_string(),
            writable: w,
            readable_extra: extra.iter().map(|p| p.display().to_string()).collect(),
            summary,
        }
    }

    pub(crate) fn not_enforced(reason: &str, writable: &[PathBuf]) -> Self {
        let mut w: Vec<String> = writable.iter().map(|p| p.display().to_string()).collect();
        w.push(SCRATCH_LABEL.to_string());
        SandboxSummary {
            backend: "none".to_string(),
            enforced: false,
            network: "allowed".to_string(),
            writable: w,
            readable_extra: Vec::new(),
            summary: format!("no OS sandbox ({reason}); the run is not isolated from the network or other folders"),
        }
    }
}

/// Everything a backend needs for one run. Every path is absolute and canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The granted folders the program may write (and read).
    pub write_roots: Vec<PathBuf>,
    /// Directories (or files) beyond the system set it may read.
    pub read_roots: Vec<PathBuf>,
    /// The per-run scratch HOME / TMPDIR.
    pub scratch: PathBuf,
    /// Where the program starts.
    pub cwd: PathBuf,
    /// Files inside the write roots that are made unreadable and unwritable (bwrap masks them
    /// with `/dev/null`; Seatbelt denies them by pattern instead).
    pub masked_files: Vec<PathBuf>,
}

// ------------------------------------------------------------------------------------------
// Detection
// ------------------------------------------------------------------------------------------

const SEATBELT_EXE: &str = "/usr/bin/sandbox-exec";
const BWRAP_LOCATIONS: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];
const TRUE_LOCATIONS: &[&str] = &["/usr/bin/true", "/bin/true"];

static DETECTED: OnceLock<Result<Backend, String>> = OnceLock::new();

/// The backend that works on this machine, probed once per process.
pub fn detect() -> Result<Backend, String> {
    DETECTED.get_or_init(probe).clone()
}

fn true_program() -> Option<&'static str> {
    TRUE_LOCATIONS
        .iter()
        .copied()
        .find(|p| Path::new(p).is_file())
}

fn probe() -> Result<Backend, String> {
    if cfg!(windows) {
        return Err(
            "no OS sandbox backend is implemented for Windows (neither Seatbelt nor bubblewrap exists there)"
                .to_string(),
        );
    }
    let Some(truth) = true_program() else {
        return Err("no `true` program to probe the sandbox with".to_string());
    };
    if cfg!(target_os = "macos") {
        let exe = PathBuf::from(SEATBELT_EXE);
        if !exe.is_file() {
            return Err(format!("{SEATBELT_EXE} is not present"));
        }
        let ok = run_probe(Command::new(&exe).args(["-p", "(version 1)(allow default)", truth]))?;
        return if ok {
            Ok(Backend::Seatbelt { exe })
        } else {
            Err(format!("{SEATBELT_EXE} could not apply a profile"))
        };
    }
    if cfg!(target_os = "linux") {
        let Some(exe) = BWRAP_LOCATIONS
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
        else {
            return Err(
                "bubblewrap (bwrap) is not installed in /usr/bin, /bin or /usr/local/bin, and the Landlock fallback is not implemented"
                    .to_string(),
            );
        };
        let ok = run_probe(Command::new(&exe).args([
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            truth,
        ]))?;
        return if ok {
            Ok(Backend::Bwrap { exe })
        } else {
            Err(format!(
                "{} is installed but could not create a sandbox here (unprivileged user namespaces may be disabled)",
                exe.display()
            ))
        };
    }
    Err("no OS sandbox backend exists for this operating system".to_string())
}

fn run_probe(cmd: &mut Command) -> Result<bool, String> {
    cmd.env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .map_err(|e| format!("the sandbox probe could not start: {e}"))
}

// ------------------------------------------------------------------------------------------
// Seatbelt
// ------------------------------------------------------------------------------------------

/// System locations a macOS program needs to start (libraries, frameworks, the dyld cache,
/// locale and timezone data, `/dev`), plus the usual toolchain prefixes.
pub const MACOS_SYSTEM_READ: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library/Frameworks",
    "/Library/Developer/CommandLineTools",
    "/Applications/Xcode.app/Contents/Developer",
    "/private/etc",
    "/private/var/db/timezone",
    "/private/var/db/dyld",
    "/private/var/select",
    "/dev",
    "/opt/homebrew",
    "/usr/local",
];

/// The Seatbelt profile for a run with `n_read` extra read roots (`R0`..) and `n_write` write
/// roots (`W0`..). The scratch HOME is `S` and the system read set is `Y0`..; every path is a
/// `-D` parameter.
pub fn seatbelt_profile(n_read: usize, n_write: usize) -> String {
    let mut p = String::from("(version 1)\n(deny default)\n");
    p.push_str("(allow process-fork)\n(allow process-exec)\n");
    p.push_str("(allow signal (target same-sandbox))\n(allow sysctl-read)\n");
    // Existence and attributes of any path (path resolution needs it); contents are not.
    p.push_str("(allow file-read-metadata)\n");
    p.push_str(
        "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\") (global-name \"com.apple.system.notification_center\") (global-name \"com.apple.system.logger\"))\n",
    );
    p.push_str(
        "(allow ipc-posix-shm-read-data (ipc-posix-name \"apple.shm.notification_center\"))\n",
    );
    p.push_str("(allow file-read* (literal \"/\")");
    for i in 0..MACOS_SYSTEM_READ.len() {
        p.push_str(&format!(" (subpath (param \"Y{i}\"))"));
    }
    p.push_str(")\n");
    p.push_str("(allow file-read* (subpath (param \"S\"))");
    for i in 0..n_read {
        p.push_str(&format!(" (subpath (param \"R{i}\"))"));
    }
    for i in 0..n_write {
        p.push_str(&format!(" (subpath (param \"W{i}\"))"));
    }
    p.push_str(")\n");
    p.push_str("(allow file-write* (subpath (param \"S\"))");
    for i in 0..n_write {
        p.push_str(&format!(" (subpath (param \"W{i}\"))"));
    }
    p.push_str(")\n");
    p.push_str(
        "(allow file-write-data (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/dtracehelper\"))\n",
    );
    p.push_str("(allow file-ioctl (literal \"/dev/dtracehelper\"))\n");
    // Later rules win: these hold even inside a granted folder.
    p.push_str("(deny file-write* (regex #\"/\\.git/hooks(/|$)\") (regex #\"/\\.git/config$\"))\n");
    p.push_str("(deny file-read* file-write* (regex #\"/\\.env[^/]*$\"))\n");
    p
}

/// The `sandbox-exec` argv (after the executable) for one run.
pub fn seatbelt_command(spec: &SandboxSpec, program: &Path, args: &[String]) -> Vec<OsString> {
    let mut a: Vec<OsString> = vec![
        "-p".into(),
        seatbelt_profile(spec.read_roots.len(), spec.write_roots.len()).into(),
    ];
    let mut param = |k: String, v: &Path| {
        let mut s = OsString::from(format!("{k}="));
        s.push(v.as_os_str());
        a.push("-D".into());
        a.push(s);
    };
    for (i, y) in MACOS_SYSTEM_READ.iter().enumerate() {
        param(format!("Y{i}"), Path::new(y));
    }
    param("S".to_string(), &spec.scratch);
    for (i, r) in spec.read_roots.iter().enumerate() {
        param(format!("R{i}"), r);
    }
    for (i, w) in spec.write_roots.iter().enumerate() {
        param(format!("W{i}"), w);
    }
    a.push(program.as_os_str().to_owned());
    a.extend(args.iter().map(OsString::from));
    a
}

// ------------------------------------------------------------------------------------------
// bubblewrap
// ------------------------------------------------------------------------------------------

/// System locations bound read-only on Linux (missing ones are skipped).
pub const LINUX_SYSTEM_READ: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt",
];

/// The `bwrap` argv (after the executable) for one run.
pub fn bwrap_command(spec: &SandboxSpec, program: &Path, args: &[String]) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();
    let mut push = |xs: &[&std::ffi::OsStr]| a.extend(xs.iter().map(|x| x.to_os_string()));
    push(&[
        "--unshare-all".as_ref(),
        "--die-with-parent".as_ref(),
        "--dev".as_ref(),
        "/dev".as_ref(),
        "--proc".as_ref(),
        "/proc".as_ref(),
        "--tmpfs".as_ref(),
        "/tmp".as_ref(),
    ]);
    for y in LINUX_SYSTEM_READ {
        push(&["--ro-bind-try".as_ref(), y.as_ref(), y.as_ref()]);
    }
    for r in &spec.read_roots {
        push(&["--ro-bind-try".as_ref(), r.as_os_str(), r.as_os_str()]);
    }
    for w in &spec.write_roots {
        push(&["--bind".as_ref(), w.as_os_str(), w.as_os_str()]);
    }
    push(&[
        "--bind".as_ref(),
        spec.scratch.as_os_str(),
        spec.scratch.as_os_str(),
    ]);
    // Masks go after the writable binds, so they sit on top of them.
    for w in &spec.write_roots {
        for sub in [".git/hooks", ".git/config"] {
            let p = w.join(sub);
            push(&["--ro-bind-try".as_ref(), p.as_os_str(), p.as_os_str()]);
        }
    }
    for f in &spec.masked_files {
        push(&["--ro-bind".as_ref(), "/dev/null".as_ref(), f.as_os_str()]);
    }
    push(&["--chdir".as_ref(), spec.cwd.as_os_str(), "--".as_ref()]);
    a.push(program.as_os_str().to_owned());
    a.extend(args.iter().map(OsString::from));
    a
}

/// `.env*` files at the top of each write root (bwrap masks them; Seatbelt denies by pattern).
pub(crate) fn env_files(write_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for w in write_roots {
        let Ok(rd) = std::fs::read_dir(w) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            let is_file = e.file_type().map(|t| t.is_file()).unwrap_or(false);
            if is_file && (name == ".env" || name.starts_with(".env.")) {
                out.push(e.path());
            }
        }
    }
    out.sort();
    out
}

/// The command that runs `program` with `args` under `backend`.
pub(crate) fn wrap(
    backend: &Backend,
    spec: &SandboxSpec,
    program: &Path,
    args: &[String],
) -> Command {
    match backend {
        Backend::Seatbelt { exe } => {
            let mut c = Command::new(exe);
            c.args(seatbelt_command(spec, program, args));
            c
        }
        Backend::Bwrap { exe } => {
            let mut c = Command::new(exe);
            c.args(bwrap_command(spec, program, args));
            c
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parses() {
        assert_eq!(SandboxMode::parse("Required"), Some(SandboxMode::Required));
        assert_eq!(
            SandboxMode::parse(" preferred "),
            Some(SandboxMode::Preferred)
        );
        assert_eq!(SandboxMode::parse("off"), Some(SandboxMode::Off));
        assert_eq!(SandboxMode::parse("yes"), None);
    }

    #[test]
    fn off_never_yields_a_backend() {
        let p = SandboxPolicy::off().with_backend(Ok(Backend::Seatbelt {
            exe: PathBuf::from(SEATBELT_EXE),
        }));
        assert!(p.backend().is_err());
    }

    /// An absolute path on this platform (`/abs` has no drive, so it is relative on Windows).
    fn abs() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from("C:\\abs")
        } else {
            PathBuf::from("/abs")
        }
    }

    #[test]
    fn relative_extra_read_roots_are_dropped() {
        let p = SandboxPolicy::new(SandboxMode::Preferred)
            .with_extra_read_roots(vec![PathBuf::from("rel"), abs()]);
        assert_eq!(p.extra_read_roots(), &[abs()]);
    }

    #[test]
    fn seatbelt_argv_passes_paths_as_parameters() {
        let spec = SandboxSpec {
            write_roots: vec![PathBuf::from("/w/a\"b")],
            read_roots: vec![PathBuf::from("/r")],
            scratch: PathBuf::from("/s"),
            cwd: PathBuf::from("/w/a\"b"),
            masked_files: vec![],
        };
        let a: Vec<String> = seatbelt_command(&spec, Path::new("/bin/sh"), &["-c".into()])
            .iter()
            .map(|x| x.to_string_lossy().into_owned())
            .collect();
        assert_eq!(a[0], "-p");
        assert!(!a[1].contains("/w/a"), "paths never enter the profile text");
        assert!(a.contains(&"W0=/w/a\"b".to_string()));
        assert!(a.contains(&"R0=/r".to_string()));
        assert!(a.contains(&"S=/s".to_string()));
        assert_eq!(&a[a.len() - 2..], &["/bin/sh", "-c"]);
    }

    #[test]
    fn env_files_lists_only_top_level_env_files() {
        let d = tempfile::tempdir().expect("tmp");
        let root = d.path().to_path_buf();
        std::fs::write(root.join(".env"), "x").expect("w");
        std::fs::write(root.join(".env.local"), "x").expect("w");
        std::fs::write(root.join("env.txt"), "x").expect("w");
        std::fs::create_dir(root.join(".env.d")).expect("d");
        let got = env_files(std::slice::from_ref(&root));
        assert_eq!(got, vec![root.join(".env"), root.join(".env.local")]);
    }
}
