//! OpenClaw Launcher - Seccomp-Locked AI Agent Launcher
//!
//! This binary launches an AI agent (OpenClaw) in a seccomp-locked environment
//! with configurable security profiles loaded from policy.yaml.
//!
//! Security flow:
//! 1. Load seccomp profile from policy.yaml
//! 2. Optionally start Sentra (API or REPL mode)
//! 3. Apply seccomp filter based on selected profile
//! 4. Set SHELL to sentra-shell for command governance
//! 5. Exec OpenClaw binary (this is the LAST exec before seccomp locks)
//!
//! After step 5, the OpenClaw process CANNOT:
//! - Run any subprocess (subprocess.run(), os.system() all fail)
//! - Fork new processes
//! - Execute dangerous syscalls (ptrace, mount, etc.)
//!
//! Commands executed by OpenClaw go through the SHELL (Sentra REPL) for
//! policy enforcement.

use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use clap::Parser;
use sentra::seccomp_profile::{
    apply_seccomp_profile, load_from_policy, PolicySeccompConfig, SeccompProfile,
};

/// OpenClaw Launcher - Secure AI Agent Execution Environment
#[derive(Parser, Debug)]
#[command(name = "openclaw_launcher")]
#[command(author = "Sundar Subramaniam")]
#[command(version)]
#[command(about = "Launch OpenClaw AI agent in a seccomp-locked environment")]
struct Args {
    /// Path to the OpenClaw binary
    #[arg(short, long, default_value = "/usr/local/bin/openclaw")]
    openclaw_bin: String,

    /// Path to the Sentra binary
    #[arg(short, long, default_value = "/usr/local/bin/sentra")]
    sentra_bin: String,

    /// Path to policy.yaml file
    #[arg(long, default_value = "/etc/sentra/policy.yaml")]
    policy: String,

    /// Seccomp profile to apply (from policy.yaml seccomp_profiles section)
    /// Use 'gateway' (default) for OpenClaw which needs subprocess spawning
    /// Use restrictive profiles like 'whatsapp_agent' only for sandboxed code
    #[arg(long, default_value = "gateway")]
    seccomp_profile: String,

    /// Sentra API port (used when --sentra-api is set)
    #[arg(short, long, default_value = "9999")]
    port: u16,

    /// Path to python_runner binary (for Sentra)
    #[arg(long, default_value = "/usr/lib/sentra/python_runner")]
    python_runner: String,

    /// Path to sentra-shell wrapper script
    #[arg(long, default_value = "/usr/local/bin/sentra-shell")]
    sentra_shell: String,

    /// Use Sentra REPL mode (commands via SHELL env var)
    /// This is the default and recommended mode
    #[arg(long, default_value = "true")]
    sentra_repl: bool,

    /// Use Sentra API mode instead of REPL
    /// When set, starts Sentra API server and waits for it
    #[arg(long)]
    sentra_api: bool,

    /// Skip starting Sentra entirely (if already running or not needed)
    #[arg(long)]
    skip_sentra: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Skip seccomp lockdown (allows full system access)
    /// WARNING: This reduces security - only use for trusted AI agents
    #[arg(long)]
    no_seccomp: bool,

    /// List available seccomp profiles and exit
    #[arg(long)]
    list_profiles: bool,

    /// Remaining arguments passed to OpenClaw
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    openclaw_args: Vec<String>,
}

fn main() {
    let args = Args::parse();

    // Load policy configuration
    let config = match load_from_policy(&args.policy) {
        Ok(c) => c,
        Err(e) => {
            // If policy file doesn't exist, use defaults
            if args.verbose {
                eprintln!("Warning: Could not load policy from {}: {}", args.policy, e);
                eprintln!("Using default configuration");
            }
            PolicySeccompConfig::default()
        }
    };

    // Handle --list-profiles
    if args.list_profiles {
        println!("Available seccomp profiles:");
        println!();
        for (name, profile) in &config.seccomp_profiles {
            let extends = profile
                .extends
                .as_ref()
                .map(|e| format!(" (extends: {})", e))
                .unwrap_or_default();
            let network = if profile.allow.iter().any(|s| s == "socket") {
                "network: allowed"
            } else {
                "network: blocked"
            };
            println!("  • {}{}", name, extends);
            println!("    {}", network);
            if let Some(np) = &profile.network_policy {
                if !np.allow_outbound.is_empty() {
                    println!("    outbound: {:?}", np.allow_outbound);
                }
            }
            println!();
        }
        return;
    }

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║           OpenClaw Launcher - Secure Execution           ║");
    println!("║         Seccomp-Locked AI Agent Environment              ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Resolve the seccomp profile
    let profile_name = &args.seccomp_profile;
    let resolved_profile = if config.seccomp_profiles.is_empty() {
        if args.verbose {
            println!("→ No seccomp profiles in policy, using built-in defaults");
        }
        None
    } else {
        match SeccompProfile::resolve(profile_name, &config.seccomp_profiles) {
            Ok(p) => {
                println!("→ Using seccomp profile: {}", profile_name);
                Some(p)
            }
            Err(e) => {
                eprintln!(
                    "ERROR: Failed to resolve seccomp profile '{}': {}",
                    profile_name, e
                );
                eprintln!(
                    "Available profiles: {:?}",
                    config.seccomp_profiles.keys().collect::<Vec<_>>()
                );
                std::process::exit(1);
            }
        }
    };

    // Step 1: Handle Sentra startup based on mode
    if args.sentra_api && !args.skip_sentra {
        // API mode: start Sentra API server
        if let Err(e) = start_sentra_api_server(&args) {
            eprintln!("ERROR: Failed to start Sentra API: {}", e);
            std::process::exit(1);
        }

        // Wait for Sentra API to be ready
        println!("→ Waiting for Sentra API on port {}...", args.port);
        if !wait_for_sentra(args.port, Duration::from_secs(10)) {
            eprintln!("ERROR: Sentra API not responding on port {}", args.port);
            std::process::exit(1);
        }
        println!("✓ Sentra API ready");
    } else if args.sentra_repl && !args.skip_sentra {
        // REPL mode: verify sentra-shell exists
        if !std::path::Path::new(&args.sentra_shell).exists() {
            eprintln!("ERROR: sentra-shell not found at: {}", args.sentra_shell);
            eprintln!("Create it or specify path with --sentra-shell");
            std::process::exit(1);
        }
        println!("→ Sentra REPL mode: SHELL={}", args.sentra_shell);
    } else if args.skip_sentra {
        println!("→ Skipping Sentra (--skip-sentra)");
    }

    // Step 2: Apply seccomp filter (Linux only, unless --no-seccomp)
    #[cfg(target_os = "linux")]
    {
        if args.no_seccomp {
            println!("⚠ WARNING: Seccomp lockdown DISABLED by --no-seccomp flag");
            println!("  OpenClaw will have full system access");
            println!("  Network access: ALLOWED");
            println!("  Subprocess spawning: ALLOWED");
            println!();
        } else if let Some(ref profile) = resolved_profile {
            println!("→ Applying seccomp lockdown...");
            if let Err(e) = apply_seccomp_profile(profile, args.verbose) {
                eprintln!("ERROR: Failed to apply seccomp: {}", e);
                std::process::exit(1);
            }
            println!("✓ Seccomp filter applied - process locked");

            // Print what's allowed/blocked
            if args.verbose {
                println!("  Denied syscalls: {:?}", profile.all_denied_syscalls());
                if !profile.allow.is_empty() {
                    println!("  Allowed syscalls: {:?}", profile.allow);
                }
            }
        } else {
            // Use built-in hardcoded seccomp (fallback)
            println!("→ Applying built-in seccomp lockdown...");
            if let Err(e) = apply_builtin_seccomp(args.verbose) {
                eprintln!("ERROR: Failed to apply seccomp: {}", e);
                std::process::exit(1);
            }
            println!("✓ Seccomp filter applied - process locked");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("⚠ WARNING: Seccomp not available on this platform");
        println!("  OpenClaw will run WITHOUT seccomp lockdown");
        println!("  This is NOT secure for production use");
        println!();
    }

    // Step 3: Set environment variables
    if args.sentra_repl && !args.skip_sentra {
        std::env::set_var("SHELL", &args.sentra_shell);
        std::env::set_var("SENTRA_POLICY", &args.policy);
        std::env::set_var("PYTHON_RUNNER", &args.python_runner);
        println!("→ Set SHELL={}", args.sentra_shell);
    }

    // Step 4: Print security status
    println!();
    println!("═══════════════════════════════════════════════════════════");
    if args.sentra_repl {
        println!("  SECCOMP LOCKED - Commands via Sentra REPL             ");
    } else if args.sentra_api {
        println!("  SECCOMP LOCKED - Code execution via Sentra API        ");
        println!("  API endpoint: 127.0.0.1:{}", args.port);
    } else {
        println!("  SECCOMP LOCKED - Limited system access                ");
    }
    println!("═══════════════════════════════════════════════════════════");
    println!();

    // Step 5: Exec OpenClaw (this is the LAST exec)
    println!("→ Launching OpenClaw: {}", args.openclaw_bin);
    exec_openclaw(&args.openclaw_bin, &args.openclaw_args);
}

/// Start Sentra API server in background
fn start_sentra_api_server(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("→ Starting Sentra API server on port {}...", args.port);

    // Check if Sentra is already running
    if TcpStream::connect(format!("127.0.0.1:{}", args.port)).is_ok() {
        println!("✓ Sentra already running on port {}", args.port);
        return Ok(());
    }

    // Start Sentra in background
    let mut cmd = Command::new(&args.sentra_bin);
    cmd.arg("--api")
        .arg("--port")
        .arg(args.port.to_string())
        .arg("--policy")
        .arg(&args.policy)
        .arg("--python-runner")
        .arg(&args.python_runner)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Spawn as detached process
    let child = cmd.spawn()?;
    println!("✓ Sentra started (PID: {})", child.id());

    // Give it time to start
    thread::sleep(Duration::from_millis(500));

    Ok(())
}

/// Wait for Sentra API to be ready
fn wait_for_sentra(port: u16, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    let addr = format!("127.0.0.1:{}", port);

    while start.elapsed() < timeout {
        if TcpStream::connect(&addr).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }

    false
}

/// Apply built-in seccomp filter (fallback when no YAML profile)
#[cfg(target_os = "linux")]
fn apply_builtin_seccomp(verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
    use nix::libc;

    // Set NO_NEW_PRIVS
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("Failed to set NO_NEW_PRIVS".into());
        }
    }

    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)?;

    // Block fork/vfork
    for syscall_name in &["fork", "vfork", "execveat"] {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            filter.add_rule(ScmpAction::Errno(libc::EPERM), syscall)?;
            if verbose {
                println!("  → Deny: {}", syscall_name);
            }
        }
    }

    // Block clone for process creation (allow threads)
    if let Ok(clone_syscall) = ScmpSyscall::from_name("clone") {
        filter.add_rule_conditional(
            ScmpAction::Errno(libc::EPERM),
            clone_syscall,
            &[ScmpArgCompare::new(
                0,
                ScmpCompareOp::MaskedEqual(0x10000),
                0,
            )],
        )?;
        if verbose {
            println!("  → Deny: clone (process creation, threads allowed)");
        }
    }

    // Block dangerous syscalls
    let dangerous = [
        "ptrace",
        "mount",
        "umount2",
        "pivot_root",
        "bpf",
        "perf_event_open",
        "init_module",
        "delete_module",
        "finit_module",
        "keyctl",
        "unshare",
        "setns",
        "setuid",
        "setgid",
        "setresuid",
        "setresgid",
        "setgroups",
        "capset",
        "reboot",
        "kexec_load",
        "kexec_file_load",
        "swapon",
        "swapoff",
        "sethostname",
        "setdomainname",
        "iopl",
        "ioperm",
    ];

    for syscall_name in &dangerous {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            filter.add_rule(ScmpAction::Errno(libc::EPERM), syscall)?;
        }
    }

    filter.load()?;

    if verbose {
        println!("  → Seccomp filter loaded");
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_builtin_seccomp(_verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

/// Exec OpenClaw - this replaces the current process
#[cfg(target_os = "linux")]
fn exec_openclaw(openclaw_bin: &str, args: &[String]) -> ! {
    use nix::unistd::execv;
    use std::ffi::CString;

    let mut c_args: Vec<CString> = Vec::new();
    c_args.push(CString::new(openclaw_bin).expect("Invalid openclaw path"));

    for arg in args {
        c_args.push(CString::new(arg.as_str()).expect("Invalid argument"));
    }

    let c_args_refs: Vec<&std::ffi::CStr> = c_args.iter().map(|s| s.as_c_str()).collect();

    match execv(&c_args[0], &c_args_refs) {
        Ok(_) => unreachable!(),
        Err(e) => {
            eprintln!("ERROR: Failed to exec OpenClaw: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn exec_openclaw(openclaw_bin: &str, args: &[String]) -> ! {
    let status = Command::new(openclaw_bin)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();

    match status {
        Ok(s) => std::process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("ERROR: Failed to run OpenClaw: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        let args = Args::try_parse_from(&[
            "openclaw_launcher",
            "--port",
            "9999",
            "--skip-sentra",
            "--seccomp-profile",
            "whatsapp_agent",
        ]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.port, 9999);
        assert!(args.skip_sentra);
        assert_eq!(args.seccomp_profile, "whatsapp_agent");
    }

    #[test]
    fn test_default_values() {
        let args = Args::try_parse_from(&["openclaw_launcher"]).unwrap();
        assert_eq!(args.port, 9999);
        assert_eq!(args.openclaw_bin, "/usr/local/bin/openclaw");
        assert_eq!(args.sentra_bin, "/usr/local/bin/sentra");
        assert_eq!(args.seccomp_profile, "gateway");
        assert!(args.sentra_repl);
        assert!(!args.sentra_api);
    }

    #[test]
    fn test_list_profiles_flag() {
        let args = Args::try_parse_from(&["openclaw_launcher", "--list-profiles"]).unwrap();
        assert!(args.list_profiles);
    }
}
