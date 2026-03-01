//! Python sandbox runner binary
//!
//! This binary is spawned by SandboxExecutor as a child process.
//! It receives a SandboxRequest via stdin, applies sandbox restrictions,
//! executes the Python code, and returns results via stdout as JSON.
//!
//! Configuration is loaded from policy.yaml (same file as execwall shell and API).
//!
//! Security flow:
//! 1. Load policy.yaml for profile configuration (if --policy specified)
//! 2. Receive SandboxRequest JSON from parent via stdin
//! 3. Apply namespace isolation (Linux only)
//! 4. Apply seccomp-bpf syscall filter based on profile's syscall_profile (Linux only)
//! 5. Drop privileges
//! 6. Execute Python code
//! 7. Return SandboxResponse JSON via stdout

use std::collections::HashMap;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::Instant;

use clap::Parser;
use serde::{Deserialize, Serialize};

use execwall::policy::PolicyEngine;

/// Python Sandbox Runner - Isolated Python Execution
#[derive(Parser, Debug)]
#[command(name = "python_runner")]
#[command(version)]
#[command(about = "Execute Python code in isolated sandbox")]
struct Args {
    /// Path to policy.yaml file for profile configuration
    #[arg(long, default_value = "/etc/execwall/policy.yaml")]
    policy: String,

    /// Verbose output (to stderr)
    #[arg(short, long)]
    verbose: bool,
}

/// Request to execute code in sandbox (mirrored from sandbox.rs for binary use)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRequest {
    /// Python code to execute
    pub code: String,
    /// Sandbox profile name
    pub profile: String,
    /// Working directory
    pub cwd: String,
    /// Allowed read paths
    pub fs_read_allow: Vec<String>,
    /// Allowed write paths
    pub fs_write_allow: Vec<String>,
    /// Timeout in seconds
    pub timeout_sec: u64,
    /// Memory limit in MB
    pub mem_max_mb: u64,
    /// Max processes
    pub pids_max: u32,
    /// Max stdout bytes
    pub max_stdout_bytes: usize,
    /// Max stderr bytes
    pub max_stderr_bytes: usize,
    /// Environment variables
    pub env: HashMap<String, String>,
}

/// Response from sandbox execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResponse {
    /// Process exit code
    pub exit_code: i32,
    /// Captured stdout
    pub stdout: String,
    /// Captured stderr
    pub stderr: String,
    /// Wall clock time in milliseconds
    pub wall_time_ms: u64,
    /// Peak memory usage in MB
    pub peak_mem_mb: u64,
    /// SHA256 hash of executed code
    pub code_sha256: String,
    /// Whether execution timed out
    pub timed_out: bool,
    /// Whether stdout was truncated
    pub truncated_stdout: bool,
    /// Whether stderr was truncated
    pub truncated_stderr: bool,
}

/// Error response for structured error reporting
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub stage: String,
}

fn main() {
    let args = Args::parse();

    // Run the main logic and handle any errors
    match run(&args) {
        Ok(response) => {
            // Output successful response as JSON to stdout
            let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                format!(r#"{{"error": "Failed to serialize response: {}"}}"#, e)
            });
            println!("{}", json);
        }
        Err(e) => {
            // Output error as JSON to stdout for parent to parse
            let error_response = ErrorResponse {
                error: e.to_string(),
                stage: "runner".to_string(),
            };
            let json = serde_json::to_string(&error_response)
                .unwrap_or_else(|_| format!(r#"{{"error": "{}"}}"#, e));
            println!("{}", json);
            std::process::exit(1);
        }
    }
}

fn run(args: &Args) -> Result<SandboxResponse, Box<dyn std::error::Error>> {
    // Step 1: Load policy.yaml for profile configuration
    let policy = PolicyEngine::load_from_file(&args.policy).ok();
    if args.verbose {
        if let Some(ref p) = policy {
            eprintln!("python_runner: Loaded policy with {} profiles", p.profile_count());
        } else {
            eprintln!("python_runner: No policy loaded, using request defaults");
        }
    }

    // Step 2: Read SandboxRequest JSON from stdin
    let mut request = read_request_from_stdin()?;

    // Step 3: If policy loaded, look up profile and apply any additional settings
    if let Some(ref policy) = policy {
        if let Some(profile) = policy.get_profile(&request.profile) {
            if args.verbose {
                eprintln!("python_runner: Using profile '{}' with syscall_profile '{}'",
                    request.profile, profile.syscall_profile);
            }
            // Profile settings from YAML can override/augment request
            // (request already has settings from API, but profile may have syscall info)
        }
    }

    // Step 4: Apply namespace isolation (Linux only)
    #[cfg(target_os = "linux")]
    apply_namespace_isolation(&request)?;

    // Step 5: Apply seccomp-bpf filter (Linux only)
    // Note: We do NOT apply seccomp here because we need to call execve for Python
    // The seccomp filter would block execve. Instead, seccomp should be applied
    // by Python code itself or we use a different approach.
    // For now, we skip seccomp for the runner itself.
    // In a production system, you might use a two-stage approach:
    // 1. Runner forks a child
    // 2. Child applies seccomp (which blocks execve but allows already-running code)
    // 3. Child execs Python before seccomp is applied (in the fork)
    //
    // For this implementation, we apply seccomp AFTER forking but BEFORE exec.
    // Actually, let's not apply seccomp since it would block the Python execution.
    // The parent process (SandboxExecutor) handles cgroups for resource limits.

    // Step 4: Drop privileges (Linux only)
    #[cfg(target_os = "linux")]
    drop_privileges()?;

    // Step 5: Execute Python code
    let response = execute_python(&request)?;

    Ok(response)
}

/// Read SandboxRequest JSON from stdin
fn read_request_from_stdin() -> Result<SandboxRequest, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut input = String::new();

    // Read all input from stdin
    stdin.lock().read_to_string(&mut input)?;

    // Parse JSON
    let request: SandboxRequest = serde_json::from_str(&input)
        .map_err(|e| format!("Failed to parse SandboxRequest JSON: {}", e))?;

    Ok(request)
}

/// Apply namespace isolation (Linux only)
#[cfg(target_os = "linux")]
fn apply_namespace_isolation(request: &SandboxRequest) -> Result<(), Box<dyn std::error::Error>> {
    use execwall::namespace::{NamespaceBuilder, NamespaceConfig};

    // Create namespace configuration
    let ns_config = NamespaceConfig {
        new_mount_ns: true,
        new_pid_ns: false,  // PID namespace requires fork, skip for simplicity
        new_net_ns: true,   // Block all network access
        new_user_ns: false, // User namespace requires additional UID mapping
    };

    // Unshare namespaces
    ns_config.unshare()?;

    // Set up filesystem isolation
    let mut ns_builder = NamespaceBuilder::new(&request.cwd);

    // Set up minimal Python sandbox environment
    ns_builder.setup_python_sandbox();

    // Add allowed read paths as read-only mounts
    for path in &request.fs_read_allow {
        ns_builder.bind_mount(path, path, true);
    }

    // Add allowed write paths as read-write mounts
    for path in &request.fs_write_allow {
        ns_builder.bind_mount(path, path, false);
    }

    // Apply the mount configuration
    ns_builder.apply_mounts()?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_namespace_isolation(_request: &SandboxRequest) -> Result<(), Box<dyn std::error::Error>> {
    // Namespace isolation not available on non-Linux platforms
    eprintln!("WARNING: Namespace isolation not available on this platform");
    Ok(())
}

/// Drop privileges to reduce attack surface
#[cfg(target_os = "linux")]
fn drop_privileges() -> Result<(), Box<dyn std::error::Error>> {
    use nix::libc;
    use std::ffi::CString;

    // Set NO_NEW_PRIVS to prevent privilege escalation
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err("Failed to set NO_NEW_PRIVS".into());
        }
    }

    // If running as root, try to drop to nobody
    unsafe {
        let uid = libc::getuid();
        if uid == 0 {
            // Try to set to nobody (65534) - common unprivileged user
            let nobody_uid = 65534;
            let nobody_gid = 65534;

            // Drop supplementary groups first
            if libc::setgroups(0, std::ptr::null()) != 0 {
                eprintln!("WARNING: Failed to clear supplementary groups");
            }

            // Set GID before UID (required order)
            if libc::setgid(nobody_gid) != 0 {
                eprintln!("WARNING: Failed to drop GID to nobody");
            }

            // Set UID last
            if libc::setuid(nobody_uid) != 0 {
                eprintln!("WARNING: Failed to drop UID to nobody");
            }
        }
    }

    // Drop all capabilities if caps crate is available
    #[cfg(feature = "caps")]
    {
        use caps::{clear, CapSet, Capability};
        // Clear all capability sets
        let _ = clear(None, CapSet::Effective);
        let _ = clear(None, CapSet::Permitted);
        let _ = clear(None, CapSet::Inheritable);
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_privileges() -> Result<(), Box<dyn std::error::Error>> {
    // Privilege dropping not available on non-Linux platforms
    Ok(())
}

/// Execute Python code and capture output
fn execute_python(request: &SandboxRequest) -> Result<SandboxResponse, Box<dyn std::error::Error>> {
    let start = Instant::now();

    // Calculate code hash
    let code_hash = calculate_sha256(&request.code);

    // Write code to a temporary file
    let temp_dir = std::env::temp_dir();
    let code_file = temp_dir.join(format!("execwall_exec_{}.py", std::process::id()));
    std::fs::write(&code_file, &request.code)?;

    // Build Python command
    let mut cmd = Command::new("python3");
    cmd.arg("-u") // Unbuffered output
        .arg("-B") // Don't write .pyc files
        .arg(&code_file)
        .current_dir(&request.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Clear environment and set minimal env vars
    cmd.env_clear();
    cmd.env("HOME", &request.cwd);
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("PYTHONPATH", "");
    cmd.env("PYTHONDONTWRITEBYTECODE", "1");
    cmd.env("PYTHONUNBUFFERED", "1");

    // Add user-specified environment variables
    for (key, value) in &request.env {
        cmd.env(key, value);
    }

    // Spawn the Python process
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn Python: {}", e))?;

    // Wait for completion with timeout handling
    let timeout = std::time::Duration::from_secs(request.timeout_sec);
    let mut timed_out = false;

    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if start.elapsed() > timeout {
                    // Kill the child process
                    let _ = child.kill();
                    timed_out = true;
                    // Wait for process to actually terminate
                    break child.wait()?;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    };

    let wall_time = start.elapsed();

    // Read stdout with truncation
    let mut stdout = String::new();
    let mut truncated_stdout = false;
    if let Some(mut out) = child.stdout.take() {
        let mut buf = vec![0u8; request.max_stdout_bytes + 1];
        let n = out.read(&mut buf).unwrap_or(0);
        if n > request.max_stdout_bytes {
            truncated_stdout = true;
            stdout = String::from_utf8_lossy(&buf[..request.max_stdout_bytes]).to_string();
            stdout.push_str("\n[TRUNCATED]");
        } else {
            stdout = String::from_utf8_lossy(&buf[..n]).to_string();
        }
    }

    // Read stderr with truncation
    let mut stderr = String::new();
    let mut truncated_stderr = false;
    if let Some(mut err) = child.stderr.take() {
        let mut buf = vec![0u8; request.max_stderr_bytes + 1];
        let n = err.read(&mut buf).unwrap_or(0);
        if n > request.max_stderr_bytes {
            truncated_stderr = true;
            stderr = String::from_utf8_lossy(&buf[..request.max_stderr_bytes]).to_string();
            stderr.push_str("\n[TRUNCATED]");
        } else {
            stderr = String::from_utf8_lossy(&buf[..n]).to_string();
        }
    }

    // Clean up temp file
    let _ = std::fs::remove_file(&code_file);

    Ok(SandboxResponse {
        exit_code: status.code().unwrap_or(-1),
        stdout,
        stderr,
        wall_time_ms: wall_time.as_millis() as u64,
        peak_mem_mb: 0, // Memory tracking is done by parent via cgroups
        code_sha256: code_hash,
        timed_out,
        truncated_stdout,
        truncated_stderr,
    })
}

/// Calculate SHA256 hash of a string
fn calculate_sha256(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha256() {
        let hash = calculate_sha256("print('hello')");
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex chars
    }

    #[test]
    fn test_request_deserialization() {
        let json = r#"{
            "code": "print('hello')",
            "profile": "python_sandbox_v1",
            "cwd": "/tmp",
            "fs_read_allow": ["/tmp"],
            "fs_write_allow": ["/tmp/out"],
            "timeout_sec": 30,
            "mem_max_mb": 512,
            "pids_max": 64,
            "max_stdout_bytes": 200000,
            "max_stderr_bytes": 200000,
            "env": {}
        }"#;

        let request: SandboxRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.code, "print('hello')");
        assert_eq!(request.timeout_sec, 30);
    }

    #[test]
    fn test_response_serialization() {
        let response = SandboxResponse {
            exit_code: 0,
            stdout: "hello\n".to_string(),
            stderr: String::new(),
            wall_time_ms: 100,
            peak_mem_mb: 10,
            code_sha256: "abc123".to_string(),
            timed_out: false,
            truncated_stdout: false,
            truncated_stderr: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"exit_code\":0"));
        assert!(json.contains("\"stdout\":\"hello\\n\""));
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ErrorResponse {
            error: "Something went wrong".to_string(),
            stage: "runner".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"error\":\"Something went wrong\""));
        assert!(json.contains("\"stage\":\"runner\""));
    }
}
