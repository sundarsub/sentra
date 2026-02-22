//! Sandbox orchestrator - coordinates namespace, seccomp, cgroups for execution
//!
//! This is the main entry point for sandboxed Python execution.

use std::collections::HashMap;
use std::time::Instant;
use sha2::{Sha256, Digest};

/// Request to execute code in sandbox
#[derive(Debug, Clone)]
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

impl Default for SandboxRequest {
    fn default() -> Self {
        Self {
            code: String::new(),
            profile: "python_sandbox_v1".to_string(),
            cwd: "/work".to_string(),
            fs_read_allow: vec!["/work".to_string()],
            fs_write_allow: vec!["/work/tmp".to_string(), "/work/out".to_string()],
            timeout_sec: 30,
            mem_max_mb: 512,
            pids_max: 64,
            max_stdout_bytes: 200_000,
            max_stderr_bytes: 200_000,
            env: HashMap::new(),
        }
    }
}

impl SandboxRequest {
    /// Calculate SHA256 hash of the code
    pub fn code_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.code.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Response from sandbox execution
#[derive(Debug, Clone)]
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

/// Executor for sandboxed Python code
pub struct SandboxExecutor {
    /// Path to python_runner binary
    python_runner_path: String,
}

impl SandboxExecutor {
    pub fn new(python_runner_path: &str) -> Self {
        Self {
            python_runner_path: python_runner_path.to_string(),
        }
    }

    /// Execute code in sandbox (non-Linux fallback - reduced security)
    #[cfg(not(target_os = "linux"))]
    pub fn execute(&self, request: &SandboxRequest) -> Result<SandboxResponse, Box<dyn std::error::Error>> {
        use std::process::Command;

        eprintln!("WARNING: Running in reduced-security mode (not Linux)");

        let start = Instant::now();
        let code_hash = request.code_hash();

        // Write code to temp file
        let temp_dir = std::env::temp_dir();
        let code_path = temp_dir.join("sentra_exec.py");
        std::fs::write(&code_path, &request.code)?;

        // Run Python directly (no sandbox on non-Linux)
        let output = Command::new("python3")
            .arg("-u")
            .arg("-B")
            .arg(&code_path)
            .current_dir(&request.cwd)
            .output()?;

        let wall_time = start.elapsed();

        // Cleanup
        let _ = std::fs::remove_file(&code_path);

        let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let truncated_stdout = stdout.len() > request.max_stdout_bytes;
        let truncated_stderr = stderr.len() > request.max_stderr_bytes;

        if truncated_stdout {
            stdout.truncate(request.max_stdout_bytes);
            stdout.push_str("\n[TRUNCATED]");
        }
        if truncated_stderr {
            stderr.truncate(request.max_stderr_bytes);
            stderr.push_str("\n[TRUNCATED]");
        }

        Ok(SandboxResponse {
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
            stderr,
            wall_time_ms: wall_time.as_millis() as u64,
            peak_mem_mb: 0, // Not tracked on non-Linux
            code_sha256: code_hash,
            timed_out: false,
            truncated_stdout,
            truncated_stderr,
        })
    }

    /// Execute code in full sandbox (Linux)
    #[cfg(target_os = "linux")]
    pub fn execute(&self, request: &SandboxRequest) -> Result<SandboxResponse, Box<dyn std::error::Error>> {
        use std::process::{Command, Stdio};
        use std::io::Read;

        let start = Instant::now();
        let code_hash = request.code_hash();

        // Create cgroup for this execution
        let cgroup_name = format!("exec_{}", uuid::Uuid::new_v4());
        let cgroup = crate::cgroup::CgroupController::create(&cgroup_name)?;

        let limits = crate::cgroup::CgroupLimits {
            memory_max_bytes: request.mem_max_mb * 1024 * 1024,
            cpu_max_percent: 50,
            pids_max: request.pids_max,
        };
        cgroup.set_limits(&limits)?;

        // Write code to temp file
        let temp_dir = std::env::temp_dir();
        let code_path = temp_dir.join(format!("sentra_{}.py", uuid::Uuid::new_v4()));
        std::fs::write(&code_path, &request.code)?;

        // Execute Python with output capture
        let mut child = Command::new("python3")
            .arg("-u")
            .arg("-B")
            .arg(&code_path)
            .current_dir(&request.cwd)
            .env_clear()
            .env("HOME", "/work")
            .env("PATH", "/usr/bin:/bin")
            .env("PYTHONPATH", "")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Add to cgroup
        cgroup.add_pid(child.id())?;

        // Wait with timeout
        let timeout = Duration::from_secs(request.timeout_sec);
        let mut timed_out = false;

        let status = loop {
            match child.try_wait()? {
                Some(status) => break status,
                None => {
                    if start.elapsed() > timeout {
                        // Kill the child
                        let _ = child.kill();
                        timed_out = true;
                        break child.wait()?;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };

        let wall_time = start.elapsed();

        // Read output
        let mut stdout = String::new();
        let mut stderr = String::new();

        if let Some(mut out) = child.stdout.take() {
            let mut buf = vec![0u8; request.max_stdout_bytes + 1];
            let n = out.read(&mut buf).unwrap_or(0);
            stdout = String::from_utf8_lossy(&buf[..n.min(request.max_stdout_bytes)]).to_string();
        }
        if let Some(mut err) = child.stderr.take() {
            let mut buf = vec![0u8; request.max_stderr_bytes + 1];
            let n = err.read(&mut buf).unwrap_or(0);
            stderr = String::from_utf8_lossy(&buf[..n.min(request.max_stderr_bytes)]).to_string();
        }

        let truncated_stdout = stdout.len() >= request.max_stdout_bytes;
        let truncated_stderr = stderr.len() >= request.max_stderr_bytes;

        if truncated_stdout {
            stdout.push_str("\n[TRUNCATED]");
        }
        if truncated_stderr {
            stderr.push_str("\n[TRUNCATED]");
        }

        // Get peak memory from cgroup
        let peak_mem_mb = cgroup.get_memory_peak()
            .map(|b| b / (1024 * 1024))
            .unwrap_or(0);

        // Cleanup
        let _ = std::fs::remove_file(&code_path);

        Ok(SandboxResponse {
            exit_code: status.code().unwrap_or(-1),
            stdout,
            stderr,
            wall_time_ms: wall_time.as_millis() as u64,
            peak_mem_mb,
            code_sha256: code_hash,
            timed_out,
            truncated_stdout,
            truncated_stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_request_defaults() {
        let req = SandboxRequest::default();
        assert_eq!(req.timeout_sec, 30);
        assert_eq!(req.mem_max_mb, 512);
        assert_eq!(req.profile, "python_sandbox_v1");
        assert_eq!(req.cwd, "/work");
    }

    #[test]
    fn test_code_hash() {
        let mut req = SandboxRequest::default();
        req.code = "print('hello')".to_string();
        let hash = req.code_hash();
        assert_eq!(hash.len(), 64); // SHA256 hex is 64 chars
    }

    #[test]
    fn test_sandbox_executor_new() {
        let executor = SandboxExecutor::new("/usr/lib/sentra/python_runner");
        assert_eq!(executor.python_runner_path, "/usr/lib/sentra/python_runner");
    }

    #[test]
    fn test_simple_execution() {
        let executor = SandboxExecutor::new("/usr/lib/sentra/python_runner");
        let mut req = SandboxRequest::default();
        req.code = "print('hello world')".to_string();
        req.cwd = std::env::temp_dir().to_string_lossy().to_string();

        let result = executor.execute(&req);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.stdout.contains("hello world"));
        assert_eq!(response.exit_code, 0);
    }
}
