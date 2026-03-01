//! JSON API mode for Execwall
//!
//! Provides a TCP server that accepts JSON requests for sandbox execution.
//! Loads configuration from policy.yaml for profile-based sandbox settings.

use crate::policy::PolicyEngine;
use crate::sandbox::{SandboxExecutor, SandboxRequest, SandboxResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// API request format
#[derive(Debug, Clone, Deserialize)]
pub struct ApiRequest {
    /// Python code to execute
    pub code: String,
    /// Sandbox profile name (optional, defaults to "python_sandbox_v1")
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Working directory (optional)
    #[serde(default)]
    pub cwd: Option<String>,
    /// Timeout in seconds (optional)
    #[serde(default)]
    pub timeout_sec: Option<u64>,
    /// Memory limit in MB (optional)
    #[serde(default)]
    pub mem_max_mb: Option<u64>,
    /// Max processes (optional)
    #[serde(default)]
    pub pids_max: Option<u32>,
    /// Environment variables (optional)
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
}

fn default_profile() -> String {
    "python_sandbox_v1".to_string()
}

/// API response format
#[derive(Debug, Clone, Serialize)]
pub struct ApiResponse {
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

impl From<SandboxResponse> for ApiResponse {
    fn from(resp: SandboxResponse) -> Self {
        Self {
            exit_code: resp.exit_code,
            stdout: resp.stdout,
            stderr: resp.stderr,
            wall_time_ms: resp.wall_time_ms,
            peak_mem_mb: resp.peak_mem_mb,
            code_sha256: resp.code_sha256,
            timed_out: resp.timed_out,
            truncated_stdout: resp.truncated_stdout,
            truncated_stderr: resp.truncated_stderr,
        }
    }
}

/// API error response
#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
}

/// JSON API Server
pub struct ApiServer {
    port: u16,
    executor: SandboxExecutor,
    policy: Arc<PolicyEngine>,
}

impl ApiServer {
    /// Create a new API server with policy configuration
    pub fn new(port: u16, python_runner_path: &str, policy_path: &str) -> Result<Self, String> {
        let policy = PolicyEngine::load_from_file(policy_path)
            .map_err(|e| format!("Failed to load policy from {}: {}", policy_path, e))?;

        Ok(Self {
            port,
            executor: SandboxExecutor::new(python_runner_path),
            policy: Arc::new(policy),
        })
    }

    /// Create API server with pre-loaded policy
    pub fn with_policy(port: u16, python_runner_path: &str, policy: PolicyEngine) -> Self {
        Self {
            port,
            executor: SandboxExecutor::new(python_runner_path),
            policy: Arc::new(policy),
        }
    }

    /// Start the API server
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;

        println!("Execwall API server listening on {}", addr);
        println!("Policy loaded with {} profiles", self.policy.profile_count());
        println!("Send JSON requests with format: {{\"code\": \"...\", \"profile\": \"python_sandbox_v1\"}}");
        println!("Press Ctrl+C to stop the server");

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    println!("Connection from: {}", peer_addr);
                    // Clone what we need for the async task
                    let python_runner_path = self.executor.python_runner_path().to_string();
                    let policy = Arc::clone(&self.policy);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(socket, &python_runner_path, &policy).await {
                            eprintln!("Error handling connection from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// Handle a single client connection
async fn handle_connection(
    socket: TcpStream,
    python_runner_path: &str,
    policy: &PolicyEngine,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read one line (JSON request)
    let bytes_read = reader.read_line(&mut line).await?;
    if bytes_read == 0 {
        return Ok(()); // Connection closed
    }

    let response_json = match process_request(&line, python_runner_path, policy) {
        Ok(response) => serde_json::to_string(&response)?,
        Err(error) => serde_json::to_string(&error)?,
    };

    // Send response
    writer.write_all(response_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    Ok(())
}

/// Process a JSON request and return a response
fn process_request(
    request_json: &str,
    python_runner_path: &str,
    policy: &PolicyEngine,
) -> Result<ApiResponse, ApiError> {
    // Parse the request
    let api_request: ApiRequest = serde_json::from_str(request_json).map_err(|e| ApiError {
        error: format!("Invalid JSON request: {}", e),
        code: "INVALID_JSON".to_string(),
    })?;

    // Validate request
    if api_request.code.is_empty() {
        return Err(ApiError {
            error: "Code cannot be empty".to_string(),
            code: "EMPTY_CODE".to_string(),
        });
    }

    // Build SandboxRequest starting with defaults
    let mut sandbox_request = SandboxRequest::default();
    sandbox_request.code = api_request.code;
    sandbox_request.profile = api_request.profile.clone();

    // Look up profile from policy and apply its settings
    if let Some(profile) = policy.get_profile(&api_request.profile) {
        // Apply filesystem defaults from profile
        sandbox_request.cwd = profile.fs_defaults.cwd.clone();
        sandbox_request.fs_read_allow = profile.fs_defaults.read_allow.clone();
        sandbox_request.fs_write_allow = profile.fs_defaults.write_allow.clone();

        // Apply limits from profile
        sandbox_request.timeout_sec = profile.limits_defaults.timeout_sec;
        sandbox_request.mem_max_mb = profile.limits_defaults.mem_max_mb;
        sandbox_request.pids_max = profile.limits_defaults.pids_max;
        sandbox_request.max_stdout_bytes = profile.limits_defaults.max_stdout_bytes;
        sandbox_request.max_stderr_bytes = profile.limits_defaults.max_stderr_bytes;
    } else {
        // Profile not found - log warning but continue with defaults
        eprintln!(
            "Warning: Profile '{}' not found in policy, using defaults",
            api_request.profile
        );
    }

    // Override with any explicit request parameters (request takes precedence)
    if let Some(cwd) = api_request.cwd {
        sandbox_request.cwd = cwd;
    }
    if let Some(timeout) = api_request.timeout_sec {
        sandbox_request.timeout_sec = timeout;
    }
    if let Some(mem) = api_request.mem_max_mb {
        sandbox_request.mem_max_mb = mem;
    }
    if let Some(pids) = api_request.pids_max {
        sandbox_request.pids_max = pids;
    }
    if let Some(env) = api_request.env {
        sandbox_request.env = env;
    }

    // Execute in sandbox using python_runner
    let executor = SandboxExecutor::new(python_runner_path);
    let result = executor.execute(&sandbox_request).map_err(|e| ApiError {
        error: format!("Execution failed: {}", e),
        code: "EXECUTION_ERROR".to_string(),
    })?;

    Ok(ApiResponse::from(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_request_deserialization() {
        let json = r#"{"code": "print('hello')", "profile": "test"}"#;
        let req: ApiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.code, "print('hello')");
        assert_eq!(req.profile, "test");
    }

    #[test]
    fn test_api_request_defaults() {
        let json = r#"{"code": "print('hello')"}"#;
        let req: ApiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.code, "print('hello')");
        assert_eq!(req.profile, "python_sandbox_v1");
        assert!(req.cwd.is_none());
        assert!(req.timeout_sec.is_none());
    }

    #[test]
    fn test_api_response_serialization() {
        let response = ApiResponse {
            exit_code: 0,
            stdout: "hello".to_string(),
            stderr: "".to_string(),
            wall_time_ms: 100,
            peak_mem_mb: 10,
            code_sha256: "abc123".to_string(),
            timed_out: false,
            truncated_stdout: false,
            truncated_stderr: false,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"exit_code\":0"));
        assert!(json.contains("\"stdout\":\"hello\""));
    }

    #[test]
    fn test_api_error_serialization() {
        let error = ApiError {
            error: "Something went wrong".to_string(),
            code: "TEST_ERROR".to_string(),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"error\":\"Something went wrong\""));
        assert!(json.contains("\"code\":\"TEST_ERROR\""));
    }

    #[test]
    fn test_process_request_empty_code() {
        let policy = PolicyEngine::default();
        let json = r#"{"code": ""}"#;
        let result = process_request(json, "/usr/lib/execwall/python_runner", &policy);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "EMPTY_CODE");
    }

    #[test]
    fn test_process_request_invalid_json() {
        let policy = PolicyEngine::default();
        let json = "not valid json";
        let result = process_request(json, "/usr/lib/execwall/python_runner", &policy);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "INVALID_JSON");
    }
}
