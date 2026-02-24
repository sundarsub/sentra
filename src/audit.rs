use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

/// Sandbox event types for lifecycle logging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxEvent {
    /// Sandbox environment is being set up
    SandboxEnter,
    /// Sandbox execution completed (success or failure)
    SandboxExit,
    /// A security violation occurred within the sandbox
    SandboxViolation,
}

/// Sandbox execution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMetrics {
    /// Wall clock time in milliseconds
    pub wall_time_ms: u64,
    /// Peak memory usage in megabytes
    pub peak_mem_mb: u64,
    /// Whether the execution timed out
    pub timed_out: bool,
    /// Whether stdout was truncated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_stdout: Option<bool>,
    /// Whether stderr was truncated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_stderr: Option<bool>,
}

impl SandboxMetrics {
    /// Create new sandbox metrics from execution data
    pub fn new(wall_time_ms: u64, peak_mem_mb: u64, timed_out: bool) -> Self {
        Self {
            wall_time_ms,
            peak_mem_mb,
            timed_out,
            truncated_stdout: None,
            truncated_stderr: None,
        }
    }

    /// Set truncation flags
    pub fn with_truncation(mut self, stdout: bool, stderr: bool) -> Self {
        self.truncated_stdout = Some(stdout);
        self.truncated_stderr = Some(stderr);
        self
    }
}

/// Decision made for a command
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allowed,
    Denied,
    AuditOnly, // Would be denied but audit mode
}

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO 8601 timestamp
    pub timestamp: DateTime<Utc>,
    /// Session identifier
    pub session_id: String,
    /// Hostname
    pub host: String,
    /// Username
    pub user: String,
    /// Action type (always "exec" for now)
    pub action: String,
    /// Full command as entered
    pub command: String,
    /// Executable name
    pub executable: String,
    /// Argument string
    pub args: String,
    /// Current working directory
    pub cwd: String,
    /// Decision made
    pub decision: Decision,
    /// Rule that matched (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Reason for decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Evaluation duration in milliseconds
    pub eval_duration_ms: u64,
    /// Execution duration in milliseconds (if executed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_duration_ms: Option<u64>,
    /// Exit code (if executed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    // --- Sandbox-specific fields ---
    /// SHA256 hash of the executed code (for sandbox executions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_sha256: Option<String>,
    /// Sandbox profile used for execution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Sandbox execution metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_metrics: Option<SandboxMetrics>,
}

/// Audit entry for sandbox lifecycle events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAuditEntry {
    /// ISO 8601 timestamp
    pub timestamp: DateTime<Utc>,
    /// Session identifier
    pub session_id: String,
    /// Hostname
    pub host: String,
    /// Username
    pub user: String,
    /// Sandbox event type
    pub event: SandboxEvent,
    /// SHA256 hash of the code being executed
    pub code_sha256: String,
    /// Sandbox profile name
    pub profile: String,
    /// Additional details about the event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Sandbox metrics (populated for sandbox_exit events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<SandboxMetrics>,
    /// Violation type (for sandbox_violation events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation_type: Option<String>,
    /// Exit code (for sandbox_exit events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Audit logger that writes JSON Lines to a file
pub struct AuditLogger {
    session_id: String,
    host: String,
    user: String,
    writer: Option<Mutex<BufWriter<File>>>,
    log_path: String,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_path: &str) -> Result<Self, String> {
        let session_id = Uuid::new_v4().to_string();

        let host = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let user = users::get_current_username()
            .map(|u| u.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Create parent directory if needed
        if let Some(parent) = Path::new(log_path).parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create log directory: {}", e))?;
            }
        }

        // Open file for appending
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|e| format!("Failed to open audit log '{}': {}", log_path, e))?;

        let writer = BufWriter::new(file);

        Ok(AuditLogger {
            session_id,
            host,
            user,
            writer: Some(Mutex::new(writer)),
            log_path: log_path.to_string(),
        })
    }

    /// Create a logger that only prints to stdout (no file)
    pub fn stdout_only() -> Self {
        let session_id = Uuid::new_v4().to_string();

        let host = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let user = users::get_current_username()
            .map(|u| u.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        AuditLogger {
            session_id,
            host,
            user,
            writer: None,
            log_path: String::new(),
        }
    }

    /// Get the session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the log file path
    pub fn log_path(&self) -> &str {
        &self.log_path
    }

    /// Log a command evaluation
    pub fn log_evaluation(
        &self,
        command: &str,
        executable: &str,
        args: &str,
        cwd: &str,
        decision: Decision,
        rule_id: Option<String>,
        reason: Option<String>,
        eval_start: Instant,
    ) -> AuditEntry {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: self.session_id.clone(),
            host: self.host.clone(),
            user: self.user.clone(),
            action: "exec".to_string(),
            command: command.to_string(),
            executable: executable.to_string(),
            args: args.to_string(),
            cwd: cwd.to_string(),
            decision,
            rule_id,
            reason,
            eval_duration_ms: eval_start.elapsed().as_millis() as u64,
            exec_duration_ms: None,
            exit_code: None,
            code_sha256: None,
            profile: None,
            sandbox_metrics: None,
        };

        self.write_entry(&entry);
        entry
    }

    /// Log command execution completion
    pub fn log_execution_complete(
        &self,
        mut entry: AuditEntry,
        exec_start: Instant,
        exit_code: i32,
    ) {
        entry.exec_duration_ms = Some(exec_start.elapsed().as_millis() as u64);
        entry.exit_code = Some(exit_code);
        self.write_entry(&entry);
    }

    /// Write an entry to the log file
    fn write_entry(&self, entry: &AuditEntry) {
        if let Some(ref writer_mutex) = self.writer {
            if let Ok(mut writer) = writer_mutex.lock() {
                if let Ok(json) = serde_json::to_string(entry) {
                    let _ = writeln!(writer, "{}", json);
                    let _ = writer.flush();
                }
            }
        }
    }

    /// Log session start
    pub fn log_session_start(&self, policy_info: &str) {
        let entry = serde_json::json!({
            "timestamp": Utc::now(),
            "session_id": self.session_id,
            "host": self.host,
            "user": self.user,
            "event": "session_start",
            "policy_info": policy_info,
        });

        if let Some(ref writer_mutex) = self.writer {
            if let Ok(mut writer) = writer_mutex.lock() {
                if let Ok(json) = serde_json::to_string(&entry) {
                    let _ = writeln!(writer, "{}", json);
                    let _ = writer.flush();
                }
            }
        }
    }

    /// Log session end
    pub fn log_session_end(&self, commands_executed: u64, commands_denied: u64) {
        let entry = serde_json::json!({
            "timestamp": Utc::now(),
            "session_id": self.session_id,
            "host": self.host,
            "user": self.user,
            "event": "session_end",
            "commands_executed": commands_executed,
            "commands_denied": commands_denied,
        });

        if let Some(ref writer_mutex) = self.writer {
            if let Ok(mut writer) = writer_mutex.lock() {
                if let Ok(json) = serde_json::to_string(&entry) {
                    let _ = writeln!(writer, "{}", json);
                    let _ = writer.flush();
                }
            }
        }
    }

    /// Write a sandbox audit entry to the log file
    fn write_sandbox_entry(&self, entry: &SandboxAuditEntry) {
        if let Some(ref writer_mutex) = self.writer {
            if let Ok(mut writer) = writer_mutex.lock() {
                if let Ok(json) = serde_json::to_string(entry) {
                    let _ = writeln!(writer, "{}", json);
                    let _ = writer.flush();
                }
            }
        }
    }

    /// Log sandbox enter event (when sandbox execution begins)
    pub fn log_sandbox_enter(&self, code_sha256: &str, profile: &str, details: Option<String>) {
        let entry = SandboxAuditEntry {
            timestamp: Utc::now(),
            session_id: self.session_id.clone(),
            host: self.host.clone(),
            user: self.user.clone(),
            event: SandboxEvent::SandboxEnter,
            code_sha256: code_sha256.to_string(),
            profile: profile.to_string(),
            details,
            metrics: None,
            violation_type: None,
            exit_code: None,
        };

        self.write_sandbox_entry(&entry);
    }

    /// Log sandbox exit event (when sandbox execution completes)
    pub fn log_sandbox_exit(
        &self,
        code_sha256: &str,
        profile: &str,
        exit_code: i32,
        metrics: SandboxMetrics,
        details: Option<String>,
    ) {
        let entry = SandboxAuditEntry {
            timestamp: Utc::now(),
            session_id: self.session_id.clone(),
            host: self.host.clone(),
            user: self.user.clone(),
            event: SandboxEvent::SandboxExit,
            code_sha256: code_sha256.to_string(),
            profile: profile.to_string(),
            details,
            metrics: Some(metrics),
            violation_type: None,
            exit_code: Some(exit_code),
        };

        self.write_sandbox_entry(&entry);
    }

    /// Log sandbox violation event (security policy violation)
    pub fn log_sandbox_violation(
        &self,
        code_sha256: &str,
        profile: &str,
        violation_type: &str,
        details: Option<String>,
    ) {
        let entry = SandboxAuditEntry {
            timestamp: Utc::now(),
            session_id: self.session_id.clone(),
            host: self.host.clone(),
            user: self.user.clone(),
            event: SandboxEvent::SandboxViolation,
            code_sha256: code_sha256.to_string(),
            profile: profile.to_string(),
            details,
            metrics: None,
            violation_type: Some(violation_type.to_string()),
            exit_code: None,
        };

        self.write_sandbox_entry(&entry);
    }

    /// Log a sandbox execution with full details
    /// This is a convenience method that logs the complete sandbox execution
    pub fn log_sandbox_execution(
        &self,
        command: &str,
        code_sha256: &str,
        profile: &str,
        cwd: &str,
        decision: Decision,
        rule_id: Option<String>,
        reason: Option<String>,
        eval_start: Instant,
        exit_code: Option<i32>,
        metrics: Option<SandboxMetrics>,
    ) -> AuditEntry {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: self.session_id.clone(),
            host: self.host.clone(),
            user: self.user.clone(),
            action: "sandbox_exec".to_string(),
            command: command.to_string(),
            executable: "python3".to_string(),
            args: String::new(),
            cwd: cwd.to_string(),
            decision,
            rule_id,
            reason,
            eval_duration_ms: eval_start.elapsed().as_millis() as u64,
            exec_duration_ms: metrics.as_ref().map(|m| m.wall_time_ms),
            exit_code,
            code_sha256: Some(code_sha256.to_string()),
            profile: Some(profile.to_string()),
            sandbox_metrics: metrics,
        };

        self.write_entry(&entry);
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: "test-session".to_string(),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            action: "exec".to_string(),
            command: "ls -la".to_string(),
            executable: "ls".to_string(),
            args: "-la".to_string(),
            cwd: "/home/test".to_string(),
            decision: Decision::Allowed,
            rule_id: Some("allow_ls".to_string()),
            reason: None,
            eval_duration_ms: 1,
            exec_duration_ms: Some(50),
            exit_code: Some(0),
            code_sha256: None,
            profile: None,
            sandbox_metrics: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"decision\":\"allowed\""));
        assert!(json.contains("\"executable\":\"ls\""));
        // Verify optional sandbox fields are not included when None
        assert!(!json.contains("code_sha256"));
        assert!(!json.contains("profile"));
        assert!(!json.contains("sandbox_metrics"));
    }

    #[test]
    fn test_audit_entry_with_sandbox_fields() {
        let metrics = SandboxMetrics::new(1500, 256, false).with_truncation(false, false);

        let entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: "test-session".to_string(),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            action: "sandbox_exec".to_string(),
            command: "print('hello')".to_string(),
            executable: "python3".to_string(),
            args: String::new(),
            cwd: "/work".to_string(),
            decision: Decision::Allowed,
            rule_id: None,
            reason: None,
            eval_duration_ms: 5,
            exec_duration_ms: Some(1500),
            exit_code: Some(0),
            code_sha256: Some("abc123def456".to_string()),
            profile: Some("python_sandbox_v1".to_string()),
            sandbox_metrics: Some(metrics),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"code_sha256\":\"abc123def456\""));
        assert!(json.contains("\"profile\":\"python_sandbox_v1\""));
        assert!(json.contains("\"wall_time_ms\":1500"));
        assert!(json.contains("\"peak_mem_mb\":256"));
        assert!(json.contains("\"timed_out\":false"));
    }

    #[test]
    fn test_sandbox_metrics() {
        let metrics = SandboxMetrics::new(2000, 512, true);
        let json = serde_json::to_string(&metrics).unwrap();

        assert!(json.contains("\"wall_time_ms\":2000"));
        assert!(json.contains("\"peak_mem_mb\":512"));
        assert!(json.contains("\"timed_out\":true"));
        // truncation fields should not be present when None
        assert!(!json.contains("truncated_stdout"));
        assert!(!json.contains("truncated_stderr"));

        let metrics_with_truncation =
            SandboxMetrics::new(1000, 128, false).with_truncation(true, false);
        let json2 = serde_json::to_string(&metrics_with_truncation).unwrap();
        assert!(json2.contains("\"truncated_stdout\":true"));
        assert!(json2.contains("\"truncated_stderr\":false"));
    }

    #[test]
    fn test_sandbox_event_serialization() {
        assert_eq!(
            serde_json::to_string(&SandboxEvent::SandboxEnter).unwrap(),
            "\"sandbox_enter\""
        );
        assert_eq!(
            serde_json::to_string(&SandboxEvent::SandboxExit).unwrap(),
            "\"sandbox_exit\""
        );
        assert_eq!(
            serde_json::to_string(&SandboxEvent::SandboxViolation).unwrap(),
            "\"sandbox_violation\""
        );
    }

    #[test]
    fn test_sandbox_audit_entry_serialization() {
        let entry = SandboxAuditEntry {
            timestamp: Utc::now(),
            session_id: "test-session".to_string(),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            event: SandboxEvent::SandboxExit,
            code_sha256: "deadbeef".to_string(),
            profile: "python_sandbox_v1".to_string(),
            details: Some("Execution completed".to_string()),
            metrics: Some(SandboxMetrics::new(1000, 256, false)),
            violation_type: None,
            exit_code: Some(0),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"event\":\"sandbox_exit\""));
        assert!(json.contains("\"code_sha256\":\"deadbeef\""));
        assert!(json.contains("\"profile\":\"python_sandbox_v1\""));
        assert!(json.contains("\"exit_code\":0"));
        assert!(!json.contains("violation_type")); // Should be skipped when None
    }

    #[test]
    fn test_sandbox_violation_entry() {
        let entry = SandboxAuditEntry {
            timestamp: Utc::now(),
            session_id: "test-session".to_string(),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            event: SandboxEvent::SandboxViolation,
            code_sha256: "deadbeef".to_string(),
            profile: "python_sandbox_v1".to_string(),
            details: Some("Attempted to access /etc/passwd".to_string()),
            metrics: None,
            violation_type: Some("filesystem_access".to_string()),
            exit_code: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"event\":\"sandbox_violation\""));
        assert!(json.contains("\"violation_type\":\"filesystem_access\""));
        assert!(json.contains("Attempted to access"));
    }

    #[test]
    fn test_sandbox_enter_entry() {
        let entry = SandboxAuditEntry {
            timestamp: Utc::now(),
            session_id: "test-session".to_string(),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            event: SandboxEvent::SandboxEnter,
            code_sha256: "abc123".to_string(),
            profile: "python_sandbox_v1".to_string(),
            details: Some("Starting sandbox execution".to_string()),
            metrics: None,
            violation_type: None,
            exit_code: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"event\":\"sandbox_enter\""));
        assert!(json.contains("\"code_sha256\":\"abc123\""));
        // metrics, violation_type, and exit_code should not be present
        assert!(!json.contains("\"metrics\""));
        assert!(!json.contains("\"violation_type\""));
        assert!(!json.contains("\"exit_code\""));
    }

    #[test]
    fn test_decision_serialization() {
        assert_eq!(
            serde_json::to_string(&Decision::Allowed).unwrap(),
            "\"allowed\""
        );
        assert_eq!(
            serde_json::to_string(&Decision::Denied).unwrap(),
            "\"denied\""
        );
        assert_eq!(
            serde_json::to_string(&Decision::AuditOnly).unwrap(),
            "\"auditonly\""
        );
    }

    #[test]
    fn test_backward_compatibility_no_sandbox_fields() {
        // Test that entries without sandbox fields serialize correctly
        // This ensures backward compatibility with existing audit format
        let entry = AuditEntry {
            timestamp: Utc::now(),
            session_id: "test".to_string(),
            host: "host".to_string(),
            user: "user".to_string(),
            action: "exec".to_string(),
            command: "pwd".to_string(),
            executable: "pwd".to_string(),
            args: String::new(),
            cwd: "/".to_string(),
            decision: Decision::Allowed,
            rule_id: None,
            reason: None,
            eval_duration_ms: 1,
            exec_duration_ms: None,
            exit_code: None,
            code_sha256: None,
            profile: None,
            sandbox_metrics: None,
        };

        let json = serde_json::to_string(&entry).unwrap();

        // Core fields should be present
        assert!(json.contains("\"action\":\"exec\""));
        assert!(json.contains("\"command\":\"pwd\""));

        // Optional fields that are None should NOT be present (skip_serializing_if)
        assert!(!json.contains("code_sha256"));
        assert!(!json.contains("profile"));
        assert!(!json.contains("sandbox_metrics"));
        assert!(!json.contains("rule_id"));
        assert!(!json.contains("reason"));
        assert!(!json.contains("exec_duration_ms"));
        assert!(!json.contains("exit_code"));
    }
}
