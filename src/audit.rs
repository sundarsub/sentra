use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

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
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"decision\":\"allowed\""));
        assert!(json.contains("\"executable\":\"ls\""));
    }

    #[test]
    fn test_decision_serialization() {
        assert_eq!(serde_json::to_string(&Decision::Allowed).unwrap(), "\"allowed\"");
        assert_eq!(serde_json::to_string(&Decision::Denied).unwrap(), "\"denied\"");
        assert_eq!(serde_json::to_string(&Decision::AuditOnly).unwrap(), "\"auditonly\"");
    }
}
