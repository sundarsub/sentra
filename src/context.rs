//! Context Aggregator for AgentExW
//!
//! Collects all relevant context for agent decision-making:
//! - Pending tasks and reminders
//! - Upcoming calendar events
//! - Unread messages
//! - Fund alerts

use chrono::Utc;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::process::Command;

/// Snapshot of all relevant context for agent decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSnapshot {
    pub timestamp: String,
    pub pending_tasks: Vec<TaskItem>,
    pub overdue_reminders: Vec<Reminder>,
    pub upcoming_events: Vec<CalendarEvent>,
    pub unread_messages: Vec<UnreadMessage>,
    pub new_messages: Vec<NewMessage>,
    pub fund_alerts: Vec<FundAlert>,
    pub pending_approvals: Vec<PendingApproval>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskItem {
    pub id: i64,
    pub content: String,
    pub due: Option<String>,
    pub priority: i32,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reminder {
    pub id: i64,
    pub content: String,
    pub due: String,
    pub minutes_overdue: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarEvent {
    pub id: String,
    pub summary: String,
    pub start: String,
    pub end: String,
    pub minutes_until: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnreadMessage {
    pub source: String,
    pub from: String,
    pub from_id: Option<String>,
    pub preview: String,
    pub received_at: String,
    pub priority: String,
}

/// New message from WhatsApp/Email that needs processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMessage {
    pub id: i64,
    pub participant_id: String,
    pub participant_phone: Option<String>,
    pub channel: String,
    pub content: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundAlert {
    pub alert_type: String,
    pub message: String,
    pub severity: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: i64,
    pub tool: String,
    pub args: String,
    pub reason: Option<String>,
    pub requested_by: Option<String>,
    pub created_at: String,
}

/// Context aggregator collects all relevant data
pub struct ContextAggregator {
    db_path: String,
    policy_path: String,
}

impl ContextAggregator {
    pub fn new(db_path: &str, policy_path: &str) -> Self {
        Self {
            db_path: db_path.to_string(),
            policy_path: policy_path.to_string(),
        }
    }

    /// Collect full context snapshot
    pub fn collect(&self) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
        let conn = Connection::open(&self.db_path)?;
        let now = Utc::now();

        Ok(ContextSnapshot {
            timestamp: now.to_rfc3339(),
            pending_tasks: self.get_pending_tasks(&conn)?,
            overdue_reminders: self.get_overdue_reminders(&conn)?,
            upcoming_events: self.get_upcoming_events()?,
            unread_messages: self.get_unread_messages()?,
            new_messages: self.get_new_messages(&conn)?,
            fund_alerts: self.get_fund_alerts()?,
            pending_approvals: self.get_pending_approvals(&conn)?,
        })
    }

    /// Collect context scoped to a specific contact
    pub fn collect_for_contact(
        &self,
        _contact_id: &str,
    ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
        // For contacts, we return a minimal context
        // The full context is only for the owner
        let now = Utc::now();

        Ok(ContextSnapshot {
            timestamp: now.to_rfc3339(),
            pending_tasks: vec![],
            overdue_reminders: vec![],
            upcoming_events: vec![],
            unread_messages: vec![],
            new_messages: vec![],
            fund_alerts: vec![],
            pending_approvals: vec![],
        })
    }

    fn get_pending_tasks(&self, conn: &Connection) -> Result<Vec<TaskItem>, rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT id, content, due, priority, source
             FROM tasks
             WHERE status = 'pending'
             ORDER BY COALESCE(due, '9999-12-31'), priority DESC
             LIMIT 50",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(TaskItem {
                id: row.get(0)?,
                content: row.get(1)?,
                due: row.get(2)?,
                priority: row.get(3)?,
                source: row.get(4)?,
            })
        })?;

        rows.collect()
    }

    fn get_overdue_reminders(&self, conn: &Connection) -> Result<Vec<Reminder>, rusqlite::Error> {
        let now = Utc::now().to_rfc3339();

        let mut stmt = conn.prepare(
            "SELECT id, content, due,
                    CAST((julianday('now') - julianday(due)) * 24 * 60 AS INTEGER) as minutes_overdue
             FROM reminders
             WHERE status = 'pending' AND due <= ?1
             ORDER BY due
             LIMIT 20",
        )?;

        let rows = stmt.query_map([&now], |row| {
            Ok(Reminder {
                id: row.get(0)?,
                content: row.get(1)?,
                due: row.get(2)?,
                minutes_overdue: row.get::<_, i64>(3)?.max(0),
            })
        })?;

        rows.collect()
    }

    fn get_upcoming_events(&self) -> Result<Vec<CalendarEvent>, Box<dyn std::error::Error>> {
        // Try to get calendar events via gcal tool
        let output = Command::new("gcal")
            .args(["list", "--json", "--hours", "24"])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let events: Vec<CalendarEvent> =
                    serde_json::from_slice(&out.stdout).unwrap_or_default();
                Ok(events)
            }
            _ => Ok(vec![]),
        }
    }

    fn get_unread_messages(&self) -> Result<Vec<UnreadMessage>, Box<dyn std::error::Error>> {
        let mut messages = vec![];

        // Check for unread emails via himalaya
        let email_output = Command::new("himalaya")
            .args(["envelope", "list", "-f", "INBOX", "-w", "10", "-o", "json"])
            .output();

        if let Ok(out) = email_output {
            if out.status.success() {
                if let Ok(envelopes) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout)
                {
                    for env in envelopes.iter().take(10) {
                        let from = env
                            .get("from")
                            .and_then(|f| f.as_str())
                            .unwrap_or("unknown");
                        let subject = env
                            .get("subject")
                            .and_then(|s| s.as_str())
                            .unwrap_or("(no subject)");

                        messages.push(UnreadMessage {
                            source: "email".to_string(),
                            from: from.to_string(),
                            from_id: None,
                            preview: subject.to_string(),
                            received_at: Utc::now().to_rfc3339(),
                            priority: "normal".to_string(),
                        });
                    }
                }
            }
        }

        Ok(messages)
    }

    fn get_fund_alerts(&self) -> Result<Vec<FundAlert>, Box<dyn std::error::Error>> {
        // Check for fund alerts in the events directory
        let alert_file = std::path::Path::new("/var/lib/execwall/events/fund_alerts");

        if alert_file.exists() {
            if let Ok(content) = std::fs::read_to_string(alert_file) {
                if let Ok(alerts) = serde_json::from_str::<Vec<FundAlert>>(&content) {
                    return Ok(alerts);
                }
            }
        }

        Ok(vec![])
    }

    fn get_pending_approvals(
        &self,
        conn: &Connection,
    ) -> Result<Vec<PendingApproval>, rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT id, tool, args, reason, requested_by, created_at
             FROM pending_approvals
             WHERE status = 'pending'
             ORDER BY created_at DESC
             LIMIT 20",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(PendingApproval {
                id: row.get(0)?,
                tool: row.get(1)?,
                args: row.get(2)?,
                reason: row.get(3)?,
                requested_by: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;

        rows.collect()
    }

    fn get_new_messages(&self, conn: &Connection) -> Result<Vec<NewMessage>, rusqlite::Error> {
        // Get unprocessed messages (user role messages without a corresponding agent response)
        let mut stmt = conn.prepare(
            "SELECT c.id, c.participant_id, c.channel, c.content, c.created_at,
                    (SELECT phone FROM contacts WHERE id = c.participant_id) as participant_phone
             FROM conversations c
             WHERE c.role = 'user'
               AND c.processed IS NULL
             ORDER BY c.created_at
             LIMIT 20",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(NewMessage {
                id: row.get(0)?,
                participant_id: row.get(1)?,
                channel: row.get(2)?,
                content: row.get(3)?,
                created_at: row.get(4)?,
                participant_phone: row.get(5)?,
            })
        })?;

        rows.collect()
    }

    /// Mark messages as processed
    pub fn mark_messages_processed(&self, message_ids: &[i64]) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        for id in message_ids {
            conn.execute(
                "UPDATE conversations SET processed = datetime('now') WHERE id = ?1",
                [id],
            )?;
        }

        Ok(())
    }
}

/// Quick check if context warrants immediate action
pub fn needs_immediate_action(context: &ContextSnapshot) -> bool {
    // Act if there are new messages to process
    if !context.new_messages.is_empty() {
        return true;
    }

    // Act if there are overdue reminders
    if !context.overdue_reminders.is_empty() {
        return true;
    }

    // Act if there are high-priority unread messages
    if context
        .unread_messages
        .iter()
        .any(|m| m.priority == "high")
    {
        return true;
    }

    // Act if there are upcoming events within 15 minutes
    if context
        .upcoming_events
        .iter()
        .any(|e| e.minutes_until <= 15 && e.minutes_until >= 0)
    {
        return true;
    }

    // Act if there are fund alerts
    if !context.fund_alerts.is_empty() {
        return true;
    }

    // Act if there are pending approvals
    if !context.pending_approvals.is_empty() {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_immediate_action_empty() {
        let ctx = ContextSnapshot {
            timestamp: Utc::now().to_rfc3339(),
            pending_tasks: vec![],
            overdue_reminders: vec![],
            upcoming_events: vec![],
            unread_messages: vec![],
            new_messages: vec![],
            fund_alerts: vec![],
            pending_approvals: vec![],
        };

        assert!(!needs_immediate_action(&ctx));
    }

    #[test]
    fn test_needs_immediate_action_overdue() {
        let ctx = ContextSnapshot {
            timestamp: Utc::now().to_rfc3339(),
            pending_tasks: vec![],
            overdue_reminders: vec![Reminder {
                id: 1,
                content: "Test".to_string(),
                due: "2026-01-01".to_string(),
                minutes_overdue: 60,
            }],
            upcoming_events: vec![],
            unread_messages: vec![],
            new_messages: vec![],
            fund_alerts: vec![],
            pending_approvals: vec![],
        };

        assert!(needs_immediate_action(&ctx));
    }
}
