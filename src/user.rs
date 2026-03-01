//! User management for AgentExW
//!
//! Implements the owner-controlled model:
//! - One owner with full access
//! - Contacts with scoped permissions set by owner

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// The owner (controller) of the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Owner {
    pub id: String,
    pub phone: Option<String>,
    pub email: Option<String>,
}

/// A contact that the agent can interact with
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

/// Scope defining what a contact can discuss
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactScope {
    pub id: i64,
    pub contact_id: String,
    pub instruction: String,
    pub topics_allow: Vec<String>,
    pub topics_deny: Vec<String>,
    pub tools_allow: Vec<String>,
    pub expires_at: Option<String>,
}

/// User manager for database operations
pub struct UserManager {
    db_path: String,
}

impl UserManager {
    pub fn new(db_path: &str) -> Self {
        Self {
            db_path: db_path.to_string(),
        }
    }

    /// Initialize the database schema
    pub fn init_schema(&self) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        conn.execute_batch(include_str!("../schema/agentexw.sql"))?;

        Ok(())
    }

    /// Get the owner from config (loaded from policy.yaml)
    pub fn get_owner(&self) -> Result<Option<Owner>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        conn.query_row(
            "SELECT id, phone, email FROM owner LIMIT 1",
            [],
            |row| {
                Ok(Owner {
                    id: row.get(0)?,
                    phone: row.get(1)?,
                    email: row.get(2)?,
                })
            },
        )
        .optional()
    }

    /// Set the owner (called during init from policy.yaml)
    pub fn set_owner(&self, owner: &Owner) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        let phone = owner.phone.as_deref().unwrap_or("");
        let email = owner.email.as_deref().unwrap_or("");

        conn.execute(
            "INSERT OR REPLACE INTO owner (id, phone, email) VALUES (?1, ?2, ?3)",
            [&owner.id, phone, email],
        )?;

        Ok(())
    }

    /// Check if a phone number belongs to the owner
    pub fn is_owner_phone(&self, phone: &str) -> bool {
        self.get_owner()
            .ok()
            .flatten()
            .and_then(|o| o.phone)
            .map(|p| normalize_phone(&p) == normalize_phone(phone))
            .unwrap_or(false)
    }

    /// Check if an email belongs to the owner
    pub fn is_owner_email(&self, email: &str) -> bool {
        self.get_owner()
            .ok()
            .flatten()
            .and_then(|o| o.email)
            .map(|e| e.to_lowercase() == email.to_lowercase())
            .unwrap_or(false)
    }

    /// Get contact by phone number
    pub fn get_contact_by_phone(&self, phone: &str) -> Result<Option<Contact>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        let normalized = normalize_phone(phone);

        conn.query_row(
            "SELECT id, phone, email, display_name FROM contacts WHERE phone = ?1",
            [&normalized],
            |row| {
                Ok(Contact {
                    id: row.get(0)?,
                    phone: row.get(1)?,
                    email: row.get(2)?,
                    display_name: row.get(3)?,
                })
            },
        )
        .optional()
    }

    /// Get contact by email
    pub fn get_contact_by_email(&self, email: &str) -> Result<Option<Contact>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        let normalized = email.to_lowercase();

        conn.query_row(
            "SELECT id, phone, email, display_name FROM contacts WHERE LOWER(email) = ?1",
            [&normalized],
            |row| {
                Ok(Contact {
                    id: row.get(0)?,
                    phone: row.get(1)?,
                    email: row.get(2)?,
                    display_name: row.get(3)?,
                })
            },
        )
        .optional()
    }

    /// Add or update a contact
    pub fn upsert_contact(&self, contact: &Contact) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        let phone = contact.phone.as_deref().unwrap_or("");
        let email = contact.email.as_deref().unwrap_or("");
        let display_name = contact.display_name.as_deref().unwrap_or("");

        conn.execute(
            "INSERT INTO contacts (id, phone, email, display_name)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
               phone = COALESCE(?2, phone),
               email = COALESCE(?3, email),
               display_name = COALESCE(?4, display_name)",
            [&contact.id, phone, email, display_name],
        )?;

        Ok(())
    }

    /// Get all scopes for a contact
    pub fn get_contact_scopes(&self, contact_id: &str) -> Result<Vec<ContactScope>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        let mut stmt = conn.prepare(
            "SELECT id, contact_id, instruction, topics_allow, topics_deny, tools_allow, expires_at
             FROM contact_scopes
             WHERE contact_id = ?1
               AND (expires_at IS NULL OR expires_at > datetime('now'))"
        )?;

        let rows = stmt.query_map([contact_id], |row| {
            let topics_allow_json: String = row.get(3)?;
            let topics_deny_json: String = row.get(4)?;
            let tools_allow_json: String = row.get(5)?;

            Ok(ContactScope {
                id: row.get(0)?,
                contact_id: row.get(1)?,
                instruction: row.get(2)?,
                topics_allow: serde_json::from_str(&topics_allow_json).unwrap_or_default(),
                topics_deny: serde_json::from_str(&topics_deny_json).unwrap_or_default(),
                tools_allow: serde_json::from_str(&tools_allow_json).unwrap_or_default(),
                expires_at: row.get(6)?,
            })
        })?;

        rows.collect()
    }

    /// Add a scope for a contact (from owner instruction)
    pub fn add_contact_scope(&self, scope: &ContactScope) -> Result<i64, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        let topics_allow = serde_json::to_string(&scope.topics_allow).unwrap_or_default();
        let topics_deny = serde_json::to_string(&scope.topics_deny).unwrap_or_default();
        let tools_allow = serde_json::to_string(&scope.tools_allow).unwrap_or_default();
        let expires_at = scope.expires_at.as_deref().unwrap_or("");

        conn.execute(
            "INSERT INTO contact_scopes (contact_id, instruction, topics_allow, topics_deny, tools_allow, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            [
                &scope.contact_id,
                &scope.instruction,
                &topics_allow,
                &topics_deny,
                &tools_allow,
                expires_at,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Store a conversation message
    pub fn store_message(
        &self,
        participant_id: &str,
        participant_type: &str, // "owner" or "contact"
        channel: &str,
        role: &str, // "user" or "assistant"
        content: &str,
        message_id: Option<&str>,
    ) -> Result<i64, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        conn.execute(
            "INSERT INTO conversations (participant_id, participant_type, channel, role, content, message_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            [
                participant_id,
                participant_type,
                channel,
                role,
                content,
                message_id.unwrap_or(""),
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Get recent conversation history for a participant
    pub fn get_conversation_history(
        &self,
        participant_id: &str,
        limit: usize,
    ) -> Result<Vec<ConversationMessage>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        let mut stmt = conn.prepare(
            "SELECT role, content, channel, created_at
             FROM conversations
             WHERE participant_id = ?1
             ORDER BY created_at DESC
             LIMIT ?2"
        )?;

        let rows = stmt.query_map([participant_id, &limit.to_string()], |row| {
            Ok(ConversationMessage {
                role: row.get(0)?,
                content: row.get(1)?,
                channel: row.get(2)?,
                timestamp: row.get(3)?,
            })
        })?;

        // Reverse to get chronological order
        let mut messages: Vec<ConversationMessage> = rows.filter_map(|r| r.ok()).collect();
        messages.reverse();
        Ok(messages)
    }

    /// Update last seen timestamp for a contact
    pub fn touch_contact(&self, contact_id: &str) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        conn.execute(
            "UPDATE contacts SET last_seen_at = datetime('now') WHERE id = ?1",
            [contact_id],
        )?;

        Ok(())
    }

    /// List all contacts
    pub fn list_contacts(&self) -> Result<Vec<Contact>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;

        let mut stmt = conn.prepare(
            "SELECT id, phone, email, display_name FROM contacts ORDER BY display_name"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(Contact {
                id: row.get(0)?,
                phone: row.get(1)?,
                email: row.get(2)?,
                display_name: row.get(3)?,
            })
        })?;

        rows.collect()
    }
}

/// A conversation message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub role: String,
    pub content: String,
    pub channel: String,
    pub timestamp: String,
}

/// Normalize phone number for comparison (remove spaces, dashes)
fn normalize_phone(phone: &str) -> String {
    phone
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_normalize_phone() {
        assert_eq!(normalize_phone("+1 (234) 567-8900"), "+12345678900");
        assert_eq!(normalize_phone("+16468259551"), "+16468259551");
    }

    #[test]
    fn test_user_manager_owner() {
        let tmp = NamedTempFile::new().unwrap();
        let db_path = tmp.path().to_str().unwrap();

        let mgr = UserManager::new(db_path);
        mgr.init_schema().unwrap();

        let owner = Owner {
            id: "sundar".to_string(),
            phone: Some("+16468259551".to_string()),
            email: Some("sundar@example.com".to_string()),
        };

        mgr.set_owner(&owner).unwrap();

        assert!(mgr.is_owner_phone("+16468259551"));
        assert!(mgr.is_owner_email("sundar@example.com"));
        assert!(!mgr.is_owner_phone("+1234567890"));
    }
}
