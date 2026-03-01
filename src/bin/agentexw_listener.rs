//! AgentExW Message Listener
//!
//! Monitors WhatsApp and Email for new messages from allowed users.
//! Writes events to /var/lib/execwall/events/ to wake AgentExW.
//! Maintains conversation context per user.

use clap::Parser;
use execwall::user::UserManager;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "agentexw-listener")]
#[command(about = "Message listener for AgentExW")]
struct Args {
    /// Path to policy configuration
    #[arg(long, default_value = "/etc/execwall/policy.yaml")]
    policy: String,

    /// Path to SQLite database
    #[arg(long, default_value = "/var/lib/execwall/agent_memory.db")]
    db: String,

    /// OpenClaw sessions directory
    #[arg(long, default_value = "")]
    openclaw_sessions: String,

    /// Email check interval in seconds
    #[arg(long, default_value = "60")]
    email_interval: u64,

    /// Debounce duration in milliseconds
    #[arg(long, default_value = "1000")]
    debounce_ms: u64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IncomingMessage {
    user_id: Option<String>,
    channel: String,
    from: String,
    content: String,
    message_id: String,
    timestamp: String,
    is_owner: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let user_mgr = UserManager::new(&args.db);
    let mut debounce_map: HashMap<String, Instant> = HashMap::new();
    let debounce_duration = Duration::from_millis(args.debounce_ms);

    // Determine OpenClaw sessions path
    let home = std::env::var("HOME").unwrap_or_default();
    let openclaw_sessions = if args.openclaw_sessions.is_empty() {
        format!("{}/.openclaw/agents/main/sessions", home)
    } else {
        args.openclaw_sessions.clone()
    };

    // Set up file watcher
    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )?;

    // Watch OpenClaw sessions directory if it exists
    let wa_path = Path::new(&openclaw_sessions);
    if wa_path.exists() {
        watcher.watch(wa_path, RecursiveMode::NonRecursive)?;
        log(&args, &format!("Watching WhatsApp sessions at {}", openclaw_sessions));
    } else {
        log(&args, &format!("WhatsApp sessions path not found: {}", openclaw_sessions));
    }

    // Email check timer
    let email_interval = Duration::from_secs(args.email_interval);
    let mut last_email_check = Instant::now();

    log(&args, "AgentExW Listener started");

    loop {
        // Check for WhatsApp file changes (non-blocking with timeout)
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(event) => {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    for path in event.paths {
                        if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
                            // Process WhatsApp session update
                            if let Some(msg) = parse_whatsapp_session(&path, &user_mgr) {
                                // Debounce
                                let key = format!("wa:{}", msg.from);
                                if let Some(last) = debounce_map.get(&key) {
                                    if last.elapsed() < debounce_duration {
                                        continue;
                                    }
                                }
                                debounce_map.insert(key, Instant::now());

                                // Process message
                                process_message(&args, &user_mgr, &msg)?;
                            }
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => {
                log(&args, &format!("Watch error: {}", e));
            }
        }

        // Periodic email check
        if last_email_check.elapsed() >= email_interval {
            last_email_check = Instant::now();

            if let Ok(emails) = check_emails(&args, &user_mgr) {
                for msg in emails {
                    // Debounce by message ID
                    let key = format!("email:{}", msg.message_id);
                    if debounce_map.contains_key(&key) {
                        continue;
                    }
                    debounce_map.insert(key, Instant::now());

                    process_message(&args, &user_mgr, &msg)?;
                }
            }
        }

        // Clean old debounce entries (older than 5 minutes)
        let cutoff = Duration::from_secs(300);
        debounce_map.retain(|_, v| v.elapsed() < cutoff);
    }
}

fn parse_whatsapp_session(
    session_path: &Path,
    user_mgr: &UserManager,
) -> Option<IncomingMessage> {
    // Read the session file
    let content = std::fs::read_to_string(session_path).ok()?;

    // Get last line (most recent message)
    let last_line = content.lines().last()?;

    // Parse JSONL entry
    let entry: serde_json::Value = serde_json::from_str(last_line).ok()?;

    // OpenClaw format: {"type":"message","id":"...","message":{"role":"user","content":[...]}}
    let msg_obj = entry.get("message")?;

    // Check if it's a user message
    let role = msg_obj.get("role")?.as_str()?;
    if role != "user" {
        return None;
    }

    // Get message ID from top level
    let message_id = entry
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string();

    // Extract content from message object
    let content_text = msg_obj
        .get("content")
        .and_then(|c| {
            if c.is_string() {
                c.as_str().map(|s| s.to_string())
            } else if c.is_array() {
                // Handle array format [{"type":"text","text":"..."}]
                c.as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|first| first.get("text"))
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
            } else {
                None
            }
        })?;

    // Get phone from sessions.json
    let session_id = session_path.file_stem()?.to_str()?;
    let sessions_json_path = session_path.parent()?.join("sessions.json");
    let from = if let Ok(sessions_content) = std::fs::read_to_string(&sessions_json_path) {
        if let Ok(sessions) = serde_json::from_str::<serde_json::Value>(&sessions_content) {
            // Find session with matching sessionId
            sessions.as_object()
                .and_then(|obj| {
                    obj.values().find(|v| {
                        v.get("sessionId").and_then(|s| s.as_str()) == Some(session_id)
                    })
                })
                .and_then(|session| {
                    session.get("origin")
                        .and_then(|o| o.get("from"))
                        .and_then(|f| f.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    // Check if from owner
    let is_owner = user_mgr.is_owner_phone(&from);

    // Try to resolve user
    let user_id = if is_owner {
        user_mgr
            .get_owner()
            .ok()
            .flatten()
            .map(|o| o.id)
    } else {
        user_mgr
            .get_contact_by_phone(&from)
            .ok()
            .flatten()
            .map(|c| c.id)
    };

    Some(IncomingMessage {
        user_id,
        channel: "whatsapp".to_string(),
        from: from.to_string(),
        content: content_text,
        message_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        is_owner,
    })
}

fn check_emails(
    args: &Args,
    user_mgr: &UserManager,
) -> Result<Vec<IncomingMessage>, Box<dyn std::error::Error>> {
    let mut messages = vec![];

    // Use himalaya to check for unread emails
    let output = std::process::Command::new("himalaya")
        .args(["envelope", "list", "-f", "INBOX", "-w", "10", "-o", "json"])
        .output()?;

    if !output.status.success() {
        return Ok(messages);
    }

    let envelopes: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;

    for env in envelopes {
        let from_raw = env.get("from").and_then(|f| f.as_str()).unwrap_or("");
        let subject = env.get("subject").and_then(|s| s.as_str()).unwrap_or("");
        let id = env.get("id").and_then(|i| i.as_str()).unwrap_or("");

        // Extract email address
        let email_addr = extract_email_address(from_raw);

        // Check if from owner
        let is_owner = user_mgr.is_owner_email(&email_addr);

        // Try to resolve user
        let user_id = if is_owner {
            user_mgr.get_owner().ok().flatten().map(|o| o.id)
        } else {
            user_mgr
                .get_contact_by_email(&email_addr)
                .ok()
                .flatten()
                .map(|c| c.id)
        };

        // Only process if from known user
        if user_id.is_some() || is_owner {
            messages.push(IncomingMessage {
                user_id,
                channel: "email".to_string(),
                from: email_addr,
                content: subject.to_string(),
                message_id: id.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                is_owner,
            });
        }
    }

    Ok(messages)
}

fn process_message(
    args: &Args,
    user_mgr: &UserManager,
    msg: &IncomingMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    log(
        args,
        &format!(
            "Message from {} via {}: {}",
            msg.from,
            msg.channel,
            truncate(&msg.content, 50)
        ),
    );

    // Determine participant type
    let (participant_id, participant_type) = if msg.is_owner {
        (
            msg.user_id.clone().unwrap_or_else(|| "owner".to_string()),
            "owner",
        )
    } else if let Some(ref uid) = msg.user_id {
        (uid.clone(), "contact")
    } else {
        // Unknown sender - ignore
        log(args, &format!("Ignoring message from unknown sender: {}", msg.from));
        return Ok(());
    };

    // Store in conversation history
    user_mgr.store_message(
        &participant_id,
        participant_type,
        &msg.channel,
        "user",
        &msg.content,
        Some(&msg.message_id),
    )?;

    // Update last seen for contacts
    if participant_type == "contact" {
        user_mgr.touch_contact(&participant_id)?;
    }

    // Write event to wake AgentExW
    write_event(&msg.channel, msg)?;

    Ok(())
}

fn write_event(channel: &str, msg: &IncomingMessage) -> Result<(), std::io::Error> {
    let event_dir = Path::new("/var/lib/execwall/events");

    // Create directory if needed
    if !event_dir.exists() {
        std::fs::create_dir_all(event_dir)?;
    }

    let event_file = event_dir.join(channel);
    let event_data = serde_json::to_string(msg)?;
    std::fs::write(&event_file, &event_data)?;

    Ok(())
}

fn extract_email_address(from: &str) -> String {
    // "Name <email@example.com>" -> "email@example.com"
    if let Some(start) = from.find('<') {
        if let Some(end) = from.find('>') {
            return from[start + 1..end].to_string();
        }
    }
    from.to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

fn log(args: &Args, msg: &str) {
    if args.verbose || std::env::var("JOURNAL_STREAM").is_ok() {
        eprintln!("[listener] {}", msg);
    }
}
