//! WhatsApp Service - Polls wacli for incoming messages
//! Writes trigger files to /var/lib/execwall/events/

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const EVENTS_DIR: &str = "/var/lib/execwall/events";
const STATE_FILE: &str = "/var/lib/execwall/whatsapp_seen.json";
const POLL_INTERVAL: u64 = 5; // Check every 5 seconds
const SYNC_INTERVAL: u64 = 30; // Sync every 30 seconds
const OWNER_PHONE: &str = "16173597259"; // Only process messages from owner

#[derive(Debug, Serialize)]
struct TriggerEvent {
    #[serde(rename = "type")]
    event_type: String,
    channel: String,
    from: String,
    from_name: Option<String>,
    content: String,
    message_id: String,
    timestamp: String,
}

#[derive(Debug, Deserialize)]
struct WacliResponse {
    success: bool,
    data: Option<WacliData>,
}

#[derive(Debug, Deserialize)]
struct WacliData {
    messages: Vec<WacliMessage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WacliMessage {
    #[serde(rename = "MsgID")]
    msg_id: String,
    #[serde(rename = "ChatJID")]
    chat_jid: String,
    chat_name: Option<String>,
    #[serde(rename = "SenderJID")]
    sender_jid: String,
    timestamp: String,
    from_me: bool,
    text: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(EVENTS_DIR)?;

    let mut seen_ids = load_seen_ids();
    let mut sync_counter: u64 = 0;

    println!("[whatsapp-svc] Starting WhatsApp message watcher...");
    println!("[whatsapp-svc] Poll interval: {}s, Sync interval: {}s", POLL_INTERVAL, SYNC_INTERVAL);
    println!("[whatsapp-svc] Events dir: {}", EVENTS_DIR);

    loop {
        // Sync periodically to get new messages from WhatsApp servers
        if sync_counter % (SYNC_INTERVAL / POLL_INTERVAL) == 0 {
            let _ = run_sync();
        }
        sync_counter += 1;

        // Check for new messages
        match check_messages(&mut seen_ids) {
            Ok(count) => {
                if count > 0 {
                    println!("[whatsapp-svc] Processed {} new messages", count);
                }
            }
            Err(e) => {
                eprintln!("[whatsapp-svc] Error checking messages: {}", e);
            }
        }

        std::thread::sleep(Duration::from_secs(POLL_INTERVAL));
    }
}

fn run_sync() -> Result<(), Box<dyn std::error::Error>> {
    // Don't sync - just rely on messages already in the database
    // wacli sync can take a long time and block the service
    // The database already has messages from previous syncs
    Ok(())
}

fn check_messages(seen_ids: &mut HashSet<String>) -> Result<usize, Box<dyn std::error::Error>> {
    // Get recent messages
    let output = Command::new("wacli")
        .args(["messages", "list", "--json", "--limit", "50"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("wacli messages failed: {}", stderr).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let response: WacliResponse = serde_json::from_str(&stdout)?;

    if !response.success {
        return Err("wacli returned success=false".into());
    }

    let messages = response.data.map(|d| d.messages).unwrap_or_default();
    let mut new_count = 0;

    for msg in messages {
        // Skip bot-sent messages (FromMe=true AND empty SenderJID)
        // User messages from same account have SenderJID populated
        if msg.from_me && msg.sender_jid.is_empty() {
            continue;
        }

        // Only process messages from owner's chat
        if !msg.chat_jid.contains(OWNER_PHONE) {
            continue;
        }

        // Skip if already seen
        if seen_ids.contains(&msg.msg_id) {
            continue;
        }

        // Skip empty messages
        if msg.text.is_empty() {
            seen_ids.insert(msg.msg_id.clone());
            continue;
        }

        // Mark as seen
        seen_ids.insert(msg.msg_id.clone());
        save_seen_ids(seen_ids);

        // Extract phone from JID
        let phone = extract_phone_from_jid(&msg.sender_jid);
        if phone.is_empty() {
            // Use chat JID as fallback
            let phone = extract_phone_from_jid(&msg.chat_jid);
            if phone.is_empty() {
                continue;
            }
        }

        let phone = if msg.sender_jid.is_empty() {
            extract_phone_from_jid(&msg.chat_jid)
        } else {
            extract_phone_from_jid(&msg.sender_jid)
        };

        println!("[whatsapp-svc] New message from {} ({}): {}...",
                 msg.chat_name.as_deref().unwrap_or("Unknown"),
                 phone,
                 &msg.text[..msg.text.len().min(50)]);

        // Create trigger event
        let event = TriggerEvent {
            event_type: "message".to_string(),
            channel: "whatsapp".to_string(),
            from: phone,
            from_name: msg.chat_name,
            content: msg.text,
            message_id: msg.msg_id,
            timestamp: msg.timestamp,
        };

        // Write trigger file
        let event_path = Path::new(EVENTS_DIR).join("whatsapp.json");
        std::fs::write(&event_path, serde_json::to_string_pretty(&event)?)?;

        // Wake agent
        let _ = Command::new("pkill")
            .args(["-USR1", "agentexw"])
            .output();

        new_count += 1;
    }

    Ok(new_count)
}

fn extract_phone_from_jid(jid: &str) -> String {
    // JID format: 14155551234@s.whatsapp.net
    let phone = jid.split('@').next().unwrap_or(jid);
    if phone.is_empty() {
        return String::new();
    }
    if phone.starts_with('+') {
        phone.to_string()
    } else {
        format!("+{}", phone)
    }
}

fn load_seen_ids() -> HashSet<String> {
    if let Ok(data) = std::fs::read_to_string(STATE_FILE) {
        if let Ok(ids) = serde_json::from_str(&data) {
            return ids;
        }
    }
    HashSet::new()
}

fn save_seen_ids(seen_ids: &HashSet<String>) {
    // Only keep last 1000 IDs
    let ids: HashSet<String> = if seen_ids.len() > 1000 {
        seen_ids.iter().take(1000).cloned().collect()
    } else {
        seen_ids.clone()
    };

    if let Ok(json) = serde_json::to_string(&ids) {
        let _ = std::fs::write(STATE_FILE, json);
    }
}
