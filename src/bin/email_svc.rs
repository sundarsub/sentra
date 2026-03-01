//! Email Service - Polls himalaya for new emails
//! Writes trigger files to /var/lib/execwall/events/

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const EVENTS_DIR: &str = "/var/lib/execwall/events";
const STATE_FILE: &str = "/var/lib/execwall/email_seen.json";
const POLL_INTERVAL: u64 = 60; // seconds

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
struct HimalayaEnvelope {
    id: String,
    #[serde(default)]
    from: HimalayaAddress,
    subject: Option<String>,
    date: Option<String>,
    #[serde(default)]
    flags: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct HimalayaAddress {
    name: Option<String>,
    addr: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(EVENTS_DIR)?;

    let mut seen_ids = load_seen_ids();
    let mut last_check = Instant::now() - Duration::from_secs(POLL_INTERVAL);

    println!("[email-svc] Starting email watcher...");
    println!("[email-svc] Polling interval: {}s", POLL_INTERVAL);
    println!("[email-svc] Events dir: {}", EVENTS_DIR);

    loop {
        if last_check.elapsed() >= Duration::from_secs(POLL_INTERVAL) {
            last_check = Instant::now();

            match check_emails(&mut seen_ids) {
                Ok(count) => {
                    if count > 0 {
                        println!("[email-svc] Processed {} new emails", count);
                    }
                }
                Err(e) => {
                    eprintln!("[email-svc] Error checking emails: {}", e);
                }
            }
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

fn check_emails(seen_ids: &mut HashSet<String>) -> Result<usize, Box<dyn std::error::Error>> {
    // Run himalaya to list recent envelopes
    let output = Command::new("himalaya")
        .args(["envelope", "list", "-f", "INBOX", "-w", "20", "-o", "json"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("himalaya failed: {}", stderr).into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(0);
    }

    // Parse JSON response
    let envelopes: Vec<HimalayaEnvelope> = serde_json::from_str(&stdout)?;

    let mut new_count = 0;

    for envelope in envelopes {
        // Skip if already seen
        if seen_ids.contains(&envelope.id) {
            continue;
        }

        // Skip if already read (has \Seen flag)
        if envelope.flags.iter().any(|f| f.contains("Seen")) {
            seen_ids.insert(envelope.id.clone());
            continue;
        }

        seen_ids.insert(envelope.id.clone());
        save_seen_ids(seen_ids);

        // Extract email info
        let from_addr = envelope.from.addr.as_deref().unwrap_or("unknown@email");
        let from_name = envelope.from.name.clone();
        let subject = envelope.subject.as_deref().unwrap_or("(no subject)");

        println!("[email-svc] New email from {}: {}", from_addr, subject);

        // Read email body (first 500 chars)
        let body = get_email_body(&envelope.id).unwrap_or_else(|| subject.to_string());

        // Create trigger event
        let event = TriggerEvent {
            event_type: "message".to_string(),
            channel: "email".to_string(),
            from: from_addr.to_string(),
            from_name,
            content: format!("Subject: {}\n\n{}", subject, body),
            message_id: envelope.id.clone(),
            timestamp: envelope.date.unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
        };

        // Write trigger file
        let event_path = Path::new(EVENTS_DIR).join("email.json");
        std::fs::write(&event_path, serde_json::to_string_pretty(&event)?)?;

        // Wake agent
        let _ = Command::new("pkill")
            .args(["-USR1", "agentexw"])
            .output();

        new_count += 1;
    }

    Ok(new_count)
}

fn get_email_body(id: &str) -> Option<String> {
    let output = Command::new("himalaya")
        .args(["message", "read", "-f", "INBOX", id, "-t", "plain"])
        .output()
        .ok()?;

    if output.status.success() {
        let body = String::from_utf8_lossy(&output.stdout);
        // Truncate to 500 chars
        let truncated: String = body.chars().take(500).collect();
        Some(truncated)
    } else {
        None
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
    // Only keep last 500 IDs
    let ids: HashSet<String> = if seen_ids.len() > 500 {
        seen_ids.iter().take(500).cloned().collect()
    } else {
        seen_ids.clone()
    };

    if let Ok(json) = serde_json::to_string(&ids) {
        let _ = std::fs::write(STATE_FILE, json);
    }
}
