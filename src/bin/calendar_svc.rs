//! Calendar Service - Polls gcal (gcsa-based) for upcoming events
//! Writes trigger files to /var/lib/execwall/events/

use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const EVENTS_DIR: &str = "/var/lib/execwall/events";
const STATE_FILE: &str = "/var/lib/execwall/calendar_notified.json";
const POLL_INTERVAL: u64 = 300; // 5 minutes
const GCAL_PATH: &str = "/home/opc/.local/bin/gcal";
const REMINDER_MINUTES: i64 = 15; // For display purposes

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(EVENTS_DIR)?;

    let mut notified = load_notified();
    let mut last_check = Instant::now() - Duration::from_secs(POLL_INTERVAL);

    println!("[calendar-svc] Starting calendar watcher...");
    println!("[calendar-svc] Polling interval: {}s", POLL_INTERVAL);
    println!("[calendar-svc] Reminder window: {} minutes", REMINDER_MINUTES);
    println!("[calendar-svc] Events dir: {}", EVENTS_DIR);

    loop {
        if last_check.elapsed() >= Duration::from_secs(POLL_INTERVAL) {
            last_check = Instant::now();

            match check_upcoming_events(&mut notified) {
                Ok(count) => {
                    if count > 0 {
                        println!("[calendar-svc] Notified about {} upcoming events", count);
                    }
                }
                Err(e) => {
                    eprintln!("[calendar-svc] Error checking calendar: {}", e);
                }
            }

            // Clean old notifications
            clean_old_notified(&mut notified);
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

fn check_upcoming_events(notified: &mut HashSet<String>) -> Result<usize, Box<dyn std::error::Error>> {
    // Run gcal to list events for next 1 day (we filter by time in parsing)
    let output = Command::new(GCAL_PATH)
        .args(["list", "1"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore Python warnings
        if !stderr.contains("FutureWarning") {
            return Err(format!("gcal failed: {}", stderr).into());
        }
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut new_count = 0;

    // Parse gcal output format: "• 2026-03-01 14:00: Meeting Title"
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.contains("No upcoming events") || line.starts_with("===") {
            continue;
        }

        // Skip lines that don't start with bullet
        if !line.starts_with('•') && !line.starts_with('-') {
            continue;
        }

        // Parse "• 2026-03-01 14:00: Title"
        let content = line.trim_start_matches('•').trim_start_matches('-').trim();

        // Split on first colon after the time
        if let Some(colon_pos) = content.find(": ") {
            let datetime_str = &content[..colon_pos];
            let title = &content[colon_pos + 2..];

            // Check if event is within next 15 minutes
            if let Ok(event_time) = chrono::NaiveDateTime::parse_from_str(datetime_str, "%Y-%m-%d %H:%M") {
                let now = chrono::Local::now().naive_local();
                let diff = event_time.signed_duration_since(now);

                // Only trigger for events 0-15 minutes away
                if diff.num_minutes() > 15 || diff.num_minutes() < 0 {
                    continue;
                }

                let event_key = format!("{}:{}", datetime_str, title);

                // Skip if already notified
                if notified.contains(&event_key) {
                    continue;
                }
                notified.insert(event_key.clone());
                save_notified(notified);

                println!("[calendar-svc] Upcoming event: {} at {}", title, datetime_str);

                // Create trigger event
                let event = TriggerEvent {
                    event_type: "calendar".to_string(),
                    channel: "calendar".to_string(),
                    from: "calendar".to_string(),
                    from_name: None,
                    content: format!("Upcoming event in {} minutes: {} at {}",
                                   diff.num_minutes(), title, datetime_str),
                    message_id: event_key,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };

                // Write trigger file
                let event_path = Path::new(EVENTS_DIR).join("calendar.json");
                std::fs::write(&event_path, serde_json::to_string_pretty(&event)?)?;

                // Wake agent
                let _ = Command::new("pkill")
                    .args(["-USR1", "agentexw"])
                    .output();

                new_count += 1;
            }
        }
    }

    Ok(new_count)
}

fn clean_old_notified(notified: &mut HashSet<String>) {
    // Keep only last 100 entries
    if notified.len() > 100 {
        let keep: HashSet<String> = notified.iter().take(100).cloned().collect();
        *notified = keep;
        save_notified(notified);
    }
}

fn load_notified() -> HashSet<String> {
    if let Ok(data) = std::fs::read_to_string(STATE_FILE) {
        if let Ok(ids) = serde_json::from_str(&data) {
            return ids;
        }
    }
    HashSet::new()
}

fn save_notified(notified: &HashSet<String>) {
    if let Ok(json) = serde_json::to_string(notified) {
        let _ = std::fs::write(STATE_FILE, json);
    }
}
