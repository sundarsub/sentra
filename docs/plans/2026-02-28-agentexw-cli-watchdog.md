# AgentExW CLI + Watchdog Architecture

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace OpenClaw agent with pure CLI tools + file-based watchdog events for WhatsApp, Email, Calendar.

**Architecture:** File watchers detect incoming events, write trigger files. Main loop processes triggers + SQLite todos. Claude API makes decisions. CLI tools execute actions.

**Tech Stack:** whatsapp-cli (Go), himalaya (Rust), gcalcli (Python), notify crate (Rust file watcher), SQLite

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         AgentExW                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐ │
│  │   Main Loop      │  │  File Watcher    │  │   SQLite DB   │ │
│  │   (300s timer    │  │  /var/lib/       │  │   - todos     │ │
│  │    + events)     │  │  execwall/events │  │   - memory    │ │
│  └────────┬─────────┘  └────────┬─────────┘  │   - contacts  │ │
│           │                     │            └───────────────┘ │
│           └──────────┬──────────┘                              │
│                      ▼                                          │
│           ┌──────────────────┐                                  │
│           │   Claude API     │                                  │
│           │   (Anthropic)    │                                  │
│           └────────┬─────────┘                                  │
│                    │                                            │
│    ┌───────────────┼───────────────┐                           │
│    ▼               ▼               ▼                           │
│ ┌──────────┐  ┌──────────┐  ┌──────────┐                       │
│ │whatsapp- │  │ himalaya │  │ gcalcli  │                       │
│ │cli       │  │          │  │          │                       │
│ └──────────┘  └──────────┘  └──────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

## Event Flow

```
1. WhatsApp message arrives
   → whatsapp-cli sync writes to SQLite
   → watcher detects change
   → writes /var/lib/execwall/events/whatsapp

2. Email arrives
   → himalaya envelope list (polled)
   → new email detected
   → writes /var/lib/execwall/events/email

3. Calendar reminder due
   → gcalcli remind (cron or polled)
   → writes /var/lib/execwall/events/calendar

4. AgentExW main loop
   → reads event files
   → aggregates context from SQLite
   → calls Claude API with tools
   → executes tool calls via CLI
   → deletes processed event files
```

---

## Task 1: Install whatsapp-cli

**Files:**
- Install: `/usr/local/bin/whatsapp-cli`

**Step 1: Install Go whatsapp-cli**

```bash
# On Oracle server
ssh opc@193.122.147.218

# Install Go if needed
sudo dnf install -y golang

# Install whatsapp-cli
go install github.com/vicentereig/whatsapp-cli@latest

# Link to path
sudo ln -sf ~/go/bin/whatsapp-cli /usr/local/bin/whatsapp-cli
```

**Step 2: Link WhatsApp (QR code)**

```bash
whatsapp-cli link
# Scan QR code with phone
```

**Step 3: Test send**

```bash
whatsapp-cli send --to "+16173597259" --message "Test from CLI"
```

**Step 4: Start sync daemon**

```bash
# Run in background or tmux
whatsapp-cli sync &
```

**Step 5: Commit**

```bash
# No code changes yet - just server setup
```

---

## Task 2: Install gcalcli

**Files:**
- Install: `~/.local/bin/gcalcli`

**Step 1: Install gcalcli**

```bash
pip install gcalcli
```

**Step 2: Authenticate**

```bash
# Set up OAuth (requires client ID from Google Cloud Console)
gcalcli --client-id=YOUR_CLIENT_ID.apps.googleusercontent.com init
```

**Step 3: Test list**

```bash
gcalcli agenda --nocolor
gcalcli calw  # Week view
```

**Step 4: Test add**

```bash
gcalcli add --title "Test Event" --when "tomorrow 2pm" --duration 30
```

---

## Task 3: Create CLI wrapper scripts

**Files:**
- Create: `/usr/lib/execwall/tools/wa_send`
- Create: `/usr/lib/execwall/tools/wa_check`
- Create: `/usr/lib/execwall/tools/email_send`
- Create: `/usr/lib/execwall/tools/email_check`
- Create: `/usr/lib/execwall/tools/cal_list`
- Create: `/usr/lib/execwall/tools/cal_add`

**Step 1: wa_send wrapper**

```bash
#!/bin/bash
# /usr/lib/execwall/tools/wa_send
# Usage: wa_send <phone> <message>

PHONE="${1:-$WA_TO}"
MSG="${2:-$WA_MESSAGE}"

if [ -z "$PHONE" ] || [ -z "$MSG" ]; then
    echo '{"error": "Usage: wa_send <phone> <message>"}'
    exit 1
fi

whatsapp-cli send --to "$PHONE" --message "$MSG" --json 2>&1
```

**Step 2: wa_check wrapper**

```bash
#!/bin/bash
# /usr/lib/execwall/tools/wa_check
# Returns unread messages as JSON

whatsapp-cli list --unread --json 2>&1
```

**Step 3: email_send wrapper**

```bash
#!/bin/bash
# /usr/lib/execwall/tools/email_send
# Usage: email_send <to> <subject> <body>

TO="$1"
SUBJECT="$2"
BODY="$3"

if [ -z "$TO" ] || [ -z "$SUBJECT" ]; then
    echo '{"error": "Usage: email_send <to> <subject> <body>"}'
    exit 1
fi

himalaya send <<EOF
To: $TO
Subject: $SUBJECT

$BODY
EOF
```

**Step 4: email_check wrapper**

```bash
#!/bin/bash
# /usr/lib/execwall/tools/email_check
# Returns recent unread emails as JSON

himalaya envelope list -f INBOX -w 10 -o json 2>&1
```

**Step 5: cal_list wrapper**

```bash
#!/bin/bash
# /usr/lib/execwall/tools/cal_list
# Usage: cal_list [days]

DAYS="${1:-7}"
gcalcli agenda --nocolor --tsv "now" "+${DAYS}d" 2>&1
```

**Step 6: cal_add wrapper**

```bash
#!/bin/bash
# /usr/lib/execwall/tools/cal_add
# Usage: cal_add <title> <when> [duration_minutes]

TITLE="$1"
WHEN="$2"
DURATION="${3:-60}"

if [ -z "$TITLE" ] || [ -z "$WHEN" ]; then
    echo '{"error": "Usage: cal_add <title> <when> [duration]"}'
    exit 1
fi

gcalcli add --title "$TITLE" --when "$WHEN" --duration "$DURATION" --noprompt 2>&1
```

**Step 7: Make executable and commit**

```bash
chmod +x /usr/lib/execwall/tools/*
```

---

## Task 4: Create Event Watcher Daemon

**Files:**
- Create: `src/bin/agentexw_watcher.rs`

**Step 1: Create watcher that monitors CLI tool outputs**

```rust
//! AgentExW Event Watcher
//!
//! Watches for:
//! 1. whatsapp-cli sync SQLite changes
//! 2. New emails (polls himalaya)
//! 3. Calendar reminders (polls gcalcli)
//!
//! Writes trigger files to /var/lib/execwall/events/

use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::process::Command;

const EVENTS_DIR: &str = "/var/lib/execwall/events";
const EMAIL_POLL_SECS: u64 = 60;
const CAL_POLL_SECS: u64 = 300;

#[derive(Debug, Serialize)]
struct TriggerEvent {
    channel: String,
    from: String,
    content: String,
    timestamp: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure events directory exists
    std::fs::create_dir_all(EVENTS_DIR)?;

    // Watch whatsapp-cli database for changes
    let wa_db = dirs::data_local_dir()
        .unwrap_or_default()
        .join("whatsapp-cli/messages.db");

    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )?;

    if wa_db.exists() {
        watcher.watch(&wa_db, RecursiveMode::NonRecursive)?;
        println!("[watcher] Watching WhatsApp DB: {:?}", wa_db);
    }

    let mut last_email_check = Instant::now();
    let mut last_cal_check = Instant::now();
    let mut last_email_ids: Vec<String> = vec![];

    println!("[watcher] AgentExW Event Watcher started");

    loop {
        // Check for WhatsApp DB changes
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(event) => {
                if matches!(event.kind, EventKind::Modify(_)) {
                    // WhatsApp DB changed - check for new messages
                    if let Some(msg) = check_new_whatsapp() {
                        write_event("whatsapp", &msg)?;
                        wake_agent()?;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(e) => eprintln!("[watcher] Error: {}", e),
        }

        // Poll email
        if last_email_check.elapsed() >= Duration::from_secs(EMAIL_POLL_SECS) {
            last_email_check = Instant::now();
            if let Some((msg, new_ids)) = check_new_email(&last_email_ids) {
                last_email_ids = new_ids;
                write_event("email", &msg)?;
                wake_agent()?;
            }
        }

        // Poll calendar reminders
        if last_cal_check.elapsed() >= Duration::from_secs(CAL_POLL_SECS) {
            last_cal_check = Instant::now();
            if let Some(msg) = check_calendar_reminders() {
                write_event("calendar", &msg)?;
                wake_agent()?;
            }
        }
    }
}

fn check_new_whatsapp() -> Option<TriggerEvent> {
    let output = Command::new("whatsapp-cli")
        .args(["list", "--unread", "--json"])
        .output()
        .ok()?;

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let messages = json.as_array()?;

    if let Some(msg) = messages.first() {
        return Some(TriggerEvent {
            channel: "whatsapp".to_string(),
            from: msg["from"].as_str()?.to_string(),
            content: msg["body"].as_str()?.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }
    None
}

fn check_new_email(last_ids: &[String]) -> Option<(TriggerEvent, Vec<String>)> {
    let output = Command::new("himalaya")
        .args(["envelope", "list", "-f", "INBOX", "-w", "5", "-o", "json"])
        .output()
        .ok()?;

    let emails: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).ok()?;
    let current_ids: Vec<String> = emails.iter()
        .filter_map(|e| e["id"].as_str().map(|s| s.to_string()))
        .collect();

    // Find new emails
    for email in &emails {
        let id = email["id"].as_str()?;
        if !last_ids.contains(&id.to_string()) {
            let from = email["from"].as_str().unwrap_or("unknown");
            let subject = email["subject"].as_str().unwrap_or("");
            return Some((TriggerEvent {
                channel: "email".to_string(),
                from: from.to_string(),
                content: subject.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            }, current_ids));
        }
    }
    None
}

fn check_calendar_reminders() -> Option<TriggerEvent> {
    // Check for events in next 15 minutes
    let output = Command::new("gcalcli")
        .args(["agenda", "--nocolor", "now", "+15m"])
        .output()
        .ok()?;

    let agenda = String::from_utf8_lossy(&output.stdout);
    if agenda.trim().is_empty() || agenda.contains("No Events Found") {
        return None;
    }

    Some(TriggerEvent {
        channel: "calendar".to_string(),
        from: "calendar".to_string(),
        content: agenda.trim().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

fn write_event(channel: &str, event: &TriggerEvent) -> std::io::Result<()> {
    let path = Path::new(EVENTS_DIR).join(channel);
    let json = serde_json::to_string(event)?;
    std::fs::write(path, json)
}

fn wake_agent() -> std::io::Result<()> {
    // Send SIGUSR1 to agentexw
    Command::new("pkill")
        .args(["-USR1", "agentexw"])
        .output()?;
    Ok(())
}
```

**Step 2: Add to Cargo.toml**

```toml
[[bin]]
name = "agentexw-watcher"
path = "src/bin/agentexw_watcher.rs"
```

**Step 3: Build**

```bash
cargo build --release --bin agentexw-watcher
```

---

## Task 5: Update AgentExW Tools

**Files:**
- Modify: `src/bin/agentexw.rs` (tool definitions)

**Step 1: Update tool definitions to use CLI wrappers**

```rust
fn get_tools() -> Vec<ClaudeTool> {
    vec![
        ClaudeTool {
            name: "wa_send".to_string(),
            description: "Send a WhatsApp message".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "phone": { "type": "string", "description": "Phone number in E.164 format (+1234567890)" },
                    "message": { "type": "string", "description": "Message text to send" }
                },
                "required": ["phone", "message"]
            }),
        },
        ClaudeTool {
            name: "email_send".to_string(),
            description: "Send an email".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "to": { "type": "string", "description": "Recipient email address" },
                    "subject": { "type": "string", "description": "Email subject" },
                    "body": { "type": "string", "description": "Email body text" }
                },
                "required": ["to", "subject", "body"]
            }),
        },
        ClaudeTool {
            name: "cal_list".to_string(),
            description: "List upcoming calendar events".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "days": { "type": "integer", "description": "Number of days to look ahead (default 7)" }
                }
            }),
        },
        ClaudeTool {
            name: "cal_add".to_string(),
            description: "Add a calendar event".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "title": { "type": "string", "description": "Event title" },
                    "when": { "type": "string", "description": "When the event starts (e.g., 'tomorrow 2pm', '2026-03-01 14:00')" },
                    "duration": { "type": "integer", "description": "Duration in minutes (default 60)" }
                },
                "required": ["title", "when"]
            }),
        },
    ]
}
```

**Step 2: Update execute_tool to call CLI wrappers**

```rust
fn execute_tool(args: &Args, tool: &str, input: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    let tool_path = format!("/usr/lib/execwall/tools/{}", tool);

    let output = match tool {
        "wa_send" => {
            let phone = input["phone"].as_str().unwrap_or("");
            let message = input["message"].as_str().unwrap_or("");
            std::process::Command::new(&tool_path)
                .args([phone, message])
                .output()?
        }
        "email_send" => {
            let to = input["to"].as_str().unwrap_or("");
            let subject = input["subject"].as_str().unwrap_or("");
            let body = input["body"].as_str().unwrap_or("");
            std::process::Command::new(&tool_path)
                .args([to, subject, body])
                .output()?
        }
        "cal_list" => {
            let days = input["days"].as_i64().unwrap_or(7).to_string();
            std::process::Command::new(&tool_path)
                .args([&days])
                .output()?
        }
        "cal_add" => {
            let title = input["title"].as_str().unwrap_or("");
            let when = input["when"].as_str().unwrap_or("");
            let duration = input["duration"].as_i64().unwrap_or(60).to_string();
            std::process::Command::new(&tool_path)
                .args([title, when, &duration])
                .output()?
        }
        _ => return Err(format!("Unknown tool: {}", tool).into()),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        Ok(stdout.to_string())
    } else {
        Ok(format!("Error: {}", stderr))
    }
}
```

---

## Task 6: Create systemd services

**Files:**
- Create: `/etc/systemd/system/agentexw.service`
- Create: `/etc/systemd/system/agentexw-watcher.service`
- Create: `/etc/systemd/system/whatsapp-sync.service`

**Step 1: agentexw.service**

```ini
[Unit]
Description=AgentExW Autonomous Agent
After=network.target

[Service]
Type=simple
User=opc
Environment=ANTHROPIC_API_KEY=your-key-here
ExecStart=/usr/local/bin/agentexw run --interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Step 2: agentexw-watcher.service**

```ini
[Unit]
Description=AgentExW Event Watcher
After=network.target

[Service]
Type=simple
User=opc
ExecStart=/usr/local/bin/agentexw-watcher
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Step 3: whatsapp-sync.service**

```ini
[Unit]
Description=WhatsApp CLI Sync
After=network.target

[Service]
Type=simple
User=opc
ExecStart=/usr/local/bin/whatsapp-cli sync
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Step 4: Enable services**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now whatsapp-sync
sudo systemctl enable --now agentexw-watcher
sudo systemctl enable --now agentexw
```

---

## Summary

| Component | Tool | Purpose |
|-----------|------|---------|
| WhatsApp Send | whatsapp-cli send | Send messages |
| WhatsApp Receive | whatsapp-cli sync | Background sync to SQLite |
| Email Send | himalaya send | Send emails |
| Email Receive | himalaya envelope list | Poll for new emails |
| Calendar List | gcalcli agenda | List events |
| Calendar Add | gcalcli add | Create events |
| Event Watcher | agentexw-watcher | Watch for events, write triggers |
| Main Agent | agentexw | Process events, call Claude, execute tools |

**No OpenClaw needed** - pure CLI tools with file-based event triggers.
