# AgentExW Independent Architecture (No OpenClaw)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a fully independent autonomous agent with file-based event triggers, CLI integrations, and SQLite memory. Zero OpenClaw dependency.

**Architecture:** Event services write trigger files. Main agent loop watches triggers. Claude API makes decisions. CLI tools execute actions. SQLite stores everything.

**Tech Stack:** Rust (agent), wacli (WhatsApp), himalaya (Email), gcalcli (Calendar), SQLite, Python runner

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              SERVICES                                    │
│  (Each writes JSON trigger files when events occur)                     │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ whatsapp-svc │  │  email-svc   │  │calendar-svc  │  │  cron-svc  │  │
│  │  (wacli)     │  │ (himalaya)   │  │  (gcalcli)   │  │ (reminders)│  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │
│         │                 │                 │                 │         │
│         └─────────────────┴─────────────────┴─────────────────┘         │
│                                    │                                     │
│                                    ▼                                     │
│                    /var/lib/execwall/events/                            │
│                    ├── whatsapp.json                                    │
│                    ├── email.json                                       │
│                    ├── calendar.json                                    │
│                    └── reminder.json                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           AGENTEXW CORE                                  │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      FILE WATCHER (notify)                       │   │
│  │              Watches /var/lib/execwall/events/                   │   │
│  └─────────────────────────────┬───────────────────────────────────┘   │
│                                │                                         │
│                                ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     CONTEXT AGGREGATOR                           │   │
│  │  - Read trigger files                                            │   │
│  │  - Query SQLite (todos, reminders, conversations, notes)         │   │
│  │  - Build context snapshot                                        │   │
│  └─────────────────────────────┬───────────────────────────────────┘   │
│                                │                                         │
│                                ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      AGENTIC LOOP                                │   │
│  │  1. Check if action needed                                       │   │
│  │  2. Build system prompt + context                                │   │
│  │  3. Call Claude API (Anthropic)                                  │   │
│  │  4. Process tool calls                                           │   │
│  │  5. Execute tools via CLI                                        │   │
│  │  6. Loop until stop_reason == "end_turn"                         │   │
│  │  7. Store conversation in SQLite                                 │   │
│  │  8. Delete processed trigger files                               │   │
│  └─────────────────────────────┬───────────────────────────────────┘   │
│                                │                                         │
│                                ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      TOOL EXECUTOR                               │   │
│  │  CLI Tools:           Python Runner:        Shell:               │   │
│  │  - wa_send            - scripts/*.py        - execwall-shell     │   │
│  │  - email_send         - fund scripts        - bash commands      │   │
│  │  - cal_add            - analysis            - system commands    │   │
│  │  - remember/recall                                               │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                       SQLITE MEMORY                              │   │
│  │  Tables: contacts, conversations, todos, reminders, notes,       │   │
│  │          execution_log, pending_approvals, owner                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Event Trigger Format

All services write JSON files to `/var/lib/execwall/events/`:

```json
{
  "type": "message",
  "channel": "whatsapp",
  "from": "+14155551234",
  "from_name": "Marco",
  "content": "Hey, can you check the markets?",
  "message_id": "wamid.abc123",
  "timestamp": "2026-02-28T23:45:00Z",
  "metadata": {}
}
```

**Trigger types:**
- `message` - incoming message (WhatsApp, Email)
- `reminder` - due reminder/task
- `calendar` - upcoming calendar event
- `alert` - system alert (fund, price, etc.)

---

## Component Details

### 1. WhatsApp Service (whatsapp-svc)

Uses **wacli** (github.com/steipete/wacli) - standalone WhatsApp CLI.

**Responsibilities:**
- Run `wacli sync --follow` to receive messages
- Parse new messages from wacli's SQLite database
- Write trigger files for incoming messages
- Provide `wa_send` CLI for outgoing messages

**Files:**
- `/usr/local/bin/whatsapp-svc` - Daemon that watches wacli DB
- `/usr/local/bin/wa_send` - CLI wrapper for sending

### 2. Email Service (email-svc)

Uses **himalaya** - already installed.

**Responsibilities:**
- Poll `himalaya envelope list` every 60 seconds
- Detect new unread emails
- Write trigger files for incoming emails
- Provide `email_send` CLI for outgoing emails

**Files:**
- `/usr/local/bin/email-svc` - Daemon that polls himalaya
- `/usr/local/bin/email_send` - CLI wrapper for sending

### 3. Calendar Service (calendar-svc)

Uses **gcalcli** - Google Calendar CLI.

**Responsibilities:**
- Poll `gcalcli agenda` every 5 minutes
- Detect events starting in next 15 minutes
- Write trigger files for upcoming events
- Provide `cal_add` CLI for creating events

**Files:**
- `/usr/local/bin/calendar-svc` - Daemon that polls gcalcli
- `/usr/local/bin/cal_add` - CLI wrapper for adding events
- `/usr/local/bin/cal_list` - CLI wrapper for listing events

### 4. Reminder Service (cron-svc)

Built into AgentExW - checks SQLite reminders table.

**Responsibilities:**
- Check for overdue reminders every minute
- Write trigger files for due reminders
- Mark reminders as notified in SQLite

---

## SQLite Schema

```sql
-- Owner configuration
CREATE TABLE owner (
    id TEXT PRIMARY KEY,
    phone TEXT,
    email TEXT,
    identity TEXT DEFAULT 'Sundaddy',
    created_at TEXT DEFAULT (datetime('now'))
);

-- Contacts with scopes
CREATE TABLE contacts (
    id TEXT PRIMARY KEY,
    phone TEXT,
    email TEXT,
    display_name TEXT,
    scope_instruction TEXT,
    topics_allow TEXT,  -- JSON array
    topics_deny TEXT,   -- JSON array
    tools_allow TEXT,   -- JSON array
    created_at TEXT DEFAULT (datetime('now'))
);

-- Conversation history (per contact)
CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,
    contact_id TEXT NOT NULL,
    channel TEXT NOT NULL,      -- whatsapp, email
    role TEXT NOT NULL,         -- user, assistant
    content TEXT NOT NULL,
    message_id TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (contact_id) REFERENCES contacts(id)
);

-- Todos/Tasks
CREATE TABLE todos (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due_at TEXT,
    priority INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',  -- pending, in_progress, done
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT
);

-- Reminders
CREATE TABLE reminders (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due_at TEXT NOT NULL,
    notified INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Notes/Memory
CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    tags TEXT,  -- JSON array
    created_at TEXT DEFAULT (datetime('now'))
);

-- Execution log (audit trail)
CREATE TABLE execution_log (
    id INTEGER PRIMARY KEY,
    tool TEXT NOT NULL,
    args TEXT,
    result TEXT,
    exit_code INTEGER,
    executed_at TEXT DEFAULT (datetime('now'))
);

-- Pending approvals (for sensitive actions)
CREATE TABLE pending_approvals (
    id INTEGER PRIMARY KEY,
    tool TEXT NOT NULL,
    args TEXT,
    reason TEXT,
    status TEXT DEFAULT 'pending',  -- pending, approved, denied
    created_at TEXT DEFAULT (datetime('now'))
);
```

---

## Task 1: Install wacli (WhatsApp CLI)

**Step 1: Install Go**

```bash
ssh opc@193.122.147.218
sudo dnf install -y golang
```

**Step 2: Install wacli**

```bash
go install github.com/steipete/wacli/cmd/wacli@latest
sudo ln -sf ~/go/bin/wacli /usr/local/bin/wacli
```

**Step 3: Authenticate wacli**

```bash
wacli auth
# Scan QR code with WhatsApp on phone
```

**Step 4: Test send**

```bash
wacli send --to "+16173597259" --message "Test from wacli"
```

**Step 5: Test sync**

```bash
wacli sync --follow
# Watch for incoming messages
```

---

## Task 2: Install gcalcli

**Step 1: Install gcalcli**

```bash
pip3 install gcalcli
```

**Step 2: Set up Google OAuth**

```bash
# Create OAuth credentials in Google Cloud Console
# Download client_secret.json
gcalcli --client-id=YOUR_CLIENT_ID.apps.googleusercontent.com init
```

**Step 3: Test commands**

```bash
gcalcli agenda
gcalcli add --title "Test" --when "tomorrow 2pm" --duration 30
```

---

## Task 3: Create WhatsApp Service

**File:** `src/bin/whatsapp_svc.rs`

```rust
//! WhatsApp Service - Watches wacli for incoming messages
//! Writes trigger files to /var/lib/execwall/events/

use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;
use std::collections::HashSet;

const EVENTS_DIR: &str = "/var/lib/execwall/events";
const WACLI_DB: &str = ".local/share/wacli/store.db";  // wacli's SQLite

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

    let home = std::env::var("HOME")?;
    let db_path = Path::new(&home).join(WACLI_DB);

    println!("[whatsapp-svc] Watching wacli database: {:?}", db_path);

    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        notify::Config::default(),
    )?;

    watcher.watch(&db_path, RecursiveMode::NonRecursive)?;

    let mut seen_ids: HashSet<String> = HashSet::new();

    // Load existing message IDs to avoid re-triggering
    if let Ok(conn) = Connection::open(&db_path) {
        if let Ok(mut stmt) = conn.prepare("SELECT id FROM messages") {
            if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                for id in rows.flatten() {
                    seen_ids.insert(id);
                }
            }
        }
    }

    println!("[whatsapp-svc] Loaded {} existing messages", seen_ids.len());
    println!("[whatsapp-svc] Listening for new WhatsApp messages...");

    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(event) => {
                if matches!(event.kind, EventKind::Modify(_)) {
                    // Check for new messages
                    if let Ok(conn) = Connection::open(&db_path) {
                        check_new_messages(&conn, &mut seen_ids)?;
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Periodic check even without file change
            }
            Err(e) => {
                eprintln!("[whatsapp-svc] Watch error: {}", e);
            }
        }
    }
}

fn check_new_messages(
    conn: &Connection,
    seen_ids: &mut HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Query wacli's messages table for new incoming messages
    let mut stmt = conn.prepare(
        "SELECT id, sender, text, timestamp FROM messages
         WHERE is_from_me = 0
         ORDER BY timestamp DESC
         LIMIT 10"
    )?;

    let messages = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,  // id
            row.get::<_, String>(1)?,  // sender (JID)
            row.get::<_, String>(2)?,  // text
            row.get::<_, i64>(3)?,     // timestamp
        ))
    })?;

    for msg in messages {
        let (id, sender, text, timestamp) = msg?;

        if seen_ids.contains(&id) {
            continue;
        }
        seen_ids.insert(id.clone());

        // Extract phone from JID (e.g., "14155551234@s.whatsapp.net")
        let phone = sender.split('@').next().unwrap_or(&sender);
        let phone = if phone.starts_with('+') {
            phone.to_string()
        } else {
            format!("+{}", phone)
        };

        println!("[whatsapp-svc] New message from {}: {}", phone, &text[..text.len().min(50)]);

        let event = TriggerEvent {
            event_type: "message".to_string(),
            channel: "whatsapp".to_string(),
            from: phone,
            from_name: None,
            content: text,
            message_id: id,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let event_path = Path::new(EVENTS_DIR).join("whatsapp.json");
        std::fs::write(&event_path, serde_json::to_string_pretty(&event)?)?;

        // Wake agent
        let _ = std::process::Command::new("pkill")
            .args(["-USR1", "agentexw"])
            .output();
    }

    Ok(())
}
```

---

## Task 4: Create Email Service

**File:** `src/bin/email_svc.rs`

```rust
//! Email Service - Polls himalaya for new emails
//! Writes trigger files to /var/lib/execwall/events/

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const EVENTS_DIR: &str = "/var/lib/execwall/events";
const POLL_INTERVAL: u64 = 60;  // seconds

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
    from: String,
    subject: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(EVENTS_DIR)?;

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut last_check = Instant::now();

    println!("[email-svc] Polling himalaya every {}s", POLL_INTERVAL);

    loop {
        if last_check.elapsed() >= Duration::from_secs(POLL_INTERVAL) {
            last_check = Instant::now();

            if let Ok(emails) = check_emails() {
                for email in emails {
                    if seen_ids.contains(&email.id) {
                        continue;
                    }
                    seen_ids.insert(email.id.clone());

                    println!("[email-svc] New email from {}: {}", email.from, email.subject);

                    let event = TriggerEvent {
                        event_type: "message".to_string(),
                        channel: "email".to_string(),
                        from: extract_email_address(&email.from),
                        from_name: extract_name(&email.from),
                        content: email.subject,
                        message_id: email.id,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };

                    let event_path = Path::new(EVENTS_DIR).join("email.json");
                    std::fs::write(&event_path, serde_json::to_string_pretty(&event)?)?;

                    // Wake agent
                    let _ = Command::new("pkill").args(["-USR1", "agentexw"]).output();
                }
            }

            // Clean old seen IDs (keep last 1000)
            if seen_ids.len() > 1000 {
                seen_ids.clear();
            }
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

fn check_emails() -> Result<Vec<HimalayaEnvelope>, Box<dyn std::error::Error>> {
    let output = Command::new("himalaya")
        .args(["envelope", "list", "-f", "INBOX", "-w", "10", "-o", "json"])
        .output()?;

    if !output.status.success() {
        return Err("himalaya failed".into());
    }

    let emails: Vec<HimalayaEnvelope> = serde_json::from_slice(&output.stdout)?;
    Ok(emails)
}

fn extract_email_address(from: &str) -> String {
    // Parse "Name <email@example.com>" format
    if let Some(start) = from.find('<') {
        if let Some(end) = from.find('>') {
            return from[start + 1..end].to_string();
        }
    }
    from.to_string()
}

fn extract_name(from: &str) -> Option<String> {
    if let Some(pos) = from.find('<') {
        let name = from[..pos].trim().trim_matches('"');
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}
```

---

## Task 5: Create Calendar Service

**File:** `src/bin/calendar_svc.rs`

```rust
//! Calendar Service - Polls gcalcli for upcoming events
//! Writes trigger files to /var/lib/execwall/events/

use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

const EVENTS_DIR: &str = "/var/lib/execwall/events";
const POLL_INTERVAL: u64 = 300;  // 5 minutes
const REMINDER_WINDOW: &str = "+15m";  // 15 minutes before event

#[derive(Debug, Serialize)]
struct TriggerEvent {
    #[serde(rename = "type")]
    event_type: String,
    channel: String,
    from: String,
    content: String,
    message_id: String,
    timestamp: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(EVENTS_DIR)?;

    let mut notified: HashSet<String> = HashSet::new();
    let mut last_check = Instant::now();

    println!("[calendar-svc] Polling gcalcli every {}s", POLL_INTERVAL);

    loop {
        if last_check.elapsed() >= Duration::from_secs(POLL_INTERVAL) {
            last_check = Instant::now();

            if let Ok(events) = check_upcoming_events() {
                for event in events {
                    let event_key = format!("{}:{}", event.0, event.1);  // time:title

                    if notified.contains(&event_key) {
                        continue;
                    }
                    notified.insert(event_key.clone());

                    println!("[calendar-svc] Upcoming: {} at {}", event.1, event.0);

                    let trigger = TriggerEvent {
                        event_type: "calendar".to_string(),
                        channel: "calendar".to_string(),
                        from: "calendar".to_string(),
                        content: format!("Upcoming event: {} at {}", event.1, event.0),
                        message_id: event_key,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };

                    let event_path = Path::new(EVENTS_DIR).join("calendar.json");
                    std::fs::write(&event_path, serde_json::to_string_pretty(&trigger)?)?;

                    // Wake agent
                    let _ = Command::new("pkill").args(["-USR1", "agentexw"]).output();
                }
            }

            // Clean old notifications (keep last 100)
            if notified.len() > 100 {
                notified.clear();
            }
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}

fn check_upcoming_events() -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let output = Command::new("gcalcli")
        .args(["agenda", "--nocolor", "--tsv", "now", REMINDER_WINDOW])
        .output()?;

    if !output.status.success() {
        return Err("gcalcli failed".into());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut events = Vec::new();

    for line in text.lines() {
        if line.trim().is_empty() || line.contains("No Events Found") {
            continue;
        }

        // TSV format: date\ttime\ttitle
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 3 {
            let time = format!("{} {}", parts[0], parts[1]);
            let title = parts[2..].join(" ");
            events.push((time, title));
        }
    }

    Ok(events)
}
```

---

## Task 6: Create CLI Tool Wrappers

**File:** `/usr/lib/execwall/tools/wa_send`

```bash
#!/bin/bash
# WhatsApp send via wacli
# Usage: wa_send <phone> <message>

PHONE="${1:-$WA_TO}"
MSG="${2:-$WA_MESSAGE}"

if [ -z "$PHONE" ] || [ -z "$MSG" ]; then
    echo '{"error": "Usage: wa_send <phone> <message>"}'
    exit 1
fi

wacli send --to "$PHONE" --message "$MSG" 2>&1
```

**File:** `/usr/lib/execwall/tools/email_send`

```bash
#!/bin/bash
# Email send via himalaya
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

**File:** `/usr/lib/execwall/tools/cal_list`

```bash
#!/bin/bash
# Calendar list via gcalcli
# Usage: cal_list [days]

DAYS="${1:-7}"
gcalcli agenda --nocolor "now" "+${DAYS}d" 2>&1
```

**File:** `/usr/lib/execwall/tools/cal_add`

```bash
#!/bin/bash
# Calendar add via gcalcli
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

---

## Task 7: Update AgentExW Main Loop

**Key changes to `src/bin/agentexw.rs`:**

1. Watch `/var/lib/execwall/events/` for trigger files
2. Read trigger files into context
3. Call Claude API (Anthropic) with tools
4. Execute tools via CLI wrappers
5. Store conversation in SQLite
6. Delete processed trigger files

**Core agentic loop:**

```rust
fn run_agent_loop(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let events_dir = Path::new("/var/lib/execwall/events");

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
    watcher.watch(events_dir, RecursiveMode::NonRecursive)?;

    // Also wake on SIGUSR1 and timer
    let wake_interval = Duration::from_secs(args.interval);
    let mut last_wake = Instant::now();

    loop {
        // Check for wake conditions
        let should_wake = WAKE_REQUESTED.swap(false, Ordering::SeqCst)
            || last_wake.elapsed() >= wake_interval
            || rx.try_recv().is_ok();

        if should_wake {
            last_wake = Instant::now();

            // 1. Read all trigger files
            let triggers = read_trigger_files(events_dir)?;

            // 2. Read SQLite context (todos, reminders, recent conversations)
            let context = build_context(&args.db, &triggers)?;

            // 3. Check if action needed
            if needs_action(&context) {
                // 4. Build messages for Claude
                let messages = build_messages(&context)?;

                // 5. Call Claude with tool loop
                process_with_claude(args, &context, messages)?;
            }

            // 6. Delete processed trigger files
            delete_trigger_files(events_dir)?;
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

fn process_with_claude(
    args: &Args,
    context: &Context,
    initial_messages: Vec<ClaudeMessage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut messages = initial_messages;
    let tools = get_tools();

    loop {
        // Call Claude API
        let response = call_claude_api(args, &messages, &tools)?;

        // Extract tool calls
        let tool_calls: Vec<_> = response.content.iter()
            .filter_map(|block| match block {
                ContentBlock::ToolUse { id, name, input } => Some((id, name, input)),
                _ => None,
            })
            .collect();

        // If no tool calls, we're done
        if tool_calls.is_empty() {
            // Extract text response and send if needed
            if let Some(text) = extract_text_response(&response) {
                // Send response to user via appropriate channel
                send_response(context, &text)?;
            }
            break;
        }

        // Execute each tool and collect results
        let mut tool_results = Vec::new();
        for (id, name, input) in tool_calls {
            let result = execute_tool(args, name, input)?;
            tool_results.push(ContentBlock::ToolResult {
                tool_use_id: id.clone(),
                content: result,
            });
        }

        // Add assistant message and tool results
        messages.push(ClaudeMessage {
            role: "assistant".to_string(),
            content: ClaudeContent::Blocks(response.content.clone()),
        });
        messages.push(ClaudeMessage {
            role: "user".to_string(),
            content: ClaudeContent::Blocks(tool_results),
        });
    }

    Ok(())
}
```

---

## Task 8: Python Runner Integration

**File:** `/usr/lib/execwall/python_runner`

```python
#!/usr/bin/env python3
"""
Python Runner - Execute Python scripts in a sandboxed environment
Used by AgentExW for data analysis, fund scripts, etc.
"""

import sys
import json
import subprocess
import os

SCRIPTS_DIR = "/var/lib/execwall/scripts"

def run_script(script_name: str, args: list) -> dict:
    script_path = os.path.join(SCRIPTS_DIR, script_name)

    if not os.path.exists(script_path):
        return {"error": f"Script not found: {script_name}"}

    try:
        result = subprocess.run(
            [sys.executable, script_path] + args,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=SCRIPTS_DIR
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"error": "Script timed out (60s)"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python_runner <script.py> [args...]"}))
        sys.exit(1)

    script = sys.argv[1]
    args = sys.argv[2:]

    result = run_script(script, args)
    print(json.dumps(result))
```

---

## Task 9: Create systemd Services

**File:** `/etc/systemd/system/agentexw.service`

```ini
[Unit]
Description=AgentExW Autonomous Agent
After=network.target whatsapp-svc.service email-svc.service

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

**File:** `/etc/systemd/system/whatsapp-svc.service`

```ini
[Unit]
Description=WhatsApp Event Service
After=network.target

[Service]
Type=simple
User=opc
ExecStart=/usr/local/bin/whatsapp-svc
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**File:** `/etc/systemd/system/email-svc.service`

```ini
[Unit]
Description=Email Event Service
After=network.target

[Service]
Type=simple
User=opc
ExecStart=/usr/local/bin/email-svc
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**File:** `/etc/systemd/system/calendar-svc.service`

```ini
[Unit]
Description=Calendar Event Service
After=network.target

[Service]
Type=simple
User=opc
ExecStart=/usr/local/bin/calendar-svc
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Summary

| Component | Tool | Function |
|-----------|------|----------|
| **whatsapp-svc** | wacli | Watch for WhatsApp messages → trigger |
| **email-svc** | himalaya | Poll for emails → trigger |
| **calendar-svc** | gcalcli | Poll for events → trigger |
| **agentexw** | Claude API | Process triggers, make decisions, execute tools |
| **wa_send** | wacli | CLI to send WhatsApp |
| **email_send** | himalaya | CLI to send email |
| **cal_add/list** | gcalcli | CLI for calendar |
| **python_runner** | Python | Execute scripts |
| **SQLite** | - | Memory, todos, conversations |

**Zero OpenClaw dependency. Pure CLI + file triggers.**
