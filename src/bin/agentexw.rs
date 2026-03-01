//! AgentExW - Autonomous Agent with Execwall Security
//!
//! Main agent loop that:
//! 1. Wakes on timer or SIGUSR1
//! 2. Aggregates context (tasks, calendar, messages, alerts)
//! 3. Sends context to Claude for decision
//! 4. Executes approved actions via Execwall
//! 5. Notifies systemd watchdog (Linux)
//! 6. Sleeps until next wake

use clap::{Parser, Subcommand};
use execwall::context::{needs_immediate_action, ContextAggregator, ContextSnapshot, NewMessage};
use execwall::user::{Contact, ContactScope, Owner, UserManager};
use notify::{RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const EVENTS_DIR: &str = "/var/lib/execwall/events";

/// Trigger event from services (WhatsApp, Email, Calendar)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TriggerEvent {
    #[serde(rename = "type")]
    event_type: String,
    channel: String,
    from: String,
    from_name: Option<String>,
    content: String,
    message_id: String,
    timestamp: String,
    #[serde(default)]
    metadata: serde_json::Value,
}

static WAKE_REQUESTED: AtomicBool = AtomicBool::new(false);

// Claude API types (Anthropic Messages API)
#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<ClaudeMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<ClaudeTool>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ClaudeMessage {
    role: String,
    content: ClaudeContent,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum ClaudeContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse { id: String, name: String, input: serde_json::Value },
    #[serde(rename = "tool_result")]
    ToolResult { tool_use_id: String, content: String },
}

#[derive(Debug, Serialize)]
struct ClaudeTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    content: Vec<ContentBlock>,
    stop_reason: Option<String>,
}

/// AgentExW - Autonomous AI Agent with Execwall Security
#[derive(Parser, Debug)]
#[command(name = "agentexw")]
#[command(version)]
#[command(about = "Autonomous AI agent with deny-by-default security")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to policy configuration
    #[arg(long, default_value = "/etc/execwall/policy.yaml", global = true)]
    policy: String,

    /// Path to SQLite database
    #[arg(long, default_value = "/var/lib/execwall/agent_memory.db", global = true)]
    db: String,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the agent daemon (default)
    Run {
        /// Wake interval in seconds (0 = event-driven only)
        #[arg(long, default_value = "300")]
        interval: u64,

        /// Watchdog timeout in seconds
        #[arg(long, default_value = "60")]
        watchdog_sec: u64,

        /// Run once and exit (for testing)
        #[arg(long)]
        once: bool,
    },

    /// Initialize the database
    Init,

    /// Set the owner
    SetOwner {
        /// Owner ID
        id: String,
        /// Phone number
        #[arg(long)]
        phone: Option<String>,
        /// Email address
        #[arg(long)]
        email: Option<String>,
    },

    /// Add a contact
    AddContact {
        /// Contact ID
        id: String,
        /// Phone number
        #[arg(long)]
        phone: Option<String>,
        /// Email address
        #[arg(long)]
        email: Option<String>,
        /// Display name
        #[arg(long)]
        name: Option<String>,
    },

    /// Set scope for a contact
    SetScope {
        /// Contact ID
        contact_id: String,
        /// Instruction (e.g., "Discuss execwall only")
        instruction: String,
        /// Allowed topics (comma-separated)
        #[arg(long)]
        allow: Option<String>,
        /// Denied topics (comma-separated)
        #[arg(long)]
        deny: Option<String>,
    },

    /// List pending approval requests
    Pending,

    /// Approve a pending action
    Approve {
        /// Approval ID
        id: i64,
    },

    /// Deny a pending action
    Deny {
        /// Approval ID
        id: i64,
    },

    /// Add a task
    Task {
        /// Task content
        content: String,
        /// Due date
        #[arg(long)]
        due: Option<String>,
        /// Priority (0-5)
        #[arg(long, default_value = "0")]
        priority: i32,
    },

    /// Add a reminder
    Remind {
        /// Reminder content
        content: String,
        /// Due date/time
        due: String,
    },

    /// Add a note
    Note {
        /// Note content
        content: String,
        /// Tags (comma-separated)
        #[arg(long)]
        tags: Option<String>,
    },

    /// Show status
    Status,

    /// Wake the agent now
    Wake,

    /// List contacts
    Contacts,

    /// Show recent execution log
    Log {
        /// Number of entries
        #[arg(long, default_value = "20")]
        limit: usize,
    },

    /// Run a fund script
    FundRun {
        /// Script name
        script: String,
        /// Arguments
        args: Vec<String>,
    },
}

/// Action decision from Claude
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentDecision {
    pub should_act: bool,
    pub reasoning: String,
    pub tool_calls: Vec<ToolCallRequest>,
    pub priority: u8,
    pub response_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolCallRequest {
    pub tool: String,
    pub args: serde_json::Value,
    pub requires_user_approval: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Some(Commands::Run {
            interval,
            watchdog_sec,
            once,
        }) => run_agent(&args, interval, watchdog_sec, once),
        Some(Commands::Init) => cmd_init(&args),
        Some(Commands::SetOwner { ref id, ref phone, ref email }) => {
            cmd_set_owner(&args, id, phone.clone(), email.clone())
        }
        Some(Commands::AddContact {
            ref id,
            ref phone,
            ref email,
            ref name,
        }) => cmd_add_contact(&args, id, phone.clone(), email.clone(), name.clone()),
        Some(Commands::SetScope {
            ref contact_id,
            ref instruction,
            ref allow,
            ref deny,
        }) => cmd_set_scope(&args, contact_id, instruction, allow.clone(), deny.clone()),
        Some(Commands::Pending) => cmd_pending(&args),
        Some(Commands::Approve { id }) => cmd_approve(&args, id),
        Some(Commands::Deny { id }) => cmd_deny(&args, id),
        Some(Commands::Task {
            ref content,
            ref due,
            priority,
        }) => cmd_add_task(&args, content, due.clone(), priority),
        Some(Commands::Remind { ref content, ref due }) => cmd_add_reminder(&args, content, due),
        Some(Commands::Note { ref content, ref tags }) => cmd_add_note(&args, content, tags.clone()),
        Some(Commands::Status) => cmd_status(&args),
        Some(Commands::Wake) => cmd_wake(&args),
        Some(Commands::Contacts) => cmd_contacts(&args),
        Some(Commands::Log { limit }) => cmd_log(&args, limit),
        Some(Commands::FundRun { ref script, args: ref script_args }) => {
            cmd_fund_run(&args, script, script_args)
        }
        None => {
            // Default: run agent
            run_agent(&args, 300, 60, false)
        }
    }
}

fn run_agent(
    args: &Args,
    interval: u64,
    watchdog_sec: u64,
    once: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure events directory exists
    std::fs::create_dir_all(EVENTS_DIR)?;

    // Set up signal handler for SIGUSR1
    #[cfg(unix)]
    {
        use std::sync::Arc;
        let wake_flag = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGUSR1, Arc::clone(&wake_flag))?;
    }

    // Set up file watcher for events directory
    let (file_tx, file_rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    let _ = file_tx.send(event);
                }
            }
        },
        notify::Config::default(),
    )?;
    watcher.watch(Path::new(EVENTS_DIR), RecursiveMode::NonRecursive)?;

    // Notify systemd that we're ready (Linux only)
    #[cfg(target_os = "linux")]
    {
        let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
    }

    log(args, "AgentExW started");
    log(args, &format!("Watching events directory: {}", EVENTS_DIR));

    // Initialize components
    let user_mgr = UserManager::new(&args.db);
    let context_agg = ContextAggregator::new(&args.db, &args.policy);

    let watchdog_interval = Duration::from_secs(watchdog_sec / 2);
    let wake_interval = Duration::from_secs(interval);

    let mut last_wake = Instant::now();
    let mut last_watchdog = Instant::now();

    loop {
        // Pet the watchdog regularly (Linux only)
        #[cfg(target_os = "linux")]
        {
            if last_watchdog.elapsed() >= watchdog_interval {
                let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Watchdog]);
                last_watchdog = Instant::now();
            }
        }

        // Check for file events (non-blocking)
        let file_event = file_rx.try_recv().is_ok();

        // Check if we should wake
        let should_wake = WAKE_REQUESTED.swap(false, Ordering::SeqCst)
            || file_event
            || (interval > 0 && last_wake.elapsed() >= wake_interval);

        if should_wake || once {
            log(args, "Waking up - collecting context");
            last_wake = Instant::now();

            // Read trigger files from events directory
            let triggers = read_trigger_files(args);
            if !triggers.is_empty() {
                log(args, &format!("Found {} trigger files", triggers.len()));
            }

            // Collect context from SQLite
            let mut context = match context_agg.collect() {
                Ok(ctx) => ctx,
                Err(e) => {
                    log(args, &format!("Error collecting context: {}", e));
                    if once {
                        break;
                    }
                    continue;
                }
            };

            // Add trigger events as new messages
            for trigger in &triggers {
                context.new_messages.push(NewMessage {
                    id: 0,  // No DB id for trigger events
                    participant_id: trigger.from.clone(),
                    participant_phone: Some(trigger.from.clone()),
                    channel: trigger.channel.clone(),
                    content: trigger.content.clone(),
                    created_at: trigger.timestamp.clone(),
                });
            }

            // Check if action is needed
            if needs_immediate_action(&context) || !triggers.is_empty() {
                log(args, "Context requires action - processing with Claude");

                // Log what we found
                if !context.new_messages.is_empty() {
                    log(args, &format!("Found {} new messages", context.new_messages.len()));
                }
                if !context.overdue_reminders.is_empty() {
                    log(args, &format!("Found {} overdue reminders", context.overdue_reminders.len()));
                }
                if !context.pending_approvals.is_empty() {
                    log(args, &format!("Found {} pending approvals", context.pending_approvals.len()));
                }
                if !context.fund_alerts.is_empty() {
                    log(args, &format!("Found {} fund alerts", context.fund_alerts.len()));
                }

                // Call Claude to process and respond
                if let Err(e) = process_messages_with_claude(args, &context, &user_mgr) {
                    log(args, &format!("Error processing with Claude: {}", e));
                }

                // Delete processed trigger files
                delete_trigger_files(args);
            } else {
                log(args, "No immediate action required");
            }

            if once {
                break;
            }
        }

        // Sleep briefly
        std::thread::sleep(Duration::from_millis(100));
    }

    // Notify systemd we're stopping (Linux only)
    #[cfg(target_os = "linux")]
    {
        let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Stopping]);
    }

    log(args, "AgentExW stopped");
    Ok(())
}

fn read_trigger_files(args: &Args) -> Vec<TriggerEvent> {
    let mut triggers = Vec::new();
    let events_path = Path::new(EVENTS_DIR);

    if let Ok(entries) = std::fs::read_dir(events_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    match serde_json::from_str::<TriggerEvent>(&content) {
                        Ok(trigger) => {
                            log(args, &format!("Read trigger: {} from {} via {}",
                                             trigger.event_type, trigger.from, trigger.channel));
                            triggers.push(trigger);
                        }
                        Err(e) => {
                            log(args, &format!("Failed to parse trigger file {:?}: {}", path, e));
                        }
                    }
                }
            }
        }
    }

    triggers
}

fn delete_trigger_files(args: &Args) {
    let events_path = Path::new(EVENTS_DIR);

    if let Ok(entries) = std::fs::read_dir(events_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                if let Err(e) = std::fs::remove_file(&path) {
                    log(args, &format!("Failed to delete trigger file {:?}: {}", path, e));
                } else {
                    log(args, &format!("Deleted trigger file: {:?}", path.file_name()));
                }
            }
        }
    }
}

// Command implementations

fn cmd_init(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let user_mgr = UserManager::new(&args.db);
    user_mgr.init_schema()?;
    println!("Database initialized at {}", args.db);
    Ok(())
}

fn cmd_set_owner(
    args: &Args,
    id: &str,
    phone: Option<String>,
    email: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let user_mgr = UserManager::new(&args.db);
    user_mgr.set_owner(&Owner {
        id: id.to_string(),
        phone,
        email,
    })?;
    println!("Owner set: {}", id);
    Ok(())
}

fn cmd_add_contact(
    args: &Args,
    id: &str,
    phone: Option<String>,
    email: Option<String>,
    name: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let user_mgr = UserManager::new(&args.db);
    user_mgr.upsert_contact(&Contact {
        id: id.to_string(),
        phone,
        email,
        display_name: name,
    })?;
    println!("Contact added: {}", id);
    Ok(())
}

fn cmd_set_scope(
    args: &Args,
    contact_id: &str,
    instruction: &str,
    allow: Option<String>,
    deny: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let user_mgr = UserManager::new(&args.db);

    let topics_allow: Vec<String> = allow
        .map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let topics_deny: Vec<String> = deny
        .map(|d| d.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    user_mgr.add_contact_scope(&ContactScope {
        id: 0,
        contact_id: contact_id.to_string(),
        instruction: instruction.to_string(),
        topics_allow,
        topics_deny,
        tools_allow: vec![],
        expires_at: None,
    })?;

    println!("Scope set for {}: {}", contact_id, instruction);
    Ok(())
}

fn cmd_pending(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(&args.db)?;

    let mut stmt = conn.prepare(
        "SELECT id, tool, args, reason, created_at FROM pending_approvals WHERE status = 'pending'",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;

    println!("Pending approvals:");
    let mut count = 0;
    for row in rows {
        let (id, tool, args, reason, created) = row?;
        println!(
            "  [{}] {} - {} ({})",
            id,
            tool,
            reason.unwrap_or_default(),
            created
        );
        count += 1;
    }

    if count == 0 {
        println!("  (none)");
    }

    Ok(())
}

fn cmd_approve(args: &Args, id: i64) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(&args.db)?;

    // Get the pending action
    let (tool, tool_args): (String, String) = conn.query_row(
        "SELECT tool, args FROM pending_approvals WHERE id = ? AND status = 'pending'",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    // Update status
    conn.execute(
        "UPDATE pending_approvals SET status = 'approved', decided_at = datetime('now'), decision = 'approved' WHERE id = ?",
        [id],
    )?;

    println!("Approved: {} ({})", tool, tool_args);

    // TODO: Execute the tool via execwall

    Ok(())
}

fn cmd_deny(args: &Args, id: i64) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(&args.db)?;

    conn.execute(
        "UPDATE pending_approvals SET status = 'denied', decided_at = datetime('now'), decision = 'denied' WHERE id = ?",
        [id],
    )?;

    println!("Denied approval {}", id);
    Ok(())
}

fn cmd_add_task(
    args: &Args,
    content: &str,
    due: Option<String>,
    priority: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(&args.db)?;

    conn.execute(
        "INSERT INTO tasks (content, due, priority, source) VALUES (?1, ?2, ?3, 'cli')",
        [content, &due.unwrap_or_default(), &priority.to_string()],
    )?;

    println!("Task added: {}", content);
    Ok(())
}

fn cmd_add_reminder(args: &Args, content: &str, due: &str) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(&args.db)?;

    conn.execute(
        "INSERT INTO reminders (content, due) VALUES (?1, ?2)",
        [content, due],
    )?;

    println!("Reminder added: {} (due: {})", content, due);
    Ok(())
}

fn cmd_add_note(
    args: &Args,
    content: &str,
    tags: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(&args.db)?;

    conn.execute(
        "INSERT INTO notes (content, tags) VALUES (?1, ?2)",
        [content, &tags.unwrap_or_default()],
    )?;

    println!("Note added");
    Ok(())
}

fn cmd_status(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(&args.db)?;

    let pending_tasks: i64 =
        conn.query_row("SELECT COUNT(*) FROM tasks WHERE status = 'pending'", [], |r| {
            r.get(0)
        })?;

    let pending_approvals: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pending_approvals WHERE status = 'pending'",
        [],
        |r| r.get(0),
    )?;

    let overdue_reminders: i64 = conn.query_row(
        "SELECT COUNT(*) FROM reminders WHERE status = 'pending' AND due <= datetime('now')",
        [],
        |r| r.get(0),
    )?;

    let contacts: i64 = conn.query_row("SELECT COUNT(*) FROM contacts", [], |r| r.get(0))?;

    println!("AgentExW Status:");
    println!("  Database: {}", args.db);
    println!("  Pending tasks: {}", pending_tasks);
    println!("  Pending approvals: {}", pending_approvals);
    println!("  Overdue reminders: {}", overdue_reminders);
    println!("  Contacts: {}", contacts);

    // Check owner
    let user_mgr = UserManager::new(&args.db);
    if let Ok(Some(owner)) = user_mgr.get_owner() {
        println!("  Owner: {} ({:?})", owner.id, owner.phone);
    } else {
        println!("  Owner: (not set)");
    }

    Ok(())
}

fn cmd_wake(_args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Touch the wake file
    let event_dir = std::path::Path::new("/var/lib/execwall/events");
    if event_dir.exists() {
        let wake_file = event_dir.join("wake");
        std::fs::write(&wake_file, "")?;
    }

    // Send SIGUSR1 to the running agent
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["reload", "agentexw"])
            .output();
    }

    println!("Wake signal sent");
    Ok(())
}

fn cmd_contacts(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let user_mgr = UserManager::new(&args.db);
    let contacts = user_mgr.list_contacts()?;

    println!("Contacts:");
    for contact in contacts {
        let scopes = user_mgr.get_contact_scopes(&contact.id)?;
        let scope_summary = if scopes.is_empty() {
            "(no scope set)".to_string()
        } else {
            scopes
                .iter()
                .map(|s| s.instruction.clone())
                .collect::<Vec<_>>()
                .join("; ")
        };

        println!(
            "  {} - {} ({:?}, {:?})",
            contact.id,
            contact.display_name.unwrap_or_default(),
            contact.phone,
            contact.email
        );
        println!("    Scope: {}", scope_summary);
    }

    Ok(())
}

fn cmd_log(args: &Args, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    let conn = Connection::open(&args.db)?;

    let mut stmt = conn.prepare(
        "SELECT tool, args, exit_code, executed_at FROM execution_log ORDER BY executed_at DESC LIMIT ?1",
    )?;

    let rows = stmt.query_map([limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<i32>>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    println!("Recent executions:");
    for row in rows {
        let (tool, args, exit_code, executed) = row?;
        println!(
            "  [{}] {} {} (exit: {:?})",
            executed, tool, args, exit_code
        );
    }

    Ok(())
}

fn cmd_fund_run(
    args: &Args,
    script: &str,
    script_args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let scripts_dir = "/var/lib/execwall/fund-scripts";

    // Security: only allow simple filenames
    if script.contains('/') || script.contains("..") {
        return Err("Invalid script name".into());
    }

    let script_name = if script.ends_with(".py") {
        script.to_string()
    } else {
        format!("{}.py", script)
    };

    let script_path = format!("{}/{}", scripts_dir, script_name);

    if !std::path::Path::new(&script_path).exists() {
        // List available scripts
        println!("Script '{}' not found.", script_name);
        println!("Available scripts:");
        if let Ok(entries) = std::fs::read_dir(scripts_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".py") {
                        println!("  - {}", name);
                    }
                }
            }
        }
        return Ok(());
    }

    // Run via execwall
    let mut cmd = std::process::Command::new("execwall");
    cmd.args(["--policy", &args.policy, "-c", "python3", &script_path]);
    cmd.args(script_args);
    cmd.env("FUND_SCRIPTS_DIR", scripts_dir);
    cmd.env("FUND_LOGS_DIR", "/var/log/fund");
    cmd.env("FUND_OUTPUT_DIR", "/tmp/fund-output");

    let output = cmd.output()?;

    // Store in execution log
    let conn = Connection::open(&args.db)?;
    conn.execute(
        "INSERT INTO fund_executions (script_name, args, exit_code, stdout, stderr)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        [
            &script_name,
            &script_args.join(" "),
            &output.status.code().unwrap_or(-1).to_string(),
            &String::from_utf8_lossy(&output.stdout).to_string(),
            &String::from_utf8_lossy(&output.stderr).to_string(),
        ],
    )?;

    // Print output
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;

    if !output.status.success() {
        std::process::exit(output.status.code().unwrap_or(1));
    }

    Ok(())
}

fn log(args: &Args, msg: &str) {
    if args.verbose || std::env::var("JOURNAL_STREAM").is_ok() {
        eprintln!("[AgentExW] {}", msg);
    }
}

// Claude/OpenRouter integration

fn get_available_tools() -> Vec<ClaudeTool> {
    vec![
        ClaudeTool {
            name: "wa_send".to_string(),
            description: "Send a WhatsApp message to a phone number".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "phone": {
                        "type": "string",
                        "description": "Phone number in E.164 format (e.g., +1234567890)"
                    },
                    "message": {
                        "type": "string",
                        "description": "Message to send"
                    }
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
                    "to": {
                        "type": "string",
                        "description": "Recipient email address"
                    },
                    "subject": {
                        "type": "string",
                        "description": "Email subject"
                    },
                    "body": {
                        "type": "string",
                        "description": "Email body"
                    }
                },
                "required": ["to", "subject", "body"]
            }),
        },
        ClaudeTool {
            name: "email_check".to_string(),
            description: "Check recent emails".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "count": {
                        "type": "integer",
                        "description": "Number of emails to retrieve (default: 5)"
                    }
                }
            }),
        },
        ClaudeTool {
            name: "cal_list".to_string(),
            description: "List upcoming calendar events".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days to look ahead (default: 7)"
                    }
                }
            }),
        },
        ClaudeTool {
            name: "cal_add".to_string(),
            description: "Add a calendar event".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Event title"
                    },
                    "start": {
                        "type": "string",
                        "description": "Start time (e.g., 2026-02-28T14:00:00)"
                    },
                    "end": {
                        "type": "string",
                        "description": "End time (e.g., 2026-02-28T15:00:00)"
                    }
                },
                "required": ["title", "start", "end"]
            }),
        },
        ClaudeTool {
            name: "remember".to_string(),
            description: "Store a note in memory".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Note content to remember"
                    },
                    "tags": {
                        "type": "string",
                        "description": "Comma-separated tags for the note"
                    }
                },
                "required": ["content"]
            }),
        },
        ClaudeTool {
            name: "recall".to_string(),
            description: "Search notes in memory".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (optional, empty for recent notes)"
                    }
                }
            }),
        },
        ClaudeTool {
            name: "add_task".to_string(),
            description: "Add a task to the todo list".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Task description"
                    },
                    "due": {
                        "type": "string",
                        "description": "Due date (e.g., 2026-02-28)"
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Priority (0=normal, 1=high, 2=urgent)"
                    }
                },
                "required": ["content"]
            }),
        },
        ClaudeTool {
            name: "add_reminder".to_string(),
            description: "Set a reminder".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Reminder content"
                    },
                    "due": {
                        "type": "string",
                        "description": "When to remind (e.g., 2026-02-28 14:00)"
                    }
                },
                "required": ["content", "due"]
            }),
        },
        ClaudeTool {
            name: "add_contact".to_string(),
            description: "Add a new contact to the system".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Unique ID for the contact (e.g., 'ron')"
                    },
                    "phone": {
                        "type": "string",
                        "description": "Phone number in E.164 format (e.g., +1234567890)"
                    },
                    "email": {
                        "type": "string",
                        "description": "Email address (optional)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Display name (e.g., 'Ron Smith')"
                    }
                },
                "required": ["id", "phone"]
            }),
        },
        ClaudeTool {
            name: "set_scope".to_string(),
            description: "Set interaction scope/instructions for a contact".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "contact_id": {
                        "type": "string",
                        "description": "The contact's ID"
                    },
                    "instruction": {
                        "type": "string",
                        "description": "Instructions for how to interact with this contact"
                    },
                    "topics_allow": {
                        "type": "string",
                        "description": "Comma-separated list of allowed topics"
                    },
                    "topics_deny": {
                        "type": "string",
                        "description": "Comma-separated list of denied topics"
                    }
                },
                "required": ["contact_id", "instruction"]
            }),
        },
        ClaudeTool {
            name: "websearch".to_string(),
            description: "Search the web using Tavily. Returns relevant results for any query.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query"
                    }
                },
                "required": ["query"]
            }),
        },
    ]
}

fn build_system_prompt(owner: &Option<Owner>, contact_scopes: &HashMap<String, Vec<ContactScope>>) -> String {
    let mut prompt = String::from(
        r#"You are Sundaddy, an autonomous AI assistant secured by Execwall.

You serve one owner (Sundar) and can interact with authorized contacts based on scoped instructions.

CRITICAL - RESPONDING TO MESSAGES:
- When you receive NEW MESSAGES TO PROCESS, you MUST use the wa_send tool to reply
- ALWAYS send responses to the OWNER's phone number: +16173597259 (NOT to contacts like Ron)
- Only send to a contact's number if the owner explicitly asks you to message that specific contact
- Always identify yourself as Sundaddy in your responses
- For new contacts mentioned by owner, use add_contact to save their info

IMPORTANT RULES:
1. Never share information between different contacts unless explicitly authorized
2. Follow the scope instructions for each contact strictly
3. Be helpful but security-conscious
4. All tool calls go through Execwall for policy enforcement
5. Log all actions for audit

"#,
    );

    if let Some(ref owner) = owner {
        prompt.push_str(&format!("OWNER: {} (phone: {:?}, email: {:?})\n", owner.id, owner.phone, owner.email));
        prompt.push_str("- Owner has FULL access to all features and information\n");
        prompt.push_str("- Always respond to owner requests promptly\n\n");
    }

    if !contact_scopes.is_empty() {
        prompt.push_str("CONTACT SCOPES:\n");
        for (contact_id, scopes) in contact_scopes {
            for scope in scopes {
                prompt.push_str(&format!("- {}: {}\n", contact_id, scope.instruction));
                if !scope.topics_allow.is_empty() {
                    prompt.push_str(&format!("  Allowed topics: {:?}\n", scope.topics_allow));
                }
                if !scope.topics_deny.is_empty() {
                    prompt.push_str(&format!("  Denied topics: {:?}\n", scope.topics_deny));
                }
            }
        }
        prompt.push_str("\n");
    }

    prompt.push_str("Available tools: wa_send, email_send, email_check, cal_list, cal_add, remember, recall, add_task, add_reminder, add_contact, set_scope, websearch\n");
    prompt
}

fn format_context_for_claude(context: &ContextSnapshot, user_mgr: &UserManager) -> String {
    let mut msg = String::new();

    // Add pending messages
    if !context.new_messages.is_empty() {
        msg.push_str("NEW MESSAGES TO PROCESS:\n");
        for m in &context.new_messages {
            // Get contact info for context
            let contact_info = if let Some(ref phone) = m.participant_phone {
                if user_mgr.is_owner_phone(phone) {
                    "[OWNER]".to_string()
                } else if let Ok(Some(contact)) = user_mgr.get_contact_by_phone(phone) {
                    format!("[{}]", contact.display_name.unwrap_or(contact.id))
                } else {
                    "[UNKNOWN]".to_string()
                }
            } else {
                "[UNKNOWN]".to_string()
            };

            msg.push_str(&format!("- From {} {}: {}\n", contact_info, m.participant_phone.as_deref().unwrap_or("?"), m.content));
        }
        msg.push_str("\n");
    }

    // Add overdue reminders
    if !context.overdue_reminders.is_empty() {
        msg.push_str("OVERDUE REMINDERS:\n");
        for r in &context.overdue_reminders {
            msg.push_str(&format!("- [{}] {} (due: {}, {}min overdue)\n", r.id, r.content, r.due, r.minutes_overdue));
        }
        msg.push_str("\n");
    }

    // Add pending tasks
    if !context.pending_tasks.is_empty() {
        msg.push_str("PENDING TASKS:\n");
        for t in &context.pending_tasks {
            let pri_str = match t.priority {
                2 => "[URGENT]",
                1 => "[HIGH]",
                _ => "",
            };
            msg.push_str(&format!("- [{}] {} {} (due: {:?})\n", t.id, pri_str, t.content, t.due));
        }
        msg.push_str("\n");
    }

    // Add fund alerts
    if !context.fund_alerts.is_empty() {
        msg.push_str("FUND ALERTS:\n");
        for alert in &context.fund_alerts {
            msg.push_str(&format!("- [{}] {} ({})\n", alert.alert_type, alert.message, alert.severity));
        }
        msg.push_str("\n");
    }

    // Add pending approvals
    if !context.pending_approvals.is_empty() {
        msg.push_str("PENDING APPROVALS (waiting for owner):\n");
        for a in &context.pending_approvals {
            msg.push_str(&format!("- [{}] {} - {}\n", a.id, a.tool, a.reason.as_deref().unwrap_or("no reason")));
        }
        msg.push_str("\n");
    }

    if msg.is_empty() {
        msg = "No new events or messages to process.".to_string();
    }

    msg
}

fn call_claude(
    args: &Args,
    system_prompt: &str,
    context_msg: &str,
    conversation: &mut Vec<ClaudeMessage>,
) -> Result<ClaudeResponse, Box<dyn std::error::Error>> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| "ANTHROPIC_API_KEY not set")?;

    // Add the new context as a user message if not empty
    if !context_msg.is_empty() {
        conversation.push(ClaudeMessage {
            role: "user".to_string(),
            content: ClaudeContent::Text(context_msg.to_string()),
        });
    }

    let request = ClaudeRequest {
        model: "claude-sonnet-4-20250514".to_string(),
        max_tokens: 4096,
        system: system_prompt.to_string(),
        messages: conversation.clone(),
        tools: Some(get_available_tools()),
    };

    log(args, "Calling Claude API...");

    let response = ureq::post("https://api.anthropic.com/v1/messages")
        .set("x-api-key", &api_key)
        .set("anthropic-version", "2023-06-01")
        .set("Content-Type", "application/json")
        .send_json(&request)?;

    let response_body: ClaudeResponse = response.into_json()?;

    log(args, &format!("Claude response: stop_reason={:?}", response_body.stop_reason));

    // Add assistant response to conversation history
    conversation.push(ClaudeMessage {
        role: "assistant".to_string(),
        content: ClaudeContent::Blocks(response_body.content.clone()),
    });

    Ok(response_body)
}

fn execute_tool(
    args: &Args,
    tool_name: &str,
    tool_args: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    log(args, &format!("Executing tool: {} with args: {}", tool_name, tool_args));

    // Parse arguments
    let args_json: serde_json::Value = serde_json::from_str(tool_args)
        .unwrap_or(serde_json::Value::Null);

    // Build command based on tool
    let (cmd, cmd_args): (&str, Vec<String>) = match tool_name {
        "wa_send" => {
            let phone = args_json["phone"].as_str().unwrap_or("");
            let message = args_json["message"].as_str().unwrap_or("");
            ("wa_send", vec![phone.to_string(), message.to_string()])
        }
        "email_send" => {
            let to = args_json["to"].as_str().unwrap_or("");
            let subject = args_json["subject"].as_str().unwrap_or("");
            let body = args_json["body"].as_str().unwrap_or("");
            ("email_send", vec![to.to_string(), subject.to_string(), body.to_string()])
        }
        "email_check" => {
            let count = args_json["count"].as_i64().unwrap_or(5);
            ("email_check", vec![count.to_string()])
        }
        "cal_list" => {
            let days = args_json["days"].as_i64().unwrap_or(7);
            ("cal_list", vec![days.to_string()])
        }
        "cal_add" => {
            let title = args_json["title"].as_str().unwrap_or("");
            let start = args_json["start"].as_str().unwrap_or("");
            let end = args_json["end"].as_str().unwrap_or("");
            ("cal_add", vec![title.to_string(), start.to_string(), end.to_string()])
        }
        "remember" => {
            let content = args_json["content"].as_str().unwrap_or("");
            let tags = args_json["tags"].as_str().unwrap_or("");
            ("remember", vec![content.to_string(), tags.to_string()])
        }
        "recall" => {
            let query = args_json["query"].as_str().unwrap_or("");
            ("recall", vec![query.to_string()])
        }
        "add_task" => {
            let content = args_json["content"].as_str().unwrap_or("");
            let due = args_json["due"].as_str().unwrap_or("");
            let priority = args_json["priority"].as_i64().unwrap_or(0);
            ("add_task", vec![content.to_string(), due.to_string(), priority.to_string()])
        }
        "add_reminder" => {
            let content = args_json["content"].as_str().unwrap_or("");
            let due = args_json["due"].as_str().unwrap_or("");
            ("add_reminder", vec![content.to_string(), due.to_string()])
        }
        "add_contact" => {
            // Handle directly via UserManager
            let id = args_json["id"].as_str().unwrap_or("");
            let phone = args_json["phone"].as_str();
            let email = args_json["email"].as_str();
            let name = args_json["name"].as_str();

            let user_mgr = UserManager::new(&args.db);
            match user_mgr.upsert_contact(&Contact {
                id: id.to_string(),
                phone: phone.map(|s| s.to_string()),
                email: email.map(|s| s.to_string()),
                display_name: name.map(|s| s.to_string()),
            }) {
                Ok(_) => return Ok(format!("Contact '{}' added successfully", id)),
                Err(e) => return Err(format!("Failed to add contact: {}", e).into()),
            }
        }
        "set_scope" => {
            let contact_id = args_json["contact_id"].as_str().unwrap_or("");
            let instruction = args_json["instruction"].as_str().unwrap_or("");
            let topics_allow = args_json["topics_allow"].as_str().unwrap_or("");
            let topics_deny = args_json["topics_deny"].as_str().unwrap_or("");

            let allow_vec: Vec<String> = if topics_allow.is_empty() {
                vec![]
            } else {
                topics_allow.split(',').map(|s| s.trim().to_string()).collect()
            };
            let deny_vec: Vec<String> = if topics_deny.is_empty() {
                vec![]
            } else {
                topics_deny.split(',').map(|s| s.trim().to_string()).collect()
            };

            let user_mgr = UserManager::new(&args.db);
            match user_mgr.add_contact_scope(&ContactScope {
                id: 0,
                contact_id: contact_id.to_string(),
                instruction: instruction.to_string(),
                topics_allow: allow_vec,
                topics_deny: deny_vec,
                tools_allow: vec![],
                expires_at: None,
            }) {
                Ok(_) => return Ok(format!("Scope set for '{}': {}", contact_id, instruction)),
                Err(e) => return Err(format!("Failed to set scope: {}", e).into()),
            }
        }
        "websearch" => {
            let query = args_json["query"].as_str().unwrap_or("");
            ("websearch", vec![query.to_string()])
        }
        _ => return Err(format!("Unknown tool: {}", tool_name).into()),
    };

    // Execute via execwall-shell for policy enforcement
    let tool_path = format!("/usr/lib/execwall/tools/{}", cmd);
    let shell_cmd = format!("{} {}", tool_path, cmd_args.iter().map(|a| format!("\"{}\"", a.replace("\"", "\\\""))).collect::<Vec<_>>().join(" "));
    log(args, &format!("Running: execwall-shell -c '{}'", shell_cmd));

    let output = match std::process::Command::new("/usr/local/bin/execwall-shell")
        .args(["-c", &shell_cmd])
        .output() {
        Ok(o) => o,
        Err(e) => {
            log(args, &format!("Failed to spawn execwall-shell: {}", e));
            return Err(format!("Failed to spawn execwall-shell: {}", e).into());
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    log(args, &format!("Tool stdout: {}", stdout.trim()));
    log(args, &format!("Tool stderr: {}", stderr.trim()));
    log(args, &format!("Tool exit code: {:?}", output.status.code()));

    // Log execution
    if let Ok(conn) = Connection::open(&args.db) {
        let _ = conn.execute(
            "INSERT INTO execution_log (tool, args, result, exit_code) VALUES (?1, ?2, ?3, ?4)",
            [
                tool_name,
                tool_args,
                &stdout,
                &output.status.code().unwrap_or(-1).to_string(),
            ],
        );
    }

    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!("Tool failed: {}", stderr).into())
    }
}

fn process_messages_with_claude(
    args: &Args,
    context: &ContextSnapshot,
    user_mgr: &UserManager,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get owner and contact scopes for system prompt
    let owner = user_mgr.get_owner()?;
    let mut contact_scopes: HashMap<String, Vec<ContactScope>> = HashMap::new();
    for contact in user_mgr.list_contacts()? {
        if let Ok(scopes) = user_mgr.get_contact_scopes(&contact.id) {
            if !scopes.is_empty() {
                contact_scopes.insert(contact.id.clone(), scopes);
            }
        }
    }

    let system_prompt = build_system_prompt(&owner, &contact_scopes);
    let context_msg = format_context_for_claude(context, user_mgr);

    // Maintain conversation for tool call loop
    let mut conversation: Vec<ClaudeMessage> = Vec::new();

    // Initial call
    let mut response = call_claude(args, &system_prompt, &context_msg, &mut conversation)?;

    // Tool call loop - process any tool calls until we get end_turn
    loop {
        // Check for tool_use blocks in response
        let tool_uses: Vec<_> = response.content.iter().filter_map(|block| {
            match block {
                ContentBlock::ToolUse { id, name, input } => Some((id.clone(), name.clone(), input.clone())),
                _ => None,
            }
        }).collect();

        if tool_uses.is_empty() || response.stop_reason.as_deref() == Some("end_turn") {
            // No more tool calls, log final text response
            for block in &response.content {
                if let ContentBlock::Text { text } = block {
                    log(args, &format!("Final response: {}", text));
                }
            }
            break;
        }

        // Process each tool call
        let mut tool_results: Vec<ContentBlock> = Vec::new();
        for (tool_id, tool_name, tool_input) in &tool_uses {
            log(args, &format!("Processing tool call: {}", tool_name));

            let tool_args = serde_json::to_string(tool_input).unwrap_or_default();
            let result = match execute_tool(args, tool_name, &tool_args) {
                Ok(output) => output,
                Err(e) => format!("Error: {}", e),
            };

            tool_results.push(ContentBlock::ToolResult {
                tool_use_id: tool_id.clone(),
                content: result,
            });
        }

        // Add tool results as user message
        conversation.push(ClaudeMessage {
            role: "user".to_string(),
            content: ClaudeContent::Blocks(tool_results),
        });

        // Call Claude again with tool results
        response = call_claude(args, &system_prompt, "", &mut conversation)?;
    }

    Ok(())
}
