mod audit;
mod policy;
mod rate_limit;

use audit::{AuditLogger, Decision};
use clap::Parser;
use colored::*;
use policy::{ParsedCommand, PolicyEngine, PolicyMode};
use rate_limit::RateLimiter;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::env;
use std::process::{Command, Stdio};
use std::time::Instant;

/// Sentra - Universal Execution Governance Gateway
#[derive(Parser, Debug)]
#[command(name = "sentra")]
#[command(author = "Sundar Subramaniam")]
#[command(version = "0.1.0")]
#[command(about = "Universal execution governance gateway with argument-level policy enforcement", long_about = None)]
struct Args {
    /// Path to policy YAML file
    #[arg(short, long, default_value = "/etc/sentra/policy.yaml")]
    policy: String,

    /// Path to audit log file
    #[arg(short, long, default_value = "/var/log/sentra_audit.jsonl")]
    log: String,

    /// Override policy mode (enforce or audit)
    #[arg(short, long)]
    mode: Option<String>,

    /// Identity for policy evaluation (defaults to current user)
    #[arg(short, long)]
    identity: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    // Banner
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║              Sentra - Execution Governance               ║".cyan()
    );
    println!(
        "{}",
        "║         Universal Shell with Policy Enforcement          ║".cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════╝".cyan()
    );
    println!();

    // Load policy
    let engine = match PolicyEngine::load_from_file(&args.policy) {
        Ok(e) => {
            println!("{} Loaded policy from: {}", "✓".green(), args.policy);
            e
        }
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            eprintln!();
            eprintln!("Create a policy.yaml file or specify one with --policy");
            eprintln!("Run with --help for usage information");
            std::process::exit(1);
        }
    };

    // Show policy info
    println!("{} {}", "Policy:".cyan(), engine.info());

    // Initialize rate limiter from policy config
    let rate_config = engine.rate_limit_config();
    let mut rate_limiter = RateLimiter::new(rate_config.max_commands, rate_config.window_seconds);
    println!(
        "{} Rate limit: {} commands per {} seconds",
        "✓".green(),
        rate_config.max_commands,
        rate_config.window_seconds
    );

    // Determine identity
    let identity = args.identity.clone().unwrap_or_else(|| {
        users::get_current_username()
            .map(|u| u.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });
    println!("{} Identity: {}", "✓".green(), identity);

    // Check for mode override
    let effective_mode = match &args.mode {
        Some(m) if m == "audit" => {
            println!(
                "{} Mode overridden to AUDIT (log only, no blocking)",
                "⚠".yellow()
            );
            true
        }
        _ => *engine.mode() == PolicyMode::Audit,
    };

    // Initialize audit logger
    let logger = match AuditLogger::new(&args.log) {
        Ok(l) => {
            println!("{} Audit log: {}", "✓".green(), args.log);
            l
        }
        Err(e) => {
            eprintln!(
                "{} Failed to initialize audit log: {}",
                "Warning:".yellow(),
                e
            );
            eprintln!("  Continuing without file logging...");
            AuditLogger::stdout_only()
        }
    };

    println!("{} Session: {}", "✓".green(), logger.session_id());
    println!();

    // Log session start
    logger.log_session_start(&engine.info());

    // Show mode indicator
    if effective_mode {
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════".yellow()
        );
        println!(
            "{}",
            "  AUDIT MODE - Commands will be logged but NOT blocked    "
                .yellow()
                .bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════".yellow()
        );
    } else {
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════".cyan()
        );
        println!(
            "{}",
            "  ENFORCE MODE - Denied commands will be blocked          "
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════".cyan()
        );
    }
    println!();
    println!(
        "Type {} for help, {} to exit",
        "'help'".cyan(),
        "'exit'".cyan()
    );
    println!();

    // Start interactive shell
    let mut commands_executed: u64 = 0;
    let mut commands_denied: u64 = 0;

    let mut rl = DefaultEditor::new().expect("Failed to initialize readline");

    // Get current working directory
    let cwd = env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| ".".to_string());

    loop {
        // Build prompt
        let mode_indicator = if effective_mode {
            "audit".yellow()
        } else {
            "enforce".green()
        };
        let prompt = format!("[sentra:{}]$ ", mode_indicator);

        match rl.readline(&prompt) {
            Ok(line) => {
                let input = line.trim();

                // Skip empty lines
                if input.is_empty() {
                    continue;
                }

                // Add to history
                let _ = rl.add_history_entry(input);

                // Handle built-in commands
                match input {
                    "exit" | "quit" => {
                        println!("{} Exiting sentra...", "→".cyan());
                        break;
                    }
                    "help" => {
                        print_help();
                        continue;
                    }
                    "status" => {
                        let (used, max) = rate_limiter.usage(&identity);
                        println!();
                        println!("{}", "Session Status:".cyan().bold());
                        println!("  Session ID:        {}", logger.session_id());
                        println!("  Identity:          {}", identity);
                        println!("  Policy:            {}", engine.info());
                        println!("  Commands executed: {}", commands_executed);
                        println!("  Commands denied:   {}", commands_denied);
                        println!(
                            "  Rate limit usage:  {}/{} (per {} sec)",
                            used,
                            max,
                            rate_limiter.window_seconds()
                        );
                        println!("  Audit log:         {}", logger.log_path());
                        println!();
                        continue;
                    }
                    _ => {}
                }

                // Check rate limit first
                if let Err(wait_secs) = rate_limiter.check(&identity) {
                    let parsed = ParsedCommand::parse(input);
                    logger.log_evaluation(
                        input,
                        &parsed.executable,
                        &parsed.args_string,
                        &cwd,
                        Decision::Denied,
                        Some("rate_limit".to_string()),
                        Some(format!(
                            "Rate limit exceeded. Try again in {} seconds",
                            wait_secs
                        )),
                        Instant::now(),
                    );
                    commands_denied += 1;
                    println!();
                    println!("{} {}", "✗ RATE LIMITED:".red().bold(), input);
                    println!("  Wait {} seconds before trying again", wait_secs);
                    let (used, max) = rate_limiter.usage(&identity);
                    println!(
                        "  Usage: {}/{} commands in {} second window",
                        used,
                        max,
                        rate_limiter.window_seconds()
                    );
                    println!();
                    continue;
                }

                // Evaluate command against policy
                let eval_start = Instant::now();
                let result = engine.evaluate_with_identity(input, Some(&identity));
                let parsed = ParsedCommand::parse(input);

                if result.allowed || effective_mode {
                    // Command is allowed (or we're in audit mode)
                    let decision = if result.allowed {
                        Decision::Allowed
                    } else {
                        Decision::AuditOnly
                    };

                    // Log the evaluation
                    let entry = logger.log_evaluation(
                        input,
                        &parsed.executable,
                        &parsed.args_string,
                        &cwd,
                        decision.clone(),
                        result.matched_rule.clone(),
                        result.reason.clone(),
                        eval_start,
                    );

                    // Show what's happening
                    if args.verbose {
                        if result.allowed {
                            println!(
                                "{} {} (rule: {})",
                                "ALLOW".green().bold(),
                                input,
                                result.matched_rule.as_deref().unwrap_or("default")
                            );
                        } else {
                            println!(
                                "{} {} (rule: {}, but audit mode)",
                                "AUDIT".yellow().bold(),
                                input,
                                result.matched_rule.as_deref().unwrap_or("default")
                            );
                        }
                    }

                    // Record for rate limiting
                    rate_limiter.record(&identity);

                    // Execute the command
                    let exec_start = Instant::now();
                    let exit_code = execute_command(input);

                    // Log execution completion
                    logger.log_execution_complete(entry, exec_start, exit_code);

                    commands_executed += 1;
                } else {
                    // Command is denied
                    commands_denied += 1;

                    // Log the denial
                    logger.log_evaluation(
                        input,
                        &parsed.executable,
                        &parsed.args_string,
                        &cwd,
                        Decision::Denied,
                        result.matched_rule.clone(),
                        result.reason.clone(),
                        eval_start,
                    );

                    // Show denial message
                    println!();
                    println!("{} {}", "✗ DENIED:".red().bold(), input);
                    if let Some(rule) = &result.matched_rule {
                        println!("  Rule:   {}", rule.yellow());
                    }
                    if let Some(reason) = &result.reason {
                        println!("  Reason: {}", reason);
                    }
                    println!();
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("{} EOF received, exiting...", "→".cyan());
                break;
            }
            Err(err) => {
                eprintln!("{} Readline error: {:?}", "Error:".red(), err);
                break;
            }
        }
    }

    // Log session end
    logger.log_session_end(commands_executed, commands_denied);

    // Summary
    println!();
    println!("{}", "Session Summary:".cyan().bold());
    println!(
        "  Commands executed: {}",
        commands_executed.to_string().green()
    );
    println!("  Commands denied:   {}", commands_denied.to_string().red());
    println!("  Audit log:         {}", logger.log_path());
    println!();
}

/// Execute a shell command and return exit code
fn execute_command(command: &str) -> i32 {
    // Use the system shell to execute the command
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    match Command::new(&shell)
        .arg("-c")
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
    {
        Ok(status) => status.code().unwrap_or(-1),
        Err(e) => {
            eprintln!("{} Failed to execute command: {}", "Error:".red(), e);
            -1
        }
    }
}

/// Print help message
fn print_help() {
    println!();
    println!("{}", "Sentra - Execution Governance Gateway".cyan().bold());
    println!();
    println!("{}", "Built-in Commands:".yellow());
    println!("  {}     Show this help message", "help".cyan());
    println!("  {}   Show session status and statistics", "status".cyan());
    println!("  {}     Exit the shell", "exit".cyan());
    println!("  {}     Exit the shell", "quit".cyan());
    println!();
    println!("{}", "How It Works:".yellow());
    println!("  Every command is evaluated against the policy with argument-level analysis.");
    println!("  - {} commands are executed normally", "Allowed".green());
    println!(
        "  - {} commands are blocked (enforce mode) or logged (audit mode)",
        "Denied".red()
    );
    println!();
    println!("{}", "Policy Modes:".yellow());
    println!("  - {}: Denied commands are blocked", "enforce".green());
    println!(
        "  - {}:   Denied commands are logged but still executed",
        "audit".yellow()
    );
    println!();
    println!("{}", "Policy Features:".yellow());
    println!("  - Argument-level pattern matching (regex)");
    println!("  - Per-identity rate limiting");
    println!("  - Identity-scoped rule sets");
    println!("  - Comprehensive audit logging");
    println!();
}
