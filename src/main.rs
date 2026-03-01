mod api;
mod audit;
mod policy;
mod rate_limit;
mod sandbox;

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

/// Execwall - Execution Firewall for AI Agents
#[derive(Parser, Debug)]
#[command(name = "execwall")]
#[command(author = "Sundar Subramaniam")]
#[command(version)]
#[command(about = "Universal execution governance gateway with argument-level policy enforcement", long_about = None)]
struct Args {
    /// Path to policy YAML file
    #[arg(short, long, default_value = "/etc/execwall/policy.yaml")]
    policy: String,

    /// Path to audit log file
    #[arg(short, long, default_value = "/var/log/execwall/audit.jsonl")]
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

    /// Quiet mode - suppress banner and status messages
    #[arg(short, long)]
    quiet: bool,

    /// Execute command and exit (like bash -c)
    /// All arguments after -c are joined to form the command
    #[arg(short = 'c', value_name = "COMMAND", num_args = 1.., trailing_var_arg = true)]
    command: Option<Vec<String>>,

    /// Run in JSON API mode (TCP server)
    #[arg(long)]
    api: bool,

    /// Port for API server (default: 9999)
    #[arg(long, default_value = "9999")]
    port: u16,

    /// Path to python_runner binary (for API mode)
    #[arg(long, default_value = "/usr/lib/execwall/python_runner")]
    python_runner: String,
}

fn main() {
    let args = Args::parse();

    // Check if we should run in API mode
    if args.api {
        run_api_mode(args.port, &args.python_runner);
        return;
    }

    // Check if we should run a single command (-c flag, like bash -c)
    if let Some(ref cmd_parts) = args.command {
        // Join all command parts into a single command string
        let cmd = cmd_parts.join(" ");
        run_single_command(&args, &cmd);
        return;
    }

    // Banner (skip in quiet mode)
    if !args.quiet {
        println!(
            "{}",
            "╔══════════════════════════════════════════════════════════╗".cyan()
        );
        println!(
            "{}",
            "║              Execwall - Execution Firewall               ║".cyan()
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
    }

    // Load policy
    let engine = match PolicyEngine::load_from_file(&args.policy) {
        Ok(e) => {
            if !args.quiet {
                println!("{} Loaded policy from: {}", "✓".green(), args.policy);
            }
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
    if !args.quiet {
        println!("{} {}", "Policy:".cyan(), engine.info());
    }

    // Initialize rate limiter from policy config
    let rate_config = engine.rate_limit_config();
    let mut rate_limiter = RateLimiter::new(rate_config.max_commands, rate_config.window_seconds);
    if !args.quiet {
        println!(
            "{} Rate limit: {} commands per {} seconds",
            "✓".green(),
            rate_config.max_commands,
            rate_config.window_seconds
        );
    }

    // Determine identity
    let identity = args.identity.clone().unwrap_or_else(|| {
        users::get_current_username()
            .map(|u| u.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });
    if !args.quiet {
        println!("{} Identity: {}", "✓".green(), identity);
    }

    // Check for mode override
    let effective_mode = match &args.mode {
        Some(m) if m == "audit" => {
            if !args.quiet {
                println!(
                    "{} Mode overridden to AUDIT (log only, no blocking)",
                    "⚠".yellow()
                );
            }
            true
        }
        _ => *engine.mode() == PolicyMode::Audit,
    };

    // Initialize audit logger
    let logger = match AuditLogger::new(&args.log) {
        Ok(l) => {
            if !args.quiet {
                println!("{} Audit log: {}", "✓".green(), args.log);
            }
            l
        }
        Err(e) => {
            if !args.quiet {
                eprintln!(
                    "{} Failed to initialize audit log: {}",
                    "Warning:".yellow(),
                    e
                );
                eprintln!("  Continuing without file logging...");
            }
            AuditLogger::stdout_only()
        }
    };

    if !args.quiet {
        println!("{} Session: {}", "✓".green(), logger.session_id());
        println!();
    }

    // Log session start
    logger.log_session_start(&engine.info());

    // Show mode indicator (skip in quiet mode)
    if !args.quiet {
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
    }

    // Start interactive shell
    let mut commands_executed: u64 = 0;
    let mut commands_denied: u64 = 0;

    let mut rl = DefaultEditor::new().expect("Failed to initialize readline");

    // Get current working directory
    let cwd = env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| ".".to_string());

    loop {
        // Build prompt (simple in quiet mode)
        let prompt = if args.quiet {
            "$ ".to_string()
        } else {
            let mode_indicator = if effective_mode {
                "audit".yellow()
            } else {
                "enforce".green()
            };
            format!("[execwall:{}]$ ", mode_indicator)
        };

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
                        if !args.quiet {
                            println!("{} Exiting execwall...", "→".cyan());
                        }
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
                if !args.quiet {
                    println!("{} EOF received, exiting...", "→".cyan());
                }
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

    // Summary (skip in quiet mode)
    if !args.quiet {
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
    println!(
        "{}",
        "Execwall - Execution Firewall for AI Agents".cyan().bold()
    );
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

/// Run a single command and exit (like bash -c)
fn run_single_command(args: &Args, command: &str) {
    // Load policy
    let engine = match PolicyEngine::load_from_file(&args.policy) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("execwall: failed to load policy: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize rate limiter
    let rate_config = engine.rate_limit_config();
    let mut rate_limiter = RateLimiter::new(rate_config.max_commands, rate_config.window_seconds);

    // Determine identity
    let identity = args.identity.clone().unwrap_or_else(|| {
        users::get_current_username()
            .map(|u| u.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });

    // Check for mode override
    let effective_mode = match &args.mode {
        Some(m) if m == "audit" => true,
        _ => *engine.mode() == PolicyMode::Audit,
    };

    // Initialize audit logger (quietly)
    let logger = AuditLogger::new(&args.log).unwrap_or_else(|_| AuditLogger::stdout_only());

    // Get current working directory
    let cwd = env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| ".".to_string());

    // Check rate limit
    if let Err(wait_secs) = rate_limiter.check(&identity) {
        let parsed = ParsedCommand::parse(command);
        logger.log_evaluation(
            command,
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
        eprintln!(
            "execwall: rate limit exceeded, try again in {} seconds",
            wait_secs
        );
        std::process::exit(1);
    }

    // Evaluate command against policy
    let eval_start = Instant::now();
    let result = engine.evaluate_with_identity(command, Some(&identity));
    let parsed = ParsedCommand::parse(command);

    if result.allowed || effective_mode {
        // Command is allowed (or we're in audit mode)
        let decision = if result.allowed {
            Decision::Allowed
        } else {
            Decision::AuditOnly
        };

        // Log the evaluation
        let entry = logger.log_evaluation(
            command,
            &parsed.executable,
            &parsed.args_string,
            &cwd,
            decision,
            result.matched_rule.clone(),
            result.reason.clone(),
            eval_start,
        );

        // Record for rate limiting
        rate_limiter.record(&identity);

        // Execute the command
        let exec_start = Instant::now();
        let exit_code = execute_command(command);

        // Log execution completion
        logger.log_execution_complete(entry, exec_start, exit_code);

        std::process::exit(exit_code);
    } else {
        // Command is denied
        logger.log_evaluation(
            command,
            &parsed.executable,
            &parsed.args_string,
            &cwd,
            Decision::Denied,
            result.matched_rule.clone(),
            result.reason.clone(),
            eval_start,
        );

        if !args.quiet {
            eprintln!("execwall: command denied: {}", command);
            if let Some(rule) = &result.matched_rule {
                eprintln!("  rule: {}", rule);
            }
            if let Some(reason) = &result.reason {
                eprintln!("  reason: {}", reason);
            }
        }
        std::process::exit(1);
    }
}

/// Run Execwall in JSON API mode
fn run_api_mode(port: u16, python_runner_path: &str) {
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║              Execwall - JSON API Mode                    ║".cyan()
    );
    println!(
        "{}",
        "║         Python Sandbox Execution Server                  ║".cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════╝".cyan()
    );
    println!();

    let server = api::ApiServer::new(port, python_runner_path);

    // Create tokio runtime and run the server
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    runtime.block_on(async {
        if let Err(e) = server.start().await {
            eprintln!("{} Failed to start API server: {}", "Error:".red(), e);
            std::process::exit(1);
        }
    });
}
