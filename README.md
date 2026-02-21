# Sentra

**Universal Execution Governance Gateway**

Sentra is a policy-enforced shell that provides argument-level command governance, per-identity rate limiting, and comprehensive audit logging. Deploy it as a login shell or forced command to transform any endpoint into a governed execution environment.

## Features

- **Argument-Level Policy Enforcement**: Evaluate commands with regex-based pattern matching on executables and arguments
- **Per-Identity Rate Limiting**: Configurable command rate limits per user/identity with sliding window algorithm
- **Identity-Scoped Rules**: Apply different policies to different users, service accounts, or AI agents
- **Comprehensive Audit Logging**: JSON Lines audit log with timestamps, decisions, execution times, and exit codes
- **Enforce/Audit Modes**: Block denied commands (enforce) or log-only (audit) for testing policies
- **Interactive Shell**: Full readline support with command history

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/sundarsub/sentra/main/install.sh | bash
```

This installs:
- Binary to `/usr/local/bin/sentra`
- Default policy to `/etc/sentra/policy.yaml`

### From Source

```bash
# Clone the repository
git clone https://github.com/sundarsubramaniam/sentra.git
cd sentra

# Build release binary
cargo build --release

# Binary is at target/release/sentra
```

### Install as Shell

```bash
# Copy binary to system path
sudo cp target/release/sentra /usr/local/bin/

# Add to valid shells
echo '/usr/local/bin/sentra' | sudo tee -a /etc/shells

# Set as user's shell (optional)
chsh -s /usr/local/bin/sentra

# Or configure SSH forced command in sshd_config:
# Match User developer
#     ForceCommand /usr/local/bin/sentra --policy /etc/sentra/policy.yaml
```

## Usage

```bash
# Start with default policy
sentra

# Specify policy file
sentra --policy /path/to/policy.yaml

# Specify audit log location
sentra --log /var/log/sentra/audit.jsonl

# Run in audit mode (log only, don't block)
sentra --mode audit

# Specify identity (overrides current user)
sentra --identity service-account

# Verbose output
sentra --verbose
```

### Built-in Commands

- `help` - Show help message
- `status` - Display session statistics and rate limit usage
- `exit` / `quit` - Exit the shell

## Policy Configuration

Policies are YAML files that define rules evaluated in order (first match wins).

### Example Policy

```yaml
version: "1.0"
mode: enforce        # enforce | audit
default: deny        # deny | allow (when no rule matches)

rate_limit:
  max_commands: 60   # Maximum commands per window
  window_seconds: 60 # Window duration

rules:
  # Allow common read-only commands
  - id: allow_read_commands
    match:
      executable: "^(ls|cat|head|tail|grep|find|pwd|whoami|date|echo)$"
    effect: allow

  # Allow git read operations
  - id: git_read_only
    match:
      executable: "^git$"
      args_pattern: "^(status|log|diff|branch|show|remote -v)"
    effect: allow

  # Block git push/force operations
  - id: git_block_write
    match:
      executable: "^git$"
      args_pattern: "(push|reset --hard|clean -fd)"
    effect: deny
    reason: "Git write operations are restricted"

  # Block privilege escalation
  - id: block_sudo
    match:
      executable: "^(sudo|su|doas)$"
    effect: deny
    reason: "Privilege escalation is not permitted"

  # Block destructive commands
  - id: block_destructive
    match:
      executable: "^rm$"
      args_pattern: "(-rf|--recursive.*--force)"
    effect: deny
    reason: "Recursive forced deletion is blocked"

  # Identity-scoped rule: allow admin users more access
  - id: admin_full_access
    match:
      identity: "^(admin|root)$"
      executable: ".*"
    effect: allow

  # Service account restrictions
  - id: service_account_restricted
    match:
      identity: "^svc-.*"
      executable: "^(curl|wget|nc|ncat)$"
    effect: deny
    reason: "Network tools blocked for service accounts"
```

### Policy Fields

| Field | Description |
|-------|-------------|
| `version` | Policy version string |
| `mode` | `enforce` (block denied) or `audit` (log only) |
| `default` | `deny` or `allow` when no rule matches |
| `rate_limit.max_commands` | Max commands per identity per window |
| `rate_limit.window_seconds` | Rate limit window duration |
| `rules` | List of rules evaluated in order |

### Rule Fields

| Field | Description |
|-------|-------------|
| `id` | Unique rule identifier (shown in logs) |
| `match.executable` | Regex pattern for command name |
| `match.args_pattern` | Regex pattern for arguments |
| `match.identity` | Regex pattern for user/identity |
| `effect` | `allow` or `deny` |
| `reason` | Message shown when denied (optional) |

## Audit Log Format

Audit logs are JSON Lines format, one entry per line:

```json
{"timestamp":"2026-02-21T10:30:00Z","session_id":"abc-123","host":"server1","user":"developer","action":"exec","command":"git status","executable":"git","args":"status","cwd":"/home/dev/project","decision":"allowed","rule_id":"git_read_only","eval_duration_ms":0,"exec_duration_ms":45,"exit_code":0}
```

### Event Types

- `session_start` - Session began with policy info
- `exec` - Command evaluation and execution
- `session_end` - Session ended with statistics

## Security Considerations

### Deployment as Forced Shell

When deployed as a ForceCommand or login shell:

1. Users cannot bypass the governance gateway
2. All commands are evaluated against policy
3. Rate limiting prevents automated attacks
4. Audit trail provides forensic visibility

### Rate Limiting for Breach Containment

Rate limiting disrupts attack patterns:
- Automated reconnaissance is throttled
- Brute-force attempts are slowed
- Data exfiltration is rate-constrained

### Policy Design Best Practices

1. **Default Deny**: Start with `default: deny` and explicitly allow needed commands
2. **Specific Rules First**: More specific rules should come before general ones
3. **Identity Scoping**: Use identity patterns to apply different rules per user type
4. **Test in Audit Mode**: Use `mode: audit` to test policies before enforcing

## Building from Source

### Requirements

- Rust 1.70+ (with cargo)
- Standard Unix build tools

### Build Commands

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run with verbose output
cargo run -- --verbose
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

The Apache 2.0 license includes:
- Grant of patent rights to users
- Patent retaliation clause for protection

## Contributing

Contributions are welcome. Please ensure:

1. Code follows existing style
2. Tests pass (`cargo test`)
3. New features include tests
4. Commit messages are descriptive

## Author

Sundar Subramaniam

## Support

For support and inquiries, contact Amar Anand: sentrahelp@gmail.com
