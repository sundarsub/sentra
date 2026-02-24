# Plan: Seccomp Profiles in YAML + OpenClaw Launcher Integration

## Overview

Add configurable seccomp profiles to `policy.yaml` that `openclaw_launcher` reads before launching OpenClaw. The launcher applies the seccomp filter, then execs OpenClaw which uses Sentra REPL for command governance.

## Current Architecture

```
┌─────────────────────┐
│  openclaw_launcher  │
│  (Rust binary)      │
│                     │
│  1. Start Sentra    │
│  2. Apply seccomp   │  ← Hardcoded in Rust
│  3. Exec OpenClaw   │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│     OpenClaw        │
│  (Node.js agent)    │
│                     │
│  - WhatsApp         │
│  - AI agent         │
│  - Exec commands    │  → Direct execution (no Sentra)
└─────────────────────┘
```

**Problems:**
- Seccomp profiles hardcoded in Rust
- OpenClaw bypasses Sentra REPL for commands
- No profile selection (one-size-fits-all)

## Proposed Architecture

```
┌─────────────────────┐
│  openclaw_launcher  │
│  (Rust binary)      │
│                     │
│  1. Read policy.yaml│
│  2. Select profile  │  ← From YAML (e.g., "whatsapp_agent")
│  3. Apply seccomp   │
│  4. Set SHELL=sentra│
│  5. Exec OpenClaw   │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐      ┌─────────────────────┐
│     OpenClaw        │      │    Sentra REPL      │
│  (Node.js agent)    │ ───► │  (command gateway)  │
│                     │      │                     │
│  - WhatsApp ✓       │      │  - Policy enforce   │
│  - AI agent         │      │  - Python sandbox   │
│  - Exec via SHELL   │      │  - Audit logging    │
└─────────────────────┘      └─────────────────────┘
```

## YAML Schema Extension

### New Section: `seccomp_profiles`

```yaml
# =============================================================================
# SECCOMP PROFILES
# Configurable syscall filtering for different execution contexts
# =============================================================================

seccomp_profiles:
  # Base profile - maximum restrictions
  base_restricted:
    default: allow  # Default action for unlisted syscalls

    # Process creation - BLOCKED
    deny:
      - fork
      - vfork
      - execveat

    # Clone with conditions (allow threads, block processes)
    conditional:
      clone:
        # Block when CLONE_THREAD (0x10000) is NOT set
        - arg: 0
          mask: 0x10000
          value: 0
          action: deny

    # Dangerous syscalls - BLOCKED
    deny_dangerous:
      - ptrace
      - mount
      - umount2
      - pivot_root
      - bpf
      - perf_event_open
      - init_module
      - delete_module
      - finit_module
      - keyctl
      - unshare
      - setns
      - setuid
      - setgid
      - setresuid
      - setresgid
      - setgroups
      - capset
      - reboot
      - kexec_load
      - kexec_file_load
      - swapon
      - swapoff
      - sethostname
      - setdomainname
      - iopl
      - ioperm

  # WhatsApp Agent Profile - allows network for WhatsApp
  whatsapp_agent:
    extends: base_restricted

    # Network syscalls needed for WhatsApp Web
    allow:
      - socket
      - socketpair
      - connect
      - accept
      - accept4
      - bind
      - listen
      - sendto
      - recvfrom
      - sendmsg
      - recvmsg
      - shutdown
      - getsockname
      - getpeername
      - setsockopt
      - getsockopt
      - poll
      - ppoll
      - select
      - pselect6
      - epoll_create
      - epoll_create1
      - epoll_ctl
      - epoll_wait
      - epoll_pwait

    # Network restrictions (applied via iptables/nftables, not seccomp)
    network_policy:
      allow_outbound:
        - "*.whatsapp.net:443"
        - "*.whatsapp.com:443"
        - "web.whatsapp.com:443"
        - "127.0.0.1:*"  # Loopback for Sentra
      deny_outbound:
        - "*"  # Block everything else

  # Isolated Agent Profile - no network, pure sandbox
  isolated_agent:
    extends: base_restricted

    deny:
      - socket
      - socketpair
      - connect
      - accept
      - bind
      - listen
      - sendto
      - recvfrom
      - sendmsg
      - recvmsg

  # Development Profile - permissive for testing
  development:
    default: allow
    deny:
      - reboot
      - kexec_load
      - init_module
      - delete_module
```

### Launcher Configuration Section

```yaml
# =============================================================================
# LAUNCHER CONFIGURATION
# Settings for openclaw_launcher
# =============================================================================

launcher:
  # Default seccomp profile to apply
  default_profile: whatsapp_agent

  # Sentra integration
  sentra:
    enabled: true
    mode: repl          # repl | api
    binary: /usr/local/bin/sentra
    policy: /etc/sentra/policy.yaml
    python_runner: /usr/lib/sentra/python_runner

  # OpenClaw settings
  openclaw:
    binary: /usr/local/bin/openclaw
    shell_wrapper: /usr/local/bin/sentra-shell
    env:
      SHELL: "{{ sentra.shell_wrapper }}"
      GEMINI_API_KEY: "${GEMINI_API_KEY}"
```

## Implementation Tasks

### Phase 1: YAML Parser for Seccomp Profiles

**File:** `src/seccomp_profile.rs`

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SeccompProfile {
    pub default: SeccompAction,
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub deny_dangerous: Vec<String>,
    #[serde(default)]
    pub conditional: HashMap<String, Vec<ConditionalRule>>,
    #[serde(default)]
    pub network_policy: Option<NetworkPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConditionalRule {
    pub arg: u32,
    pub mask: u64,
    pub value: u64,
    pub action: SeccompAction,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SeccompAction {
    Allow,
    Deny,
    Log,
    Trap,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkPolicy {
    pub allow_outbound: Vec<String>,
    pub deny_outbound: Vec<String>,
}
```

### Phase 2: Profile Resolution with Inheritance

```rust
impl SeccompProfile {
    /// Resolve profile with inheritance chain
    pub fn resolve(
        name: &str,
        profiles: &HashMap<String, SeccompProfile>,
    ) -> Result<SeccompProfile, Error> {
        let mut resolved = profiles.get(name)
            .ok_or_else(|| Error::ProfileNotFound(name.to_string()))?
            .clone();

        // Follow extends chain
        if let Some(parent_name) = &resolved.extends {
            let parent = Self::resolve(parent_name, profiles)?;
            resolved = Self::merge(parent, resolved);
        }

        Ok(resolved)
    }

    /// Merge child profile over parent
    fn merge(parent: SeccompProfile, child: SeccompProfile) -> SeccompProfile {
        SeccompProfile {
            default: child.default,
            extends: None,  // Already resolved
            allow: [parent.allow, child.allow].concat(),
            deny: [parent.deny, child.deny].concat(),
            deny_dangerous: [parent.deny_dangerous, child.deny_dangerous].concat(),
            conditional: {
                let mut merged = parent.conditional;
                merged.extend(child.conditional);
                merged
            },
            network_policy: child.network_policy.or(parent.network_policy),
        }
    }
}
```

### Phase 3: Update openclaw_launcher

**Changes to `src/bin/openclaw_launcher.rs`:**

```rust
use sentra::seccomp_profile::{SeccompProfile, load_profiles};

#[derive(Parser, Debug)]
struct Args {
    // ... existing args ...

    /// Seccomp profile to apply (from policy.yaml)
    #[arg(long, default_value = "whatsapp_agent")]
    seccomp_profile: String,

    /// Path to policy.yaml
    #[arg(long, default_value = "/etc/sentra/policy.yaml")]
    policy: String,

    /// Use Sentra REPL for command execution
    #[arg(long)]
    sentra_repl: bool,
}

fn main() {
    let args = Args::parse();

    // Load profiles from YAML
    let profiles = load_profiles(&args.policy)?;
    let profile = SeccompProfile::resolve(&args.seccomp_profile, &profiles)?;

    println!("→ Using seccomp profile: {}", args.seccomp_profile);

    // Apply seccomp from profile
    apply_seccomp_from_profile(&profile, args.verbose)?;

    // Set SHELL to Sentra wrapper if enabled
    if args.sentra_repl {
        std::env::set_var("SHELL", "/usr/local/bin/sentra-shell");
    }

    // Exec OpenClaw
    exec_openclaw(&args.openclaw_bin, &args.openclaw_args);
}

fn apply_seccomp_from_profile(
    profile: &SeccompProfile,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

    // Set NO_NEW_PRIVS
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }

    // Create filter with default action
    let default_action = match profile.default {
        SeccompAction::Allow => ScmpAction::Allow,
        SeccompAction::Deny => ScmpAction::Errno(libc::EPERM),
        _ => ScmpAction::Allow,
    };
    let mut filter = ScmpFilterContext::new_filter(default_action)?;

    // Apply deny rules
    for syscall_name in &profile.deny {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            filter.add_rule(ScmpAction::Errno(libc::EPERM), syscall)?;
            if verbose {
                println!("  → Deny: {}", syscall_name);
            }
        }
    }

    // Apply deny_dangerous
    for syscall_name in &profile.deny_dangerous {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            filter.add_rule(ScmpAction::Errno(libc::EPERM), syscall)?;
        }
    }

    // Apply allow rules (only if default is deny)
    if matches!(profile.default, SeccompAction::Deny) {
        for syscall_name in &profile.allow {
            if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
                filter.add_rule(ScmpAction::Allow, syscall)?;
                if verbose {
                    println!("  → Allow: {}", syscall_name);
                }
            }
        }
    }

    // Apply conditional rules (e.g., clone with CLONE_THREAD check)
    for (syscall_name, rules) in &profile.conditional {
        if let Ok(syscall) = ScmpSyscall::from_name(syscall_name) {
            for rule in rules {
                let action = match rule.action {
                    SeccompAction::Deny => ScmpAction::Errno(libc::EPERM),
                    _ => ScmpAction::Allow,
                };
                filter.add_rule_conditional(
                    action,
                    syscall,
                    &[ScmpArgCompare::new(
                        rule.arg,
                        ScmpCompareOp::MaskedEqual(rule.mask),
                        rule.value,
                    )],
                )?;
            }
        }
    }

    // Load filter (irremovable)
    filter.load()?;

    Ok(())
}
```

### Phase 4: Sentra Shell Wrapper

**File:** `/usr/local/bin/sentra-shell`

```bash
#!/bin/bash
# Sentra Shell - REPL wrapper for OpenClaw
# Routes all exec commands through Sentra policy enforcement

SENTRA_BIN="${SENTRA_BIN:-/usr/local/bin/sentra}"
POLICY="${SENTRA_POLICY:-/etc/sentra/policy.yaml}"
PYTHON_RUNNER="${PYTHON_RUNNER:-/usr/lib/sentra/python_runner}"

if [[ $# -gt 0 ]]; then
    # Single command mode
    echo "$*" | "$SENTRA_BIN" --policy "$POLICY" --python-runner "$PYTHON_RUNNER"
else
    # Interactive REPL
    exec "$SENTRA_BIN" --policy "$POLICY" --python-runner "$PYTHON_RUNNER"
fi
```

## Execution Flow

```
User sends WhatsApp message
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                    openclaw_launcher                     │
│                                                         │
│  1. Parse --seccomp-profile=whatsapp_agent              │
│  2. Load policy.yaml                                    │
│  3. Resolve profile (with inheritance from base)        │
│  4. Apply seccomp filter:                               │
│     - Block: fork, vfork, ptrace, mount, etc.          │
│     - Allow: socket, connect (for WhatsApp)            │
│     - Conditional: clone (threads OK, processes NO)     │
│  5. Set SHELL=/usr/local/bin/sentra-shell              │
│  6. exec(openclaw gateway)                              │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                      OpenClaw                            │
│                  (seccomp locked)                        │
│                                                         │
│  - WhatsApp Web connection ✓ (network allowed)          │
│  - AI agent processes messages                          │
│  - Agent wants to run: `ls -la /tmp`                    │
│  - Calls SHELL with command                             │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                   Sentra REPL                            │
│              (policy enforcement)                        │
│                                                         │
│  1. Receive command: `ls -la /tmp`                      │
│  2. Match against policy rules                          │
│  3. Rule "safe_read_commands" → ALLOW                   │
│  4. Execute and return output                           │
│                                                         │
│  If command was `rm -rf /`:                             │
│  → Rule "block_rm_rf_root" → DENY                       │
│  → Return error, command blocked                        │
└─────────────────────────────────────────────────────────┘
```

## Profile Examples

### 1. WhatsApp Agent (Default)
- Network: Full outbound to WhatsApp servers
- Process: No subprocess spawning
- Commands: Via Sentra REPL policy

### 2. Telegram Agent
```yaml
telegram_agent:
  extends: base_restricted
  allow:
    - socket
    - connect
    # ... network syscalls
  network_policy:
    allow_outbound:
      - "api.telegram.org:443"
      - "*.telegram.org:443"
      - "127.0.0.1:*"
```

### 3. Isolated Code Executor
```yaml
code_executor:
  extends: base_restricted
  deny:
    - socket  # No network at all
  # All execution via python_runner sandbox
```

### 4. Browser Automation Agent
```yaml
browser_agent:
  extends: whatsapp_agent
  allow:
    - clone3  # Chromium needs this for sandboxing
  network_policy:
    allow_outbound:
      - "*:443"  # HTTPS to any site
      - "*:80"   # HTTP to any site
```

## File Changes Summary

| File | Change |
|------|--------|
| `policy.yaml` | Add `seccomp_profiles` and `launcher` sections |
| `src/seccomp_profile.rs` | New module for profile parsing |
| `src/lib.rs` | Export seccomp_profile module |
| `src/bin/openclaw_launcher.rs` | Read profiles from YAML, apply dynamically |
| `/usr/local/bin/sentra-shell` | Wrapper script for REPL integration |
| `Cargo.toml` | Already has libseccomp dependency |

## Testing Plan

1. **Unit Tests:** Profile parsing and inheritance
2. **Integration:** Launch with each profile, verify syscalls blocked
3. **E2E:** WhatsApp message → AI response → command execution → Sentra enforcement

## Questions to Resolve

1. Should network policy (iptables) be applied by launcher or separate script?
2. How to handle profile hot-reload without restarting?
3. Should we support profile selection per-agent in OpenClaw config?
