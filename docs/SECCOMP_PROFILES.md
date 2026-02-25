# Seccomp Profiles for Secure Operations

Execwall includes configurable seccomp-BPF profiles that restrict system calls at the kernel level. This document describes the available profiles and their security characteristics.

## Current Configuration

The default deployment uses the **gateway** profile, which is designed for secure AI agent operations with messaging platform integration.

### Security Posture Summary

| Feature | Status | Notes |
|---------|--------|-------|
| WhatsApp connectivity | Allowed | WebSocket/HTTPS to WhatsApp servers |
| Telegram connectivity | Allowed | HTTPS to Telegram API |
| Process spawning | Blocked | No fork/exec except via Execwall |
| Direct network access | Blocked | Must go through approved channels |
| Filesystem access | Restricted | Policy-controlled paths only |
| Privilege escalation | Blocked | No sudo, setuid, capability changes |
| Kernel modules | Blocked | No insmod, modprobe, bpf |

## Available Profiles

### 1. `gateway` (Default for OpenClaw)

Permissive profile for the OpenClaw gateway process. Allows subprocess creation since OpenClaw needs to spawn internal workers.

**Blocked syscalls:**
- `ptrace` - No debugging other processes
- `mount`, `umount2`, `pivot_root` - No filesystem mount operations
- `bpf` - No eBPF programs
- `init_module`, `delete_module`, `finit_module` - No kernel modules
- `kexec_load`, `kexec_file_load` - No kernel replacement
- `reboot` - No system reboot

**Use case:** OpenClaw gateway process with Execwall policy enforcement.

### 2. `base_restricted`

Base profile for sandboxed code execution. Blocks process creation except threads.

**Blocked syscalls:**
- All from `gateway`, plus:
- `fork`, `vfork`, `execveat` - No new processes
- `clone` (conditional) - Blocked unless `CLONE_THREAD` flag set
- `unshare`, `setns` - No namespace manipulation
- `setuid`, `setgid`, `setresuid`, `setresgid` - No privilege changes
- `capset` - No capability changes
- `perf_event_open` - No performance monitoring

**Use case:** Running untrusted code in isolation.

### 3. `whatsapp_agent`

Extends `base_restricted` with network access for WhatsApp Web protocol.

**Additional allowed syscalls:**
- Socket operations: `socket`, `connect`, `accept`, `bind`, `listen`
- Data transfer: `sendto`, `recvfrom`, `sendmsg`, `recvmsg`
- Multiplexing: `epoll_*`, `poll`, `select`

**Network policy (enforced via iptables):**
```yaml
allow_loopback: true
allow_outbound:
  - "*.whatsapp.net:443"
  - "*.whatsapp.com:443"
  - "web.whatsapp.com:443"
  - "mmg.whatsapp.net:443"
  - "media.whatsapp.com:443"
```

**Use case:** WhatsApp-enabled AI agents.

### 4. `telegram_agent`

Extends `base_restricted` with network access for Telegram Bot API.

**Network policy:**
```yaml
allow_loopback: true
allow_outbound:
  - "api.telegram.org:443"
  - "*.telegram.org:443"
```

**Use case:** Telegram bot AI agents.

### 5. `isolated_agent`

Most restrictive profile - no network access except localhost.

**Blocked syscalls:**
- All network syscalls: `socket`, `connect`, `accept`, `bind`, etc.

**Network policy:**
```yaml
allow_loopback: true  # For Execwall API only
allow_outbound: []    # No external network
```

**Use case:** Pure code execution with no external communication.

### 6. `development`

Permissive profile for testing. Only blocks truly dangerous syscalls.

**Blocked syscalls:**
- `reboot`, `kexec_load`, `init_module`, `delete_module`

**Use case:** Development and debugging only. Never use in production.

## Applying Profiles

### Via openclaw_launcher

```bash
# Run OpenClaw with gateway profile (default)
openclaw_launcher --seccomp-profile gateway openclaw

# Run with WhatsApp profile
openclaw_launcher --seccomp-profile whatsapp_agent openclaw
```

### Via policy.yaml

```yaml
launcher:
  default_profile: gateway

  execwall:
    enabled: true
    mode: repl
    binary: /usr/local/bin/execwall
    shell_wrapper: /usr/local/bin/execwall-shell
```

## Security Recommendations

1. **Production deployments** should use `gateway` profile with Execwall policy enforcement
2. **Code execution sandboxes** should use `isolated_agent` or `base_restricted`
3. **Never use `development` profile** in production
4. **Combine with Execwall policies** for defense-in-depth:
   - Seccomp blocks at kernel level (syscall filtering)
   - Execwall blocks at command level (policy rules)

## Limitations

- Seccomp profiles are Linux-only (macOS uses different enforcement)
- Network policies in seccomp are informational; actual enforcement requires iptables/nftables
- Clone syscall filtering may affect some multi-threaded applications

## Future Work

- JetPatch console integration for centralized profile management
- Dynamic profile switching based on workload
- Network policy enforcement via eBPF (when available)
