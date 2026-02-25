# OpenClaw + Sentra - Oracle Cloud Deployment Guide

Deploy a secure AI agent environment on **Oracle Cloud Free Tier** with:
- **WhatsApp** integration for messaging
- **Email** support via Himalaya
- **OpenRouter** LLM (Claude, GPT-4, etc.)
- **Sentra** command governance

## Deployment Options

| Mode | Security | Use Case |
|------|----------|----------|
| **Standard** (recommended) | Sentra REPL policy enforcement | WhatsApp + Email + OpenRouter |
| **Seccomp** | Sentra + kernel syscall filtering | High-security environments |

This guide covers the **Standard** deployment.

## Architecture Overview

```
                    Internet
                        │
                        ▼
┌───────────────────────────────────────────────────────────────┐
│              Oracle Cloud VM (Free Tier)                       │
│              ARM64 Ampere A1 - 4 CPU, 24GB RAM                │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              OpenClaw Gateway (Node.js)                  │  │
│  │  • WhatsApp Web integration                              │  │
│  │  • LLM API calls (OpenRouter)                           │  │
│  │  • Email via Himalaya                                    │  │
│  │  • SHELL=/usr/local/bin/sentra-shell                    │  │
│  └────────────────────────┬────────────────────────────────┘  │
│                           │                                    │
│                           ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              sentra-shell (--quiet mode)                 │  │
│  │  • Policy-enforced command execution                     │  │
│  │  • Rate limiting                                         │  │
│  │  • Audit logging                                         │  │
│  │  • Clean output (no banner noise)                        │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                │
│  Services: openclaw.service (systemd)                          │
│  Config:   /etc/sentra/policy.yaml                            │
│  Logs:     /var/log/sentra/audit.jsonl                        │
│                                                                │
└───────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Oracle Cloud account (Free Tier eligible)
- SSH key pair for VM access
- WhatsApp account for bot integration (optional)
- LLM API key (Gemini, OpenRouter, etc.)

## Quick Start

### 1. Create Oracle Cloud VM

1. Log in to Oracle Cloud Console
2. Create a **Compute Instance**:
   - Shape: `VM.Standard.A1.Flex` (ARM64, Free Tier)
   - OCPUs: 4 (Free Tier allows up to 4)
   - Memory: 24 GB (Free Tier allows up to 24)
   - Image: Oracle Linux 9 or Ubuntu 22.04
   - Boot Volume: 100 GB (Free Tier)

3. Configure networking:
   - Create VCN with public subnet
   - Allow ingress on port 22 (SSH)

4. Add your SSH public key

### 2. One-Line Install

SSH into your VM and run:

```bash
# Install everything (Sentra, OpenClaw, Himalaya)
curl -sSL https://raw.githubusercontent.com/sundarsub/sentra/main/scripts/install-oracle-cloud.sh | sudo bash
```

Or with pre-configured credentials:

```bash
# Set credentials as environment variables
export OPENROUTER_API_KEY="sk-or-v1-your-key-here"
export GMAIL_ADDRESS="your-email@gmail.com"
export GMAIL_APP_PASSWORD="xxxx xxxx xxxx xxxx"  # Gmail app password

# Run installer
curl -sSL https://raw.githubusercontent.com/sundarsub/sentra/main/scripts/install-oracle-cloud.sh | sudo -E bash
```

### 3. Start OpenClaw

```bash
# Start with Sentra (quiet mode - no banner noise)
openclaw-start

# Or use systemd service
sudo systemctl start openclaw
sudo systemctl enable openclaw  # Start on boot
```

### 4. Link WhatsApp

When OpenClaw starts, a QR code appears. Scan it with WhatsApp mobile:
1. Open WhatsApp on your phone
2. Go to Settings → Linked Devices
3. Tap "Link a Device"
4. Scan the QR code

### 5. Test Email (Optional)

```bash
# Send a test email
email "recipient@example.com" "Test Subject" "Hello from Sentra!"
```

## Build from Source

If pre-built binaries don't work (GLIBC issues), build from source:

```bash
export BUILD_FROM_SOURCE=1
curl -sSL https://raw.githubusercontent.com/sundarsub/sentra/main/scripts/install-oracle-cloud.sh | sudo -E bash
```

## What Gets Installed

| Component | Path | Description |
|-----------|------|-------------|
| `sentra` | `/usr/local/bin/sentra` | Execution governance REPL (supports `--quiet`) |
| `sentra-shell` | `/usr/local/bin/sentra-shell` | SHELL wrapper with quiet mode |
| `email` | `/usr/local/bin/email` | Send email to any recipient |
| `send-email` | `/usr/local/bin/send-email` | Simple email helper script |
| `himalaya` | `/usr/local/bin/himalaya` | CLI email client (IMAP/SMTP) |
| `openclaw` | `/usr/bin/openclaw` | AI agent gateway (npm global) |
| `openclaw-start` | `/usr/local/bin/openclaw-start` | Start OpenClaw with Sentra |
| `openclaw-status` | `/usr/local/bin/openclaw-status` | Check service status |
| `policy.yaml` | `/etc/sentra/policy.yaml` | Execution policy rules |

## Security Profiles

### Gateway Profile (Default)

For OpenClaw gateway process - allows subprocess spawning but blocks dangerous syscalls:

```yaml
seccomp_profiles:
  gateway:
    default: allow
    deny_dangerous:
      - ptrace
      - mount
      - bpf
      - kexec_load
      - reboot
      - init_module
```

### WhatsApp Agent Profile

For sandboxed code execution with WhatsApp network access:

```yaml
seccomp_profiles:
  whatsapp_agent:
    extends: base_restricted
    allow:
      - socket
      - connect
      - sendto
      - recvfrom
    network_policy:
      allow_outbound:
        - "*.whatsapp.net:443"
        - "*.whatsapp.com:443"
```

### Isolated Agent Profile

For maximum isolation - no network, no spawn:

```yaml
seccomp_profiles:
  isolated_agent:
    extends: base_restricted
    deny:
      - socket
      - connect
```

## Command Governance

Sentra REPL enforces policy on all commands:

```
[sentra:enforce]$ ls -la
total 48
drwxr-xr-x  5 opc opc 4096 Feb 24 10:00 .
...

[sentra:enforce]$ rm -rf /
[X] DENIED: rm -rf /
  Rule:   block_rm_rf_root
  Reason: Recursive deletion of root filesystem is blocked

[sentra:enforce]$ sudo su
[X] DENIED: sudo su
  Rule:   block_sudo
  Reason: Privilege escalation via sudo is blocked
```

## Python Sandbox

Python code executes in an isolated sandbox:

```python
# This runs in python_runner with:
# - Namespace isolation (mount, PID, network)
# - Seccomp syscall filtering
# - Cgroup resource limits (512MB RAM, 30s timeout)

import math
print(f"Pi = {math.pi}")  # Works

import subprocess
subprocess.run(["ls"])  # BLOCKED by seccomp
```

## Monitoring

### View Audit Logs

```bash
# Real-time audit log
tail -f /var/log/sentra/audit.jsonl | jq .

# Filter denied commands
grep '"decision":"denied"' /var/log/sentra/audit.jsonl | jq .
```

### Check Process Status

```bash
# OpenClaw processes
ps aux | grep openclaw

# Sentra status
systemctl status openclaw-firewall
```

### Resource Usage

```bash
# Memory and CPU
htop

# Disk usage
df -h
```

## Troubleshooting

### OpenClaw won't start

```bash
# Check if ports are in use
ss -tlnp | grep 18789

# Kill existing processes
pkill -9 openclaw

# Check logs
journalctl -u openclaw-firewall -n 50
```

### WhatsApp not connecting

```bash
# Check WhatsApp logs
tail -f /tmp/openclaw/openclaw-*.log | grep whatsapp

# Re-authenticate
rm -rf ~/.openclaw/whatsapp/
openclaw gateway  # Scan new QR code
```

### Seccomp blocking needed operations

```bash
# List available profiles
openclaw_launcher --list-profiles

# Use development profile (less restrictive)
openclaw_launcher --seccomp-profile development ...

# Or disable seccomp (NOT recommended for production)
openclaw_launcher --no-seccomp ...
```

### Policy denying valid commands

```bash
# Check which rule is blocking
sentra --verbose

# Test command evaluation
echo "your-command" | sentra --policy /etc/sentra/policy.yaml

# Edit policy
sudo vim /etc/sentra/policy.yaml
```

## Updating

```bash
# Update Sentra components
curl -sSL https://raw.githubusercontent.com/sundarsub/sentra/main/scripts/install-oracle-cloud.sh | sudo bash

# Update OpenClaw
sudo npm update -g openclaw
```

## Uninstalling

```bash
# Stop services
sudo systemctl stop openclaw-firewall
sudo systemctl disable openclaw-firewall

# Remove binaries
sudo rm -f /usr/local/bin/sentra
sudo rm -f /usr/local/bin/openclaw_launcher
sudo rm -f /usr/local/bin/sentra-shell
sudo rm -rf /usr/lib/sentra/

# Remove config
sudo rm -rf /etc/sentra/

# Remove OpenClaw
sudo npm uninstall -g openclaw
rm -rf ~/.openclaw/
```

## Security Considerations

1. **API Keys**: Store API keys in environment variables, not in config files
2. **Firewall**: Only expose necessary ports (22 for SSH, optionally 18789)
3. **Updates**: Regularly update Sentra and OpenClaw for security patches
4. **Audit Logs**: Monitor `/var/log/sentra/audit.jsonl` for suspicious activity
5. **WhatsApp**: Use a dedicated phone number for the bot

## Cost (Oracle Cloud Free Tier)

| Resource | Free Tier Allowance | Usage |
|----------|---------------------|-------|
| Compute | 4 ARM OCPUs, 24GB RAM | Full allocation |
| Storage | 200GB boot volume | 100GB used |
| Network | 10TB/month outbound | Minimal for WhatsApp |
| **Total** | **$0/month** | Within free tier |

## Support

- GitHub Issues: https://github.com/sundarsub/sentra/issues
- Email: sentrahelp@gmail.com
