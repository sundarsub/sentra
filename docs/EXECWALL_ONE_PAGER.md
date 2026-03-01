# Execwall - Secure AI Agent Execution Firewall

## What is Execwall?

Execwall is an **execution firewall** for AI agents. It provides kernel-level security to ensure AI systems can only execute authorized commands within strict security boundaries.

As AI agents become more capable of executing code and system commands, Execwall acts as the critical security layer between AI and your operating system.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Seccomp Syscall Filtering** | Block dangerous operations at the Linux kernel level |
| **Policy-Based Governance** | Regex rules define what commands can execute |
| **Python Sandbox Isolation** | Namespace + cgroup + seccomp for untrusted code |
| **WhatsApp/Telegram Integration** | Deploy secure messaging AI assistants |
| **Audit Logging** | Complete visibility into all execution attempts |

---

## How It Works

```
┌─────────────────────────────────────┐
│     AI Agent (OpenClaw, etc.)       │
│  WhatsApp Bot / Code Execution      │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│      EXECWALL SECURITY LAYER        │
│  • Seccomp profiles                 │
│  • Policy engine                    │
│  • Python sandbox (namespaces)      │
│  • Audit logging                    │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│          Linux Kernel               │
└─────────────────────────────────────┘
```

---

## Download & Install

### Option 1: Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/scripts/install.sh | sudo bash
```

### Option 2: Download from GitHub Releases

**Latest Release: v1.0.1**

| Platform | Download |
|----------|----------|
| Linux x86_64 | [execwall-linux-x86_64.tar.gz](https://github.com/sundarsub/execwall/releases/download/v1.0.1/execwall-linux-x86_64.tar.gz) |
| macOS ARM64 (Apple Silicon) | [execwall-macos-aarch64.tar.gz](https://github.com/sundarsub/execwall/releases/download/v1.0.1/execwall-macos-aarch64.tar.gz) |
| macOS x86_64 (Intel) | [execwall-macos-x86_64.tar.gz](https://github.com/sundarsub/execwall/releases/download/v1.0.1/execwall-macos-x86_64.tar.gz) |

**Manual Installation:**
```bash
# Download (Linux example)
wget https://github.com/sundarsub/execwall/releases/download/v1.0.1/execwall-linux-x86_64.tar.gz

# Extract
tar -xzf execwall-linux-x86_64.tar.gz

# Install
sudo mv execwall /usr/local/bin/
sudo chmod +x /usr/local/bin/execwall
```

### Option 3: Build from Source

```bash
git clone https://github.com/sundarsub/execwall.git
cd execwall
cargo build --release
sudo cp target/release/execwall /usr/local/bin/
```

---

## Quick Start

**1. Create a policy file** (`/etc/execwall/policy.yaml`):
```yaml
rules:
  - pattern: "^(ls|cat|echo|pwd)$"
    action: allow
  - pattern: "^rm\\s+-rf"
    action: deny
  - pattern: ".*"
    action: audit
```

**2. Run a command through Execwall:**
```bash
execwall run -- ls -la
```

**3. Deploy with OpenClaw (AI agent):**
```bash
openclaw_launcher --openclaw-bin /usr/bin/openclaw -- gateway
```

---

## Deploy on Oracle Cloud (Free Tier)

Run your own secure WhatsApp AI assistant for **$0/month**:

```bash
# SSH to your Oracle Cloud VM
ssh opc@your-vm-ip

# One-line install
curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/scripts/install-oracle-cloud.sh | sudo bash
```

See full guide: [Oracle Cloud Deployment](https://github.com/sundarsub/execwall/blob/main/docs/ORACLE_CLOUD_DEPLOYMENT.md)

---

## Links

- **GitHub:** https://github.com/sundarsub/execwall
- **Releases:** https://github.com/sundarsub/execwall/releases
- **Issues:** https://github.com/sundarsub/execwall/issues

---

## Stats

| Metric | Count |
|--------|-------|
| Total Clones | 831 |
| Unique Cloners | 190 |
| Downloads | 60 |
| Stars | 3 |

---

*Execwall - Because AI agents need guardrails.*
