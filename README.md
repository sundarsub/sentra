# Execwall - OpenClaw Execution Firewall

**Seccomp-locked AI agent sandbox with policy-enforced command governance, WhatsApp/Telegram integration, and Python isolation.**

Deploy a secure AI agent execution environment on **Oracle Cloud Free Tier** - run your own WhatsApp AI assistant with enterprise-grade security.

[![GitHub stars](https://img.shields.io/github/stars/sundarsub/execwall?style=social)](https://github.com/sundarsub/execwall/stargazers)
[![Deploy on Oracle Cloud](https://img.shields.io/badge/Deploy-Oracle%20Cloud%20Free%20Tier-F80000?style=for-the-badge&logo=oracle)](docs/ORACLE_CLOUD_DEPLOYMENT.md)

> **If Execwall helps you, consider giving it a star** - it helps others discover the project!

## What is Execwall?

Execwall is an **execution firewall** for AI agents. It sits between your AI (like OpenClaw) and the operating system, ensuring that only authorized commands run within defined security boundaries.

**Key capabilities:**
- **Seccomp syscall filtering** - Block dangerous operations at the kernel level
- **Policy-based command governance** - Regex rules for what commands can execute
- **Python sandbox isolation** - Namespace + cgroup + seccomp for untrusted code
- **WhatsApp/Telegram integration** - Secure messaging bot deployments
- **Audit logging** - Complete visibility into all execution attempts

## Quick Start: Oracle Cloud Free Tier

Deploy your own secure AI assistant for **$0/month** on Oracle Cloud Free Tier:

```bash
# SSH into your Oracle Cloud VM
ssh opc@your-vm-ip

# Install Execwall execution firewall
curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/scripts/install-oracle-cloud.sh | sudo bash

# Install OpenClaw
sudo npm install -g openclaw

# Configure your LLM (Gemini example)
openclaw config set llm.provider gemini
openclaw config set llm.apiKey "YOUR_GEMINI_API_KEY"

# Launch with execution firewall
openclaw_launcher --openclaw-bin /usr/bin/openclaw -- gateway
```

See the full [Oracle Cloud Deployment Guide](docs/ORACLE_CLOUD_DEPLOYMENT.md) for WhatsApp setup and more.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your AI Agent (OpenClaw)                      │
│  • WhatsApp/Telegram bot                                         │
│  • LLM-powered responses (Gemini, GPT, Claude)                   │
│  • Code execution capabilities                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Execwall Execution Firewall                       │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   Seccomp    │  │   Policy     │  │   Python Sandbox     │   │
│  │   Profiles   │  │   Engine     │  │   (namespaces)       │   │
│  └──────────────┘  └──────────────┘  └──────────────────────┘   │
│                                                                  │
│  Blocks: fork, exec, ptrace, mount, network (configurable)      │
│  Allows: read, write, mmap, socket (to approved endpoints)       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Linux Kernel   │
                    └─────────────────┘
```

## Features

## Features

### Policy-Based Command Filtering
- **Regex-based rule matching** on executable names and argument patterns
- **First-match-wins** rule evaluation for predictable behavior
- **Identity-scoped rules** for per-user/per-service policy enforcement
- **Audit mode** for testing policies without blocking commands
- **Per-identity rate limiting** to prevent abuse

### Python Sandbox with Kernel-Level Isolation (Linux)
- **Linux namespace isolation**: Mount, PID, and network namespaces
- **Seccomp-BPF syscall filtering**: Block dangerous syscalls at the kernel level
- **Cgroups v2 resource limits**: Memory, CPU, and process count restrictions
- **Filesystem isolation**: Read-only system paths, restricted write paths
- **Network blocking**: Complete network isolation by default

### Unified JSON API Mode (v2.0)
- **TCP server** for programmatic access (ideal for VM and agent integration)
- **Dual-mode API**: Both sandboxed Python execution AND policy-governed command execution
- **Identity-scoped commands**: Per-agent/per-user policy enforcement
- **Profile-based sandbox configuration** for different security levels
- **Async execution** with timeout and resource tracking

### Audit Logging with Code Hashing
- **JSON Lines format** for easy parsing and ingestion
- **SHA256 code hashing** for executed Python code
- **Session tracking** with unique identifiers
- **Execution metrics**: wall time, memory usage, exit codes
- **Sandbox lifecycle events**: enter, exit, violation tracking

## Installation

### Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/install.sh | bash
```

### Install with Systemd Service (Linux)

```bash
curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/install.sh | INSTALL_SYSTEMD=true bash
```

### Install Specific Version

```bash
curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/install.sh | EXECWALL_VERSION=2.0.0 bash
```

### Manual Installation

1. Download the appropriate binary from [Releases](https://github.com/sundarsub/execwall/releases)
2. Extract and install:
   ```bash
   tar xzf execwall-linux-x86_64.tar.gz
   sudo mv execwall /usr/local/bin/
   sudo mv python_runner /usr/lib/execwall/
   ```
3. Create configuration:
   ```bash
   sudo mkdir -p /etc/execwall/profiles
   sudo cp policy.yaml /etc/execwall/
   sudo cp profiles/*.yaml /etc/execwall/profiles/
   ```

### What Gets Installed

| Path | Description |
|------|-------------|
| `/usr/local/bin/execwall` | Main binary (REPL and API server) |
| `/usr/lib/execwall/python_runner` | Python sandbox executor |
| `/etc/execwall/policy.yaml` | Default execution policy |
| `/etc/execwall/profiles/` | Sandbox profile configurations |
| `/var/log/execwall/` | Audit log directory |

## Usage Examples

### Interactive REPL Mode

Start the interactive shell with policy enforcement:

```bash
# Use default policy
execwall

# Use custom policy
execwall --policy /path/to/policy.yaml

# Audit mode (log but don't block)
execwall --mode audit

# Verbose output
execwall -v
```

Example session:
```
+----------------------------------------------------------+
|              Execwall - Execution Governance               |
|         Universal Shell with Policy Enforcement          |
+----------------------------------------------------------+

[ok] Loaded policy from: /etc/execwall/policy.yaml
[ok] Policy: Policy v2.0 | Mode: Enforce | Default: Deny | Rules: 45
[ok] Rate limit: 60 commands per 60 seconds
[ok] Identity: developer

[execwall:enforce]$ ls -la
total 48
drwxr-xr-x  5 user user 4096 Feb 20 10:00 .
...

[execwall:enforce]$ sudo rm -rf /
[X] DENIED: sudo rm -rf /
  Rule:   block_sudo
  Reason: Privilege escalation via sudo is blocked

[execwall:enforce]$ status
Session Status:
  Session ID:        a1b2c3d4-5678-90ab-cdef-1234567890ab
  Identity:          developer
  Commands executed: 1
  Commands denied:   1
  Rate limit usage:  2/60 (per 60 sec)
```

### API Mode for OpenClaw VM Integration

Start the API server:

```bash
# Start API server on port 9800
execwall --api --port 9800

# With custom policy and logging
execwall --api --port 9800 --policy /etc/execwall/policy.yaml --log /var/log/execwall/api.jsonl
```

Send execution requests:

```bash
# Execute Python code
echo '{"code": "print(2 + 2)", "profile": "python_sandbox_v1"}' | nc localhost 9800
```

Response:
```json
{
  "exit_code": 0,
  "stdout": "4\n",
  "stderr": "",
  "wall_time_ms": 45,
  "peak_mem_mb": 12,
  "code_sha256": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
  "timed_out": false,
  "truncated_stdout": false,
  "truncated_stderr": false
}
```

**NEW in v2.0: Execute shell commands with policy enforcement:**

```bash
# Execute a command (policy-governed)
echo '{"command": "ls -la /tmp", "identity": "myagent"}' | nc localhost 9800
```

Command Response:
```json
{
  "exit_code": 0,
  "stdout": "total 8\ndrwxrwxrwt 2 root root 4096 ...",
  "stderr": "",
  "wall_time_ms": 12,
  "allowed_by_policy": true,
  "audit_mode": false,
  "matched_rule": "allow_ls",
  "reason": null
}
```

**Sandbox Request Format** (Python execution):
```json
{
  "code": "import math; print(math.pi)",
  "profile": "python_sandbox_v1",
  "cwd": "/work",
  "timeout_sec": 30,
  "mem_max_mb": 512,
  "pids_max": 64,
  "env": {
    "MY_VAR": "value"
  }
}
```

**Command Request Format** (v2.0 - shell command execution):
```json
{
  "command": "git status",
  "identity": "myagent",
  "cwd": "/home/agent/project",
  "env": {
    "GIT_AUTHOR_NAME": "Agent"
  }
}
```

The API automatically detects request type:
- Requests with `"code"` field → Sandbox execution
- Requests with `"command"` field → Policy-governed command execution

## OpenClaw VM Integration Guide

OpenClaw VM is an AI agent execution environment that uses Execwall as its secure code execution backend. This section explains how to build an OpenClaw VM that safely executes AI-generated Python code.

### Architecture Overview

```
+------------------------------------------------------------------+
|                        OpenClaw VM                                |
|  +------------------------------------------------------------+  |
|  |                     AI Agent (LLM)                         |  |
|  |  - Generates Python code based on user requests            |  |
|  |  - Interprets execution results                            |  |
|  |  - Maintains conversation context                          |  |
|  +---------------------------+--------------------------------+  |
|                              |                                   |
|                              v                                   |
|  +---------------------------+--------------------------------+  |
|  |                  Code Execution Manager                    |  |
|  |  - Validates code before execution                         |  |
|  |  - Manages Execwall connection pool                          |  |
|  |  - Handles timeouts and retries                            |  |
|  +---------------------------+--------------------------------+  |
|                              |                                   |
+------------------------------|-----------------------------------+
                               | TCP JSON API
                               v
+------------------------------------------------------------------+
|                          Execwall                                   |
|  - Policy enforcement          - Seccomp syscall filtering       |
|  - Namespace isolation         - Cgroup resource limits          |
|  - Audit logging               - Code hashing                    |
+------------------------------------------------------------------+
                               |
                               v
                      +----------------+
                      | python_runner  |
                      |  (sandboxed)   |
                      +----------------+
```

### Quick Start: Python OpenClaw VM Client

Here's a minimal OpenClaw VM implementation in Python:

```python
#!/usr/bin/env python3
"""
OpenClaw VM - Minimal Implementation
Executes AI-generated Python code via Execwall sandbox
"""

import socket
import json
from typing import Optional

class ExecwallClient:
    """Client for Execwall JSON API"""

    def __init__(self, host: str = "127.0.0.1", port: int = 9800):
        self.host = host
        self.port = port

    def execute(
        self,
        code: str,
        timeout_sec: int = 30,
        mem_max_mb: int = 512,
        cwd: str = "/tmp"
    ) -> dict:
        """Execute Python code in Execwall sandbox"""
        request = {
            "code": code,
            "profile": "python_sandbox",
            "cwd": cwd,
            "timeout_sec": timeout_sec,
            "mem_max_mb": mem_max_mb,
            "pids_max": 64
        }

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout_sec + 5)  # Network timeout
            sock.connect((self.host, self.port))
            sock.sendall(json.dumps(request).encode() + b'\n')

            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            return json.loads(response.decode())


class OpenClawVM:
    """
    OpenClaw VM - AI Agent Execution Environment

    This VM safely executes AI-generated Python code using Execwall
    as the sandboxed execution backend.
    """

    def __init__(self, execwall_host: str = "127.0.0.1", execwall_port: int = 9800):
        self.client = ExecwallClient(execwall_host, execwall_port)
        self.execution_history = []

    def run_code(self, code: str, timeout: int = 30) -> dict:
        """
        Execute Python code and return results

        Returns:
            {
                "success": bool,
                "output": str,
                "error": str,
                "execution_time_ms": int,
                "timed_out": bool
            }
        """
        result = self.client.execute(code, timeout_sec=timeout)

        # Track execution history
        self.execution_history.append({
            "code_hash": result.get("code_sha256", ""),
            "success": result.get("exit_code", -1) == 0,
            "timed_out": result.get("timed_out", False)
        })

        return {
            "success": result.get("exit_code", -1) == 0,
            "output": result.get("stdout", ""),
            "error": result.get("stderr", ""),
            "execution_time_ms": result.get("wall_time_ms", 0),
            "timed_out": result.get("timed_out", False)
        }

    def run_with_ai(self, user_request: str, ai_generate_code) -> str:
        """
        Complete AI agent loop:
        1. AI generates code from user request
        2. Code executes in Execwall sandbox
        3. AI interprets results

        Args:
            user_request: Natural language request
            ai_generate_code: Function that takes prompt and returns Python code
        """
        # Step 1: AI generates code
        code = ai_generate_code(user_request)

        # Step 2: Execute in sandbox
        result = self.run_code(code)

        # Step 3: Return formatted result
        if result["success"]:
            return f"Execution successful:\n{result['output']}"
        elif result["timed_out"]:
            return f"Execution timed out after {result['execution_time_ms']}ms"
        else:
            return f"Execution failed:\n{result['error']}"


# Example usage
if __name__ == "__main__":
    vm = OpenClawVM()

    # Direct code execution
    result = vm.run_code("""
import math
for i in range(1, 6):
    print(f"sqrt({i}) = {math.sqrt(i):.4f}")
""")

    print("Success:", result["success"])
    print("Output:", result["output"])
    print("Time:", result["execution_time_ms"], "ms")
```

### Production OpenClaw VM with Connection Pooling

For production use, implement connection pooling and async execution:

```python
#!/usr/bin/env python3
"""
OpenClaw VM - Production Implementation
Features: Connection pooling, async execution, retry logic
"""

import asyncio
import json
from dataclasses import dataclass
from typing import Optional, List
from contextlib import asynccontextmanager


@dataclass
class ExecutionResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    wall_time_ms: int
    peak_mem_mb: int
    code_sha256: str
    timed_out: bool
    truncated: bool


class AsyncExecwallClient:
    """Async client with connection pooling for Execwall API"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9800,
        pool_size: int = 10,
        max_retries: int = 3
    ):
        self.host = host
        self.port = port
        self.pool_size = pool_size
        self.max_retries = max_retries
        self._semaphore = asyncio.Semaphore(pool_size)

    async def execute(
        self,
        code: str,
        timeout_sec: int = 30,
        mem_max_mb: int = 512,
        cwd: str = "/tmp"
    ) -> ExecutionResult:
        """Execute code with automatic retry on connection failure"""

        request = json.dumps({
            "code": code,
            "profile": "python_sandbox",
            "cwd": cwd,
            "timeout_sec": timeout_sec,
            "mem_max_mb": mem_max_mb,
            "pids_max": 64
        }).encode() + b'\n'

        last_error = None
        for attempt in range(self.max_retries):
            try:
                async with self._semaphore:
                    return await self._execute_once(request, timeout_sec)
            except (ConnectionError, asyncio.TimeoutError) as e:
                last_error = e
                await asyncio.sleep(0.1 * (attempt + 1))  # Backoff

        raise ConnectionError(f"Failed after {self.max_retries} attempts: {last_error}")

    async def _execute_once(self, request: bytes, timeout: int) -> ExecutionResult:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=5.0
        )

        try:
            writer.write(request)
            await writer.drain()

            response = await asyncio.wait_for(
                reader.read(1024 * 1024),  # 1MB max response
                timeout=timeout + 5
            )

            data = json.loads(response.decode())

            if "error" in data:
                return ExecutionResult(
                    success=False,
                    stdout="",
                    stderr=data["error"],
                    exit_code=-1,
                    wall_time_ms=0,
                    peak_mem_mb=0,
                    code_sha256="",
                    timed_out=False,
                    truncated=False
                )

            return ExecutionResult(
                success=data.get("exit_code", -1) == 0,
                stdout=data.get("stdout", ""),
                stderr=data.get("stderr", ""),
                exit_code=data.get("exit_code", -1),
                wall_time_ms=data.get("wall_time_ms", 0),
                peak_mem_mb=data.get("peak_mem_mb", 0),
                code_sha256=data.get("code_sha256", ""),
                timed_out=data.get("timed_out", False),
                truncated=data.get("truncated_stdout", False) or data.get("truncated_stderr", False)
            )
        finally:
            writer.close()
            await writer.wait_closed()


class ProductionOpenClawVM:
    """Production-ready OpenClaw VM with async execution"""

    def __init__(self, execwall_host: str = "127.0.0.1", execwall_port: int = 9800):
        self.client = AsyncExecwallClient(execwall_host, execwall_port)

    async def execute(self, code: str, timeout: int = 30) -> ExecutionResult:
        """Execute Python code asynchronously"""
        return await self.client.execute(code, timeout_sec=timeout)

    async def execute_batch(self, codes: List[str], timeout: int = 30) -> List[ExecutionResult]:
        """Execute multiple code snippets concurrently"""
        tasks = [self.execute(code, timeout) for code in codes]
        return await asyncio.gather(*tasks, return_exceptions=True)


# Example async usage
async def main():
    vm = ProductionOpenClawVM()

    # Single execution
    result = await vm.execute("print('Hello from OpenClaw VM!')")
    print(f"Output: {result.stdout}")

    # Batch execution
    codes = [
        "print(1 + 1)",
        "print(2 * 2)",
        "print(3 ** 3)"
    ]
    results = await vm.execute_batch(codes)
    for i, r in enumerate(results):
        print(f"Code {i}: {r.stdout.strip()}")


if __name__ == "__main__":
    asyncio.run(main())
```

### Rust OpenClaw VM Client

For Rust-based OpenClaw VM implementations:

```rust
//! OpenClaw VM - Rust Client for Execwall
//!
//! Add to Cargo.toml:
//! ```toml
//! [dependencies]
//! tokio = { version = "1", features = ["full"] }
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! ```

use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Serialize)]
struct ExecutionRequest {
    code: String,
    profile: String,
    cwd: String,
    timeout_sec: u64,
    mem_max_mb: u64,
    pids_max: u32,
}

#[derive(Deserialize, Debug)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub wall_time_ms: u64,
    pub peak_mem_mb: u64,
    pub code_sha256: String,
    pub timed_out: bool,
    pub truncated_stdout: bool,
    pub truncated_stderr: bool,
}

pub struct OpenClawVM {
    host: String,
    port: u16,
}

impl OpenClawVM {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
        }
    }

    pub async fn execute(&self, code: &str, timeout_sec: u64) -> Result<ExecutionResult, Box<dyn Error>> {
        let request = ExecutionRequest {
            code: code.to_string(),
            profile: "python_sandbox".to_string(),
            cwd: "/tmp".to_string(),
            timeout_sec,
            mem_max_mb: 512,
            pids_max: 64,
        };

        let mut stream = TcpStream::connect(format!("{}:{}", self.host, self.port)).await?;

        let request_json = serde_json::to_string(&request)? + "\n";
        stream.write_all(request_json.as_bytes()).await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;

        let result: ExecutionResult = serde_json::from_slice(&response)?;
        Ok(result)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let vm = OpenClawVM::new("127.0.0.1", 9800);

    let result = vm.execute(r#"
import math
print(f"Pi = {math.pi:.10f}")
"#, 30).await?;

    println!("Success: {}", result.exit_code == 0);
    println!("Output: {}", result.stdout);
    println!("Time: {}ms", result.wall_time_ms);

    Ok(())
}
```

### Deployment Guide

#### 1. Install Execwall on the Execution Host

```bash
# Install Execwall
curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/install.sh | sudo bash

# Verify installation
execwall --version
```

#### 2. Configure the Sandbox Policy

```bash
# Edit policy for your use case
sudo vim /etc/execwall/policy.yaml
```

Key policy settings for OpenClaw VM:

```yaml
version: "2.0"
mode: enforce
default: deny

profiles:
  python_sandbox:
    runner: "/usr/lib/execwall/python_runner"
    python_bin: "/usr/bin/python3"
    deny_spawn_processes: true
    default_network: deny

    fs_defaults:
      cwd: "/tmp"
      read_allow:
        - "/tmp"
        - "/usr/lib/python3"
        - "/usr/local/lib/python3"
      write_allow:
        - "/tmp"
      protected_deny:
        - "/"
        - "/etc"
        - "/home"
        - "/root"

    limits_defaults:
      timeout_sec: 30
      cpu_max_percent: 50
      mem_max_mb: 512
      pids_max: 64
      max_stdout_bytes: 200000
      max_stderr_bytes: 200000

    syscall_profile: restricted
```

#### 3. Start Execwall API Server

**Option A: Direct execution**
```bash
execwall --api --port 9800 --policy /etc/execwall/policy.yaml
```

**Option B: Systemd service (Linux)**
```bash
# Enable and start
sudo systemctl enable --now execwall-api

# Check status
sudo systemctl status execwall-api
```

**Option C: Docker deployment**
```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y python3 curl

# Install Execwall
RUN curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/install.sh | bash

# Expose API port
EXPOSE 9800

# Run Execwall API
CMD ["execwall", "--api", "--port", "9800", "--policy", "/etc/execwall/policy.yaml"]
```

#### 4. Connect OpenClaw VM to Execwall

```python
# In your OpenClaw VM application
vm = OpenClawVM(
    execwall_host="execwall-server.internal",  # Or "127.0.0.1" for local
    execwall_port=9800
)

# Execute AI-generated code safely
result = vm.run_code(ai_generated_python_code)
```

### Security Best Practices

1. **Network Isolation**: Run Execwall on a private network, not exposed to the internet
2. **Resource Limits**: Set appropriate timeouts and memory limits for your use case
3. **Audit Logging**: Enable and monitor audit logs for security events
4. **Policy Review**: Regularly review and update the execution policy
5. **Principle of Least Privilege**: Only allow necessary filesystem paths and syscalls

### Monitoring and Observability

Monitor Execwall execution via audit logs:

```bash
# Stream audit logs
tail -f /var/log/execwall/audit.jsonl | jq .

# Filter for timeouts
grep '"timed_out":true' /var/log/execwall/audit.jsonl

# Filter for failed executions
grep -v '"exit_code":0' /var/log/execwall/audit.jsonl
```

### Using with systemd (Linux)

```bash
# Enable and start the API service
sudo systemctl enable --now execwall-api

# Check status
sudo systemctl status execwall-api

# View logs
journalctl -u execwall-api -f
```

### Policy Configuration

Create a custom policy:

```yaml
# my-policy.yaml
version: "2.0"
mode: enforce
default: deny

rate_limit:
  max_commands: 100
  window_seconds: 60

rules:
  # Allow read-only git commands
  - id: git_read_only
    match:
      executable: "^git$"
      args_pattern: "^(status|log|diff|show|branch)"
    effect: allow

  # Block git push
  - id: git_block_push
    match:
      executable: "^git$"
      args_pattern: "^push"
    effect: deny
    reason: "Git push requires approval"

  # Allow npm for specific users
  - id: npm_for_developers
    match:
      executable: "^npm$"
      identity: "^developer-.*"
    effect: allow

  # Block access to .env files
  - id: block_env_files
    match:
      args_pattern: "\\.env"
    effect: deny
    reason: "Access to .env files is blocked"
```

## Sandbox Features

### Linux Namespace Isolation

Execwall uses Linux namespaces to isolate Python execution:

| Namespace | Purpose |
|-----------|---------|
| **Mount** | Isolate filesystem view, restrict accessible paths |
| **PID** | Isolate process tree, hide host processes |
| **Network** | Block all network access by default |

### Seccomp-BPF Syscall Filtering

The `restricted` syscall profile blocks dangerous syscalls:

```yaml
# Blocked syscall categories:
# - Process spawning: execve, execveat
# - Network: socket, connect, bind, listen, accept
# - Destructive FS: unlink, rmdir, rename
# - Permissions: chmod, chown
# - Privilege escalation: setuid, setgid, capset
# - Kernel: ptrace, mount, bpf, init_module
```

### Cgroups Resource Limits

Resource limits are enforced via cgroups v2:

| Limit | Default | Description |
|-------|---------|-------------|
| `mem_max_mb` | 512 | Maximum memory in MB |
| `cpu_max_percent` | 50 | CPU quota percentage |
| `pids_max` | 64 | Maximum process count |
| `timeout_sec` | 30 | Wall clock timeout |
| `max_stdout_bytes` | 200000 | Output truncation limit |

### Filesystem Isolation

Sandbox profiles define filesystem access:

```yaml
fs_defaults:
  cwd: "/work"
  read_allow:
    - "/work"
    - "/usr/lib/python3"
  write_allow:
    - "/work/tmp"
    - "/work/out"
  protected_deny:
    - "/"
    - "/etc"
    - "/proc"
    - "/sys"
```

## Policy v2.0 YAML Schema

### Root Level

```yaml
version: "2.0"           # Schema version
mode: enforce|audit      # enforce blocks, audit only logs
default: deny|allow      # Default when no rule matches

rate_limit:
  max_commands: 60       # Max commands per identity per window
  window_seconds: 60     # Sliding window duration

rules: []                # List of policy rules
profiles: {}             # Named sandbox profiles
capabilities: {}         # Named capability definitions
syscall_profiles: {}     # Named syscall filter profiles
```

### Rule Schema

```yaml
rules:
  - id: "unique_rule_id"           # Required: unique identifier
    match:
      executable: "^pattern$"       # Regex for executable name
      args_pattern: "pattern"       # Regex for argument string
      identity: "^user-.*"          # Regex for identity/username
    effect: allow|deny              # Required: rule action
    reason: "Human-readable reason" # Optional: shown on deny
```

### Sandbox Profile Schema

```yaml
profiles:
  python_sandbox_v1:
    runner: "/usr/lib/execwall/python_runner"
    python_bin: "/usr/bin/python3"
    deny_spawn_processes: true
    default_network: deny

    fs_defaults:
      cwd: "/work"
      read_allow: ["/work", "/usr/lib/python3"]
      write_allow: ["/work/tmp", "/work/out"]
      protected_deny: ["/", "/etc", "/proc", "/sys"]

    limits_defaults:
      timeout_sec: 30
      cpu_max_percent: 50
      mem_max_mb: 512
      pids_max: 64
      max_stdout_bytes: 200000
      max_stderr_bytes: 200000

    syscall_profile: restricted
```

### Capability Schema

```yaml
capabilities:
  exec_python:
    type: python
    profile: python_sandbox_v1
    allowed_python_argv: ["-u", "-B"]
```

### Syscall Profile Schema

```yaml
syscall_profiles:
  restricted:
    default: allow
    deny:
      - execve
      - socket
      - connect
      - unlink
      - chmod
      - ptrace
    allow: []
```

## Building from Source

### Prerequisites

- Rust 1.75+ (with cargo)
- Linux: libseccomp-dev (for seccomp support)

### Build Steps

```bash
# Clone repository
git clone https://github.com/sundarsub/execwall.git
cd execwall

# Build release binaries
cargo build --release

# Binaries are in target/release/
ls -la target/release/execwall target/release/python_runner
```

### Linux-specific Dependencies

```bash
# Ubuntu/Debian
sudo apt-get install libseccomp-dev

# Fedora/RHEL
sudo dnf install libseccomp-devel

# Arch
sudo pacman -S libseccomp
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test module
cargo test policy::tests
```

### Development Build

```bash
# Debug build with faster compilation
cargo build

# Run directly
cargo run -- --policy policy.yaml

# Run API mode
cargo run -- --api --port 9800
```

## Architecture

```
+-------------------------------------------------------------+
|                    OpenClaw VM / Client                     |
+-----------------------------+-------------------------------+
                              | JSON API (TCP :9800)
                              v
+-------------------------------------------------------------+
|                         Execwall                              |
|  +-------------+  +--------------+  +------------------+    |
|  | API Server  |  |Policy Engine |  |  Audit Logger    |    |
|  |  (Tokio)    |  |  (Regex)     |  |  (JSON Lines)    |    |
|  +------+------+  +------+-------+  +--------+---------+    |
|         |                |                   |              |
|         v                v                   v              |
|  +-----------------------------------------------------+    |
|  |               Sandbox Executor                      |    |
|  |  +-----------+ +----------+ +---------------------+ |    |
|  |  | Namespace | | Seccomp  | | Cgroup Controller   | |    |
|  |  | Isolation | | BPF      | | (mem/cpu/pids)      | |    |
|  |  +-----------+ +----------+ +---------------------+ |    |
|  +------------------------+----------------------------+    |
+--------------------------+----------------------------------+
                           |
                           v
                   +---------------+
                   |python_runner  |
                   |  (isolated)   |
                   +---------------+
```

## Audit Log Format

Audit logs are JSON Lines format, one entry per line:

```json
{"timestamp":"2026-02-21T10:30:00Z","session_id":"abc-123","host":"server1","user":"developer","action":"exec","command":"git status","executable":"git","args":"status","cwd":"/home/dev/project","decision":"allowed","rule_id":"git_read_only","eval_duration_ms":0,"exec_duration_ms":45,"exit_code":0}
```

### Sandbox Execution Log Entry

```json
{
  "timestamp": "2026-02-21T10:30:00Z",
  "session_id": "abc-123",
  "host": "server1",
  "user": "api-client",
  "action": "sandbox_exec",
  "command": "print('hello')",
  "executable": "python3",
  "cwd": "/work",
  "decision": "allowed",
  "code_sha256": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
  "profile": "python_sandbox_v1",
  "sandbox_metrics": {
    "wall_time_ms": 45,
    "peak_mem_mb": 12,
    "timed_out": false
  },
  "exit_code": 0
}
```

### Event Types

| Event | Description |
|-------|-------------|
| `session_start` | Session began with policy info |
| `exec` | Command evaluation and execution |
| `sandbox_exec` | Sandboxed Python execution |
| `sandbox_enter` | Sandbox environment setup |
| `sandbox_exit` | Sandbox execution completed |
| `sandbox_violation` | Security policy violation |
| `session_end` | Session ended with statistics |

## Security Considerations

1. **Run as non-root**: Execwall should run as an unprivileged user in production
2. **Policy review**: Audit your policy.yaml before deployment
3. **Log monitoring**: Monitor audit logs for security events
4. **Network isolation**: The sandbox blocks all network by default
5. **Cgroup limits**: Set appropriate resource limits to prevent DoS

### Deployment as Forced Shell

When deployed as a ForceCommand or login shell:

1. Users cannot bypass the governance gateway
2. All commands are evaluated against policy
3. Rate limiting prevents automated attacks
4. Audit trail provides forensic visibility

```bash
# SSH forced command configuration
# /etc/ssh/sshd_config
Match User developer
    ForceCommand /usr/local/bin/execwall --policy /etc/execwall/policy.yaml
```

### Rate Limiting for Breach Containment

Rate limiting disrupts attack patterns:
- Automated reconnaissance is throttled
- Brute-force attempts are slowed
- Data exfiltration is rate-constrained

## OpenClaw Launcher - Seccomp-Locked AI Agent Execution

The `openclaw_launcher` binary provides a **seccomp-locked execution environment** for AI agents. This implements the defense-in-depth principle: even if the AI agent is compromised, it **cannot directly execute code** - all execution must go through Execwall's API.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  openclaw_launcher                                               │
│  1. Start Execwall API server                                     │
│  2. Apply seccomp filter (blocks execve, fork, etc.)            │
│  3. Exec OpenClaw (this is the LAST exec before lockdown)       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  OpenClaw (AI Agent) - SECCOMP LOCKED                           │
│  ✗ Cannot execve() - BLOCKED by seccomp                         │
│  ✗ Cannot fork() - BLOCKED by seccomp                           │
│  ✗ Cannot run subprocess.run() - BLOCKED                        │
│  ✓ CAN connect to Execwall API - ALLOWED                          │
│  ✓ CAN do regular Python computation - ALLOWED                  │
│                                                                 │
│  To execute code, must call Execwall API:                         │
│  → {"code": "...", "profile": "python_sandbox"}                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ TCP 127.0.0.1:9999
┌─────────────────────────────────────────────────────────────────┐
│  Execwall API Server                                               │
│  → Receives execution request                                   │
│  → Spawns python_runner in ANOTHER sandbox                      │
│  → Returns result to OpenClaw                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Usage

```bash
# Basic usage - launch OpenClaw in locked environment
openclaw_launcher --openclaw-bin /path/to/openclaw

# Custom Execwall port
openclaw_launcher --port 9800 --openclaw-bin /path/to/openclaw

# Verbose output to see security status
openclaw_launcher -v --openclaw-bin /path/to/openclaw

# Skip Execwall start (if already running)
openclaw_launcher --skip-execwall --openclaw-bin /path/to/openclaw
```

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--openclaw-bin` | `/usr/local/bin/openclaw` | Path to AI agent binary |
| `--execwall-bin` | `/usr/local/bin/execwall` | Path to Execwall binary |
| `--port` | `9999` | Execwall API port |
| `--python-runner` | `/usr/lib/execwall/python_runner` | Path to sandbox executor |
| `--skip-execwall` | `false` | Skip starting Execwall |
| `-v, --verbose` | `false` | Show detailed security info |

### What Gets Blocked (Linux with seccomp)

When running on Linux with seccomp enabled, the AI agent cannot:

| Operation | Blocked By | What Happens |
|-----------|------------|--------------|
| `subprocess.run()` | seccomp (execve) | `OSError: Operation not permitted` |
| `os.system()` | seccomp (execve) | Returns -1 |
| `os.fork()` | seccomp (fork) | `OSError: Operation not permitted` |
| `ctypes.CDLL().execve()` | seccomp | `OSError: Operation not permitted` |
| `socket.connect("evil.com")` | Network isolation | Connection refused |
| `open("/etc/passwd")` | Filesystem isolation | `FileNotFoundError` |

### What Remains Allowed

| Operation | Why Allowed |
|-----------|-------------|
| Connect to Execwall API | Required for code execution |
| Regular Python computation | math, json, etc. work normally |
| File operations in `/work` | Designated working directory |
| Threading | Required for async operations |

### Full Network Isolation (Optional)

For complete network isolation where OpenClaw can ONLY reach Execwall:

```bash
# Use the included isolation script (requires sudo/root)
sudo ./scripts/launch_openclaw_isolated.sh /path/to/openclaw

# Or manually with network namespaces:
# 1. Create namespace with veth pair to only reach Execwall
# 2. Run openclaw_launcher inside the namespace
```

### Security Verification

Test that the lockdown is working:

```bash
# Run the mock OpenClaw test suite
./target/release/openclaw_launcher \
    --openclaw-bin /usr/bin/python3 \
    -- tests/mock_openclaw.py
```

Expected output on Linux:
```
✓ PASS: subprocess.run() blocked
✓ PASS: os.system() blocked
✓ PASS: os.fork() blocked
✓ PASS: External network blocked
✓ PASS: Execwall API reachable
✓ PASS: File operations work
✓ PASS: Python computation works
```

### Defense-in-Depth Stack

1. **OpenClaw Seccomp**: Blocks execve, fork, arbitrary network
2. **Network Namespace**: OpenClaw can ONLY reach Execwall API
3. **Execwall Policy**: Controls what code can be executed
4. **python_runner Sandbox**: Another layer of namespace + seccomp + cgroups

Even if the AI agent is fully compromised:
- It cannot execute code directly (seccomp blocks execve)
- It cannot phone home (network restricted to Execwall)
- All code execution goes through Execwall's policy engine
- Code runs in a separate, isolated sandbox

## Execwall OR Gate - Budget-Based LLM Routing

Execwall OR Gate is a Python proxy that routes LLM requests to OpenRouter with automatic model selection based on budget. As budget depletes, it automatically degrades from premium to cheaper models.

### Architecture

```
┌──────────┐     ┌──────────────┐     ┌────────────┐
│ OpenClaw │────▶│ Execwall OR    │────▶│ OpenRouter │
│ (Agent)  │     │ Gate :8080   │     │            │
└──────────┘     └──────────────┘     └────────────┘
                        │
                 ┌──────┴──────┐
                 │ policy.yaml │
                 │ (cost_routing)│
                 └─────────────┘
```

### Tier-Based Model Selection

| Budget Remaining | Models Used |
|------------------|-------------|
| > 80% | claude-3.5-sonnet, gpt-4o (Premium) |
| 30-80% | claude-3-haiku, gpt-4o-mini (Mid-tier) |
| < 30% | mistral-7b-instruct (Economy) |
| 0% (hard_cap=true) | 402 error - budget exhausted |

### Quick Start

```bash
# Install dependencies
pip install -r execwall-or-gate/requirements.txt

# Set OpenRouter API key
export OPENROUTER_API_KEY="sk-or-v1-..."

# Run the gate
python -m execwall-or-gate.main

# Test
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'
```

### Configuration

Add the `cost_routing` section to `policy.yaml`:

```yaml
cost_routing:
  openrouter:
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
    timeout_seconds: 120

  spend_log: "./spend.jsonl"

  agents:
    agent-1:
      budget_total: 50.00
      budget_spent: 0.00
      hard_cap: true
      tiers:
        - threshold: 0.80
          models: ["anthropic/claude-3.5-sonnet", "openai/gpt-4o"]
        - threshold: 0.30
          models: ["anthropic/claude-3-haiku", "openai/gpt-4o-mini"]
        - threshold: 0.00
          models: ["mistralai/mistral-7b-instruct"]
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | OpenAI-compatible chat proxy |
| `/api/health` | GET | Health check |
| `/api/spend/{agent_id}` | GET | Get spend for agent |
| `/api/budget/{agent_id}` | POST | Update budget (JetPatch console) |
| `/api/reset/{agent_id}` | POST | Reset spend for agent |

### Integration with Seccomp-Locked OpenClaw

When running with `openclaw_launcher`, OpenClaw can reach both Execwall (for code execution) and OR Gate (for LLM requests) on loopback:

```
┌─────────────────────────────────────────────────────────────┐
│                    LOOPBACK (127.0.0.1)                     │
│                                                             │
│  ┌──────────┐                                               │
│  │ OpenClaw │──┬──▶ Execwall      :9999  (code execution)     │
│  │ (locked) │  │                                            │
│  └──────────┘  └──▶ OR Gate     :8080  (LLM requests)       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

OpenClaw points its LLM client at `http://127.0.0.1:8080/v1/chat/completions` instead of OpenRouter directly.

### Testing with Mock Server

For testing without real API calls:

```bash
# Terminal 1: Start mock OpenRouter
python -m execwall-or-gate.mock_openrouter

# Terminal 2: Update policy.yaml base_url to http://localhost:9000/v1
OPENROUTER_API_KEY="test" python -m execwall-or-gate.main

# Terminal 3: Send test requests
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'
```

See [execwall-or-gate/README.md](execwall-or-gate/README.md) for full documentation.

---

## AgentExW - Enterprise Autonomous AI Agent Platform

Execwall powers **AgentExW**, an autonomous AI agent platform designed for enterprise deployments. AgentExW demonstrates the full capabilities of Execwall's unified API for building secure, production-grade AI agents.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        AgentExW Agent                            │
│  • WhatsApp, Email, Calendar integrations                        │
│  • Polling-driven trigger processing                             │
│  • Tool execution via execwall-shell                             │
│  • Multi-channel response handling                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ Unified JSON API
┌─────────────────────────────────────────────────────────────────┐
│                      Execwall Shell API                          │
│  • Sandbox requests: {"code": "...", "profile": "..."}          │
│  • Command requests: {"command": "...", "identity": "..."}      │
│  • Policy evaluation with identity context                       │
│  • Audit logging with full traceability                          │
└─────────────────────────────────────────────────────────────────┘
```

### Key Features

- **Multi-channel triggers**: WhatsApp messages, emails, calendar events
- **Unified API execution**: Both Python sandbox and shell commands through execwall
- **Identity-scoped policies**: Per-agent command governance
- **Deterministic parsing**: Structured directives (TASK:/REMINDER:) processed before LLM
- **Audit trail**: Complete visibility into all agent actions

### Enterprise Offering

AgentExW is currently a **work in progress** for enterprise deployments. The agent code is not included in this public release.

**Interested in AgentExW for your organization?**

Contact: **sentra@lma.llc**

---

## Support the Project

If Execwall has been useful for your AI agent security needs:

- **Star this repo** - helps others discover Execwall
- **Share** - tell others about secure AI agent execution
- **Contribute** - PRs and issues welcome

[![Star History](https://img.shields.io/github/stars/sundarsub/execwall?style=social)](https://github.com/sundarsub/execwall/stargazers)

## License

Apache-2.0

## Author

Sundar Subramaniam

## Support

- Issues: [GitHub Issues](https://github.com/sundarsub/execwall/issues)
- Email: execwall@gmail.com
