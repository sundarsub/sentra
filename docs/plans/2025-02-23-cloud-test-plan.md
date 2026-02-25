# Cloud Test Plan: Execwall + OR Gate + OpenClaw

## Goal

Test the full stack on a free-tier cloud instance:
- Execwall (code execution sandbox)
- Execwall OR Gate (LLM routing with mock)
- OpenClaw (AI agent)

No OpenRouter - use mock server for LLM responses.

---

## Cloud Provider Comparison

| Feature | AWS Free Tier | Oracle Cloud Free Tier |
|---------|---------------|------------------------|
| **Instance** | t2.micro (1 vCPU, 1GB RAM) | VM.Standard.E2.1.Micro (1 vCPU, 1GB RAM) |
| **Duration** | 12 months | **Forever** |
| **Storage** | 30GB EBS | 200GB block storage |
| **Bandwidth** | 15GB/month | 10TB/month |
| **OS** | Amazon Linux, Ubuntu | Oracle Linux, Ubuntu |
| **ARM option** | t4g.micro (750 hrs/mo) | **Ampere A1 (4 vCPU, 24GB RAM)** |

**Recommendation: Oracle Cloud**
- Free forever (not 12 months)
- Ampere A1 gives 4 vCPU + 24GB RAM free
- Better specs for running multiple services

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Oracle Cloud VM (Ampere A1)                 │
│                 Ubuntu 22.04 ARM64                          │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                  systemd services                     │  │
│  │                                                       │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐  │  │
│  │  │   Execwall    │  │  OR Gate    │  │ Mock Router  │  │  │
│  │  │   :9999     │  │   :8080     │  │    :9000     │  │  │
│  │  │   (API)     │  │  (Python)   │  │   (Python)   │  │  │
│  │  └─────────────┘  └─────────────┘  └──────────────┘  │  │
│  │         ▲                ▲                ▲          │  │
│  │         │                │                │          │  │
│  │         └────────────────┼────────────────┘          │  │
│  │                          │                           │  │
│  │                   ┌──────┴──────┐                    │  │
│  │                   │  OpenClaw   │                    │  │
│  │                   │  (Agent)    │                    │  │
│  │                   └─────────────┘                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Setup Steps

### Phase 1: Create Oracle Cloud Account (10 min)

1. Go to https://www.oracle.com/cloud/free/
2. Sign up (requires credit card for verification, won't be charged)
3. Select home region (choose closest to you)
4. Wait for account provisioning (~5 min)

### Phase 2: Create VM Instance (10 min)

1. Go to **Compute > Instances > Create Instance**
2. Configure:
   - **Name:** `execwall-test`
   - **Image:** Ubuntu 22.04 (aarch64)
   - **Shape:** VM.Standard.A1.Flex
     - 2 OCPUs (can use up to 4 free)
     - 12GB RAM (can use up to 24GB free)
   - **Networking:** Create new VCN with public subnet
   - **SSH Key:** Upload your public key or generate new
3. Click **Create**
4. Note the public IP address

### Phase 3: Configure Firewall (5 min)

In Oracle Cloud Console:

1. Go to **Networking > Virtual Cloud Networks**
2. Click your VCN > **Security Lists** > **Default Security List**
3. Add **Ingress Rules**:

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 22 | TCP | 0.0.0.0/0 | SSH |
| 9999 | TCP | 0.0.0.0/0 | Execwall API (optional, for external test) |
| 8080 | TCP | 0.0.0.0/0 | OR Gate (optional) |

Also run on the VM:
```bash
sudo iptables -I INPUT -p tcp --dport 9999 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 9000 -j ACCEPT
sudo netfilter-persistent save
```

### Phase 4: Install Dependencies (10 min)

```bash
# SSH into instance
ssh ubuntu@<PUBLIC_IP>

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3.11+
sudo apt install -y python3 python3-pip python3-venv

# Install Rust (for building Execwall)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install build tools
sudo apt install -y build-essential pkg-config libseccomp-dev

# Verify
python3 --version   # 3.10+
rustc --version     # 1.70+
```

### Phase 5: Install Execwall (10 min)

```bash
# Clone repo
git clone https://github.com/sundarsub/execwall.git
cd execwall

# Build Execwall (ARM64)
cargo build --release

# Install binaries
sudo mkdir -p /usr/lib/execwall
sudo cp target/release/execwall /usr/local/bin/
sudo cp target/release/python_runner /usr/lib/execwall/
sudo cp target/release/openclaw_launcher /usr/local/bin/

# Install config
sudo mkdir -p /etc/execwall
sudo cp policy.yaml /etc/execwall/

# Verify
execwall --version
```

### Phase 6: Install OR Gate (5 min)

```bash
cd ~/execwall

# Create venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r execwall-or-gate/requirements.txt

# Update policy.yaml to use mock
sudo sed -i 's|https://openrouter.ai/api/v1|http://localhost:9000/v1|' /etc/execwall/policy.yaml
```

### Phase 7: Create systemd Services (10 min)

**Execwall API service:**
```bash
sudo tee /etc/systemd/system/execwall-api.service << 'EOF'
[Unit]
Description=Execwall API Server
After=network.target

[Service]
Type=simple
User=ubuntu
ExecStart=/usr/local/bin/execwall --api --port 9999 --policy /etc/execwall/policy.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

**Mock OpenRouter service:**
```bash
sudo tee /etc/systemd/system/mock-openrouter.service << 'EOF'
[Unit]
Description=Mock OpenRouter Server
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/execwall
ExecStart=/home/ubuntu/execwall/venv/bin/python -m execwall-or-gate.mock_openrouter
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF
```

**OR Gate service:**
```bash
sudo tee /etc/systemd/system/execwall-or-gate.service << 'EOF'
[Unit]
Description=Execwall OR Gate
After=network.target mock-openrouter.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/execwall
ExecStart=/home/ubuntu/execwall/venv/bin/python -m execwall-or-gate.main
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=OPENROUTER_API_KEY=mock-key
Environment=CONFIG_PATH=/etc/execwall/policy.yaml

[Install]
WantedBy=multi-user.target
EOF
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now execwall-api
sudo systemctl enable --now mock-openrouter
sudo systemctl enable --now execwall-or-gate

# Check status
sudo systemctl status execwall-api
sudo systemctl status mock-openrouter
sudo systemctl status execwall-or-gate
```

### Phase 8: Install OpenClaw (15 min)

OpenClaw is your AI agent. If you have a binary:

```bash
# Copy your OpenClaw binary
scp openclaw ubuntu@<PUBLIC_IP>:~/

# Or if it's a Python agent:
# Clone/copy your OpenClaw code
```

Configure OpenClaw to use:
- **LLM endpoint:** `http://127.0.0.1:8080/v1/chat/completions`
- **Code execution:** `http://127.0.0.1:9999` (Execwall API)

### Phase 9: Test the Stack (10 min)

```bash
# Test Execwall API
echo '{"code": "print(1+1)", "profile": "python_sandbox"}' | nc localhost 9999

# Test OR Gate health
curl http://localhost:8080/api/health

# Test chat completion (via mock)
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'

# Check spend tracking
curl http://localhost:8080/api/spend/agent-1

# Check mock logs
cat ~/execwall/openrouter_requests.log
```

### Phase 10: Run OpenClaw (5 min)

**Option A: With seccomp lockdown (Linux only)**
```bash
openclaw_launcher --openclaw-bin /path/to/openclaw --port 9999
```

**Option B: Direct (for testing)**
```bash
# Set environment for OpenClaw
export LLM_BASE_URL="http://127.0.0.1:8080/v1"
export LLM_API_KEY="mock-key"
export EXECWALL_URL="http://127.0.0.1:9999"

# Run OpenClaw
./openclaw
```

---

## Test Scenarios

### Test 1: Basic LLM Request
```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "What is 2+2?"}]}'
```
**Expected:** Mock response with `_execwall` metadata showing budget info.

### Test 2: Code Execution via Execwall
```bash
echo '{"code": "import math; print(math.pi)", "profile": "python_sandbox"}' | nc localhost 9999
```
**Expected:** `{"exit_code": 0, "stdout": "3.14159...", ...}`

### Test 3: Budget Degradation
```bash
# Simulate spending 80% of budget
curl -X POST http://localhost:8080/api/budget/agent-1 \
  -H "Content-Type: application/json" \
  -d '{"budget_spent": 40.00}'

# Next request should use mid-tier models
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'
```
**Expected:** Response shows `models_allowed: ["claude-3-haiku", "gpt-4o-mini"]`

### Test 4: Budget Exhaustion
```bash
# Exhaust budget
curl -X POST http://localhost:8080/api/budget/agent-1 \
  -H "Content-Type: application/json" \
  -d '{"budget_spent": 50.00}'

# Request should fail
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'
```
**Expected:** 402 error with `budget_exhausted`

### Test 5: OpenClaw End-to-End
Run OpenClaw and give it a task that requires:
1. LLM reasoning (via OR Gate → Mock)
2. Code execution (via Execwall)

Example prompt: "Calculate the factorial of 10 using Python"

---

## Monitoring

```bash
# Watch all services
sudo journalctl -f -u execwall-api -u mock-openrouter -u execwall-or-gate

# Check spend log
tail -f ~/execwall/spend.jsonl

# Check mock requests
tail -f ~/execwall/openrouter_requests.log
```

---

## Cost

**Oracle Cloud Always Free:**
- VM: $0
- Storage: $0
- Bandwidth: $0 (up to 10TB)

**Total: $0/month**

---

## Cleanup

```bash
# Stop services
sudo systemctl stop execwall-api mock-openrouter execwall-or-gate

# Or terminate instance in Oracle Cloud Console
```

---

## Timeline

| Phase | Time |
|-------|------|
| Create Oracle account | 10 min |
| Create VM | 10 min |
| Configure firewall | 5 min |
| Install dependencies | 10 min |
| Install Execwall | 10 min |
| Install OR Gate | 5 min |
| Create services | 10 min |
| Install OpenClaw | 15 min |
| Test | 10 min |
| **Total** | **~85 min** |
