#!/bin/bash
# Execwall Easy Installer
# Universal Execution Governance Gateway
#
# This script installs:
#   - execwall binary (main REPL/API server)
#   - python_runner binary (sandbox executor)
#   - Default policy and sandbox profiles
#   - Optional systemd service for API mode

set -e

EXECWALL_VERSION="${EXECWALL_VERSION:-latest}"
GITHUB_REPO="sundarsub/execwall"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║              Execwall - Execution Governance               ║"
    echo "║         Universal Shell with Policy Enforcement          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

print_banner
echo "Installing Execwall..."
echo ""

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$OS" = "darwin" ]; then
    if [ "$ARCH" = "arm64" ]; then
        ASSET="execwall-macos-aarch64.tar.gz"
    else
        ASSET="execwall-macos-x86_64.tar.gz"
    fi
    PLATFORM_INFO="macOS"
elif [ "$OS" = "linux" ]; then
    if [ "$ARCH" = "aarch64" ]; then
        ASSET="execwall-linux-aarch64.tar.gz"
    else
        ASSET="execwall-linux-x86_64.tar.gz"
    fi
    PLATFORM_INFO="Linux (full sandbox support)"
else
    log_error "Unsupported OS: $OS"
    exit 1
fi

echo "Platform: $PLATFORM_INFO ($ARCH)"
echo "Downloading $ASSET..."
echo ""

# Download and extract binaries
cd /tmp
rm -rf /tmp/execwall-install-tmp
mkdir -p /tmp/execwall-install-tmp
cd /tmp/execwall-install-tmp

if [ "$EXECWALL_VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/$ASSET"
else
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${EXECWALL_VERSION}/$ASSET"
fi

curl -sL "$DOWNLOAD_URL" | tar xz

# Install main execwall binary
sudo mv /tmp/execwall-install-tmp/execwall /usr/local/bin/
log_info "Installed execwall to /usr/local/bin/execwall"

# Install python_runner binary (for sandbox execution)
if [ -f /tmp/execwall-install-tmp/python_runner ]; then
    sudo mkdir -p /usr/lib/execwall
    sudo mv /tmp/execwall-install-tmp/python_runner /usr/lib/execwall/
    sudo chmod 755 /usr/lib/execwall/python_runner
    log_info "Installed python_runner to /usr/lib/execwall/python_runner"
else
    log_warn "python_runner not found in release (sandbox features limited)"
fi

# Install openclaw_launcher binary (for seccomp-locked AI agent execution)
if [ -f /tmp/execwall-install-tmp/openclaw_launcher ]; then
    sudo mv /tmp/execwall-install-tmp/openclaw_launcher /usr/local/bin/
    sudo chmod 755 /usr/local/bin/openclaw_launcher
    log_info "Installed openclaw_launcher to /usr/local/bin/openclaw_launcher"
else
    log_warn "openclaw_launcher not found in release (AI agent lockdown not available)"
fi

rm -rf /tmp/execwall-install-tmp

# Create configuration directories
echo ""
echo "Setting up configuration directories..."
sudo mkdir -p /etc/execwall
sudo mkdir -p /etc/execwall/profiles
sudo mkdir -p /var/log/execwall

# Download default policy
sudo curl -sL "https://raw.githubusercontent.com/${GITHUB_REPO}/main/policy.yaml" \
    -o /etc/execwall/policy.yaml 2>/dev/null || {
    log_warn "Could not download default policy, creating minimal policy"
    sudo tee /etc/execwall/policy.yaml > /dev/null << 'POLICY_EOF'
# Execwall Default Policy
version: "2.0"
mode: enforce
default: deny

rate_limit:
  max_commands: 60
  window_seconds: 60

rules:
  - id: safe_read_commands
    match:
      executable: "^(ls|cat|head|tail|less|pwd|whoami|echo|date)$"
    effect: allow

  - id: block_sudo
    match:
      executable: "^sudo$"
    effect: deny
    reason: "Privilege escalation blocked"
POLICY_EOF
}
log_info "Installed default policy to /etc/execwall/policy.yaml"

# Download sandbox profiles
echo ""
echo "Downloading sandbox profiles..."

# Python sandbox profile v1
sudo curl -sL "https://raw.githubusercontent.com/${GITHUB_REPO}/main/profiles/python_sandbox_v1.yaml" \
    -o /etc/execwall/profiles/python_sandbox_v1.yaml 2>/dev/null || {
    sudo tee /etc/execwall/profiles/python_sandbox_v1.yaml > /dev/null << 'PROFILE_EOF'
# Python Sandbox Profile v1 - Secure by Default
runner: "/usr/lib/execwall/python_runner"
python_bin: "/usr/bin/python3"
deny_spawn_processes: true
default_network: deny

fs_defaults:
  cwd: "/work"
  read_allow:
    - "/work"
  write_allow:
    - "/work/tmp"
    - "/work/out"
  protected_deny:
    - "/"
    - "/etc"
    - "/proc"
    - "/sys"

limits_defaults:
  timeout_sec: 30
  cpu_max_percent: 50
  mem_max_mb: 512
  pids_max: 64
  max_stdout_bytes: 200000
  max_stderr_bytes: 200000

syscall_profile: restricted
PROFILE_EOF
}
log_info "Installed python_sandbox_v1.yaml profile"

# Python sandbox profile v2 (more permissive for data science)
sudo tee /etc/execwall/profiles/python_data_science_v1.yaml > /dev/null << 'DS_PROFILE_EOF'
# Python Data Science Profile - For numpy/pandas workloads
runner: "/usr/lib/execwall/python_runner"
python_bin: "/usr/bin/python3"
deny_spawn_processes: true
default_network: deny

fs_defaults:
  cwd: "/work"
  read_allow:
    - "/work"
    - "/usr/lib/python3"
    - "/usr/local/lib/python3"
  write_allow:
    - "/work/tmp"
    - "/work/out"
    - "/work/data"
  protected_deny:
    - "/etc"
    - "/proc"
    - "/sys"

limits_defaults:
  timeout_sec: 300
  cpu_max_percent: 100
  mem_max_mb: 4096
  pids_max: 128
  max_stdout_bytes: 1000000
  max_stderr_bytes: 500000

syscall_profile: data_science
DS_PROFILE_EOF
log_info "Installed python_data_science_v1.yaml profile"

# Set permissions
sudo chmod 644 /etc/execwall/policy.yaml
sudo chmod 644 /etc/execwall/profiles/*.yaml
sudo chmod 755 /var/log/execwall

# Linux-specific: Create execwall cgroup for resource limits
if [ "$OS" = "linux" ]; then
    echo ""
    echo "Setting up Linux-specific features..."

    # Create cgroup directory if cgroups v2 is available
    if [ -d "/sys/fs/cgroup" ] && [ -f "/sys/fs/cgroup/cgroup.controllers" ]; then
        sudo mkdir -p /sys/fs/cgroup/execwall 2>/dev/null || true
        if [ -d "/sys/fs/cgroup/execwall" ]; then
            # Enable controllers for execwall cgroup
            echo "+cpu +memory +pids" | sudo tee /sys/fs/cgroup/execwall/cgroup.subtree_control > /dev/null 2>&1 || true
            log_info "Created execwall cgroup for resource limits"
        fi
    else
        log_warn "Cgroups v2 not available, resource limits will be limited"
    fi
fi

# Optional: Install systemd service for API mode
if [ "$INSTALL_SYSTEMD" = "true" ] && [ "$OS" = "linux" ] && command -v systemctl &> /dev/null; then
    echo ""
    echo "Installing systemd service for API mode..."

    sudo tee /etc/systemd/system/execwall-api.service > /dev/null << 'SYSTEMD_EOF'
[Unit]
Description=Execwall Execution Governance API Server
Documentation=https://github.com/sundarsub/execwall
After=network.target

[Service]
Type=simple
User=execwall
Group=execwall
ExecStart=/usr/local/bin/execwall --api --port 9800 --policy /etc/execwall/policy.yaml --log /var/log/execwall/api_audit.jsonl
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/execwall
ReadOnlyPaths=/etc/execwall

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

    # Create execwall system user if it doesn't exist
    if ! id "execwall" &>/dev/null; then
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin execwall 2>/dev/null || true
    fi

    sudo chown -R execwall:execwall /var/log/execwall 2>/dev/null || true
    sudo systemctl daemon-reload
    log_info "Installed execwall-api.service"
    log_info "Enable with: sudo systemctl enable --now execwall-api"
fi

# Verification step
echo ""
echo "Verifying installation..."
VERIFY_PASSED=true

# Check execwall binary
if command -v execwall &> /dev/null; then
    EXECWALL_VERSION_OUT=$(execwall --version 2>&1 || echo "unknown")
    log_info "execwall binary: OK ($EXECWALL_VERSION_OUT)"
else
    log_error "execwall binary: NOT FOUND"
    VERIFY_PASSED=false
fi

# Check python_runner
if [ -x "/usr/lib/execwall/python_runner" ]; then
    log_info "python_runner: OK"
else
    log_warn "python_runner: NOT FOUND (sandbox features limited)"
fi

# Check openclaw_launcher
if command -v openclaw_launcher &> /dev/null; then
    log_info "openclaw_launcher: OK"
else
    log_warn "openclaw_launcher: NOT FOUND (AI agent lockdown not available)"
fi

# Check policy file
if [ -f "/etc/execwall/policy.yaml" ]; then
    log_info "policy.yaml: OK"
else
    log_error "policy.yaml: NOT FOUND"
    VERIFY_PASSED=false
fi

# Check profiles directory
PROFILE_COUNT=$(ls -1 /etc/execwall/profiles/*.yaml 2>/dev/null | wc -l)
if [ "$PROFILE_COUNT" -gt 0 ]; then
    log_info "sandbox profiles: OK ($PROFILE_COUNT profiles)"
else
    log_warn "sandbox profiles: NONE FOUND"
fi

# Check Python (needed for sandbox execution)
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    log_info "python3: OK ($PYTHON_VERSION)"
else
    log_warn "python3: NOT FOUND (required for Python sandbox)"
fi

echo ""
if [ "$VERIFY_PASSED" = "true" ]; then
    echo -e "${GREEN}Installation complete!${NC}"
else
    echo -e "${YELLOW}Installation completed with warnings.${NC}"
fi

echo ""
echo -e "${CYAN}Quick Start:${NC}"
echo ""
echo "  Interactive REPL mode:"
echo "    execwall"
echo ""
echo "  With custom policy:"
echo "    execwall --policy /path/to/policy.yaml"
echo ""
if [ "$OS" = "linux" ]; then
echo "  API mode (for OpenClaw VM integration):"
echo "    execwall --api --port 9800"
echo ""
fi
echo "  View help:"
echo "    execwall --help"
echo ""
echo -e "${CYAN}Configuration Files:${NC}"
echo "  Policy:   /etc/execwall/policy.yaml"
echo "  Profiles: /etc/execwall/profiles/"
echo "  Logs:     /var/log/execwall/"
echo ""
echo "Run 'execwall' to start!"
