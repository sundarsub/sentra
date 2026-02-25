#!/bin/bash
# =============================================================================
# Execwall + OpenClaw Install Script for Oracle Cloud
# =============================================================================
#
# Installs a complete AI agent environment:
#   - Execwall execution firewall (with --quiet mode)
#   - OpenClaw AI agent gateway
#   - Himalaya email client
#   - WhatsApp integration
#   - OpenRouter LLM support
#
# This is the STANDARD version - runs OpenClaw with Execwall REPL for command
# governance. No seccomp launcher required.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/sundarsub/execwall/main/scripts/install-oracle-cloud.sh | sudo bash
#
# Options (via environment variables):
#   OPENROUTER_API_KEY  - Pre-configure OpenRouter API key
#   GMAIL_ADDRESS       - Email address for himalaya
#   GMAIL_APP_PASSWORD  - Gmail app password for himalaya
#   BUILD_FROM_SOURCE   - Set to 1 to build Execwall from source
#   SKIP_OPENCLAW       - Set to 1 to skip OpenClaw installation
#   SKIP_HIMALAYA       - Set to 1 to skip Himalaya installation
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }

# Configuration
GITHUB_REPO="sundarsub/execwall"
INSTALL_DIR="/usr/local/bin"
LIB_DIR="/usr/lib/execwall"
CONFIG_DIR="/etc/execwall"
LOG_DIR="/var/log/execwall"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        Execwall + OpenClaw - Oracle Cloud Installer            ║"
echo "║                                                              ║"
echo "║  AI Agent Environment with:                                  ║"
echo "║  • Policy-enforced command governance (Execwall)               ║"
echo "║  • WhatsApp integration (OpenClaw)                           ║"
echo "║  • Email support (Himalaya)                                  ║"
echo "║  • OpenRouter LLM                                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# Check Prerequisites
# =============================================================================

log "Checking prerequisites..."

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)  PLATFORM="linux-x86_64" ;;
    aarch64) PLATFORM="linux-aarch64" ;;
    arm64)   PLATFORM="linux-aarch64" ;;
    *)       error "Unsupported architecture: $ARCH" ;;
esac
log "Platform: $PLATFORM"

# Detect OS and package manager
if [[ -f /etc/oracle-release ]] || [[ -f /etc/redhat-release ]]; then
    PKG_MGR="dnf"
    log "Detected: Oracle Linux / RHEL"
elif [[ -f /etc/debian_version ]]; then
    PKG_MGR="apt-get"
    log "Detected: Debian / Ubuntu"
else
    warn "Unknown OS, assuming dnf"
    PKG_MGR="dnf"
fi

# =============================================================================
# Install System Dependencies
# =============================================================================

log "Installing system dependencies..."

if [[ "$PKG_MGR" == "dnf" ]]; then
    dnf install -y \
        gcc gcc-c++ \
        libseccomp-devel \
        git cmake curl jq tar gzip \
        2>/dev/null || yum install -y gcc gcc-c++ libseccomp-devel git cmake curl jq tar gzip
else
    apt-get update
    apt-get install -y \
        build-essential \
        libseccomp-dev \
        git cmake curl jq
fi

# =============================================================================
# Install Execwall
# =============================================================================

log "Installing Execwall execution firewall..."

# Create directories
mkdir -p "$INSTALL_DIR" "$LIB_DIR" "$CONFIG_DIR" "$LOG_DIR"
chmod 755 "$LOG_DIR"

if [[ "$BUILD_FROM_SOURCE" == "1" ]]; then
    # Build from source
    log "Building from source..."

    # Install Rust if needed
    if ! command -v cargo &> /dev/null; then
        log "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    export PATH="$HOME/.cargo/bin:$PATH"

    # Clone and build
    EXECWALL_REPO="/tmp/execwall-build"
    rm -rf "$EXECWALL_REPO"
    git clone "https://github.com/$GITHUB_REPO.git" "$EXECWALL_REPO"
    cd "$EXECWALL_REPO"
    cargo build --release

    # Install binaries
    install -m 755 target/release/execwall "$INSTALL_DIR/"
    install -m 755 target/release/python_runner "$LIB_DIR/" 2>/dev/null || true
    install -m 755 target/release/openclaw_launcher "$INSTALL_DIR/" 2>/dev/null || true

    # Install scripts and policy
    install -m 755 scripts/execwall-shell "$INSTALL_DIR/"
    install -m 755 scripts/email "$INSTALL_DIR/"
    install -m 755 scripts/send-email "$INSTALL_DIR/"
    cp policy.yaml "$CONFIG_DIR/"

    cd /
    rm -rf "$EXECWALL_REPO"
else
    # Download pre-built release
    log "Downloading pre-built release..."

    # Get latest version
    EXECWALL_VERSION=$(curl -sSL "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -z "$EXECWALL_VERSION" ]] && error "Could not determine latest version"
    log "Version: $EXECWALL_VERSION"

    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/download/$EXECWALL_VERSION/execwall-$PLATFORM.tar.gz"
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    curl -sSL "$DOWNLOAD_URL" -o "$TMP_DIR/execwall.tar.gz"
    tar xzf "$TMP_DIR/execwall.tar.gz" -C "$TMP_DIR"

    # Install binaries
    [[ -f "$TMP_DIR/execwall" ]] && install -m 755 "$TMP_DIR/execwall" "$INSTALL_DIR/"
    [[ -f "$TMP_DIR/python_runner" ]] && install -m 755 "$TMP_DIR/python_runner" "$LIB_DIR/"
    [[ -f "$TMP_DIR/openclaw_launcher" ]] && install -m 755 "$TMP_DIR/openclaw_launcher" "$INSTALL_DIR/"

    # Download scripts from repo
    curl -sSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/scripts/execwall-shell" -o "$INSTALL_DIR/execwall-shell"
    curl -sSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/scripts/email" -o "$INSTALL_DIR/email"
    curl -sSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/scripts/send-email" -o "$INSTALL_DIR/send-email"
    chmod 755 "$INSTALL_DIR/execwall-shell" "$INSTALL_DIR/email" "$INSTALL_DIR/send-email"

    # Download policy
    [[ ! -f "$CONFIG_DIR/policy.yaml" ]] && \
        curl -sSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/policy.yaml" -o "$CONFIG_DIR/policy.yaml"
fi

log "Execwall installed: $($INSTALL_DIR/execwall --version 2>/dev/null || echo 'OK')"

# =============================================================================
# Install Node.js and OpenClaw
# =============================================================================

if [[ "$SKIP_OPENCLAW" != "1" ]]; then
    log "Installing Node.js and OpenClaw..."

    if ! command -v node &> /dev/null; then
        if [[ "$PKG_MGR" == "dnf" ]]; then
            curl -fsSL https://rpm.nodesource.com/setup_22.x | bash -
            dnf install -y nodejs
        else
            curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
            apt-get install -y nodejs
        fi
    fi
    log "Node.js: $(node --version)"

    npm install -g openclaw 2>/dev/null || warn "OpenClaw install had warnings"
    log "OpenClaw: $(openclaw --version 2>/dev/null || echo 'installed')"
fi

# =============================================================================
# Install Himalaya (Email Client)
# =============================================================================

if [[ "$SKIP_HIMALAYA" != "1" ]]; then
    log "Installing Himalaya email client..."

    if ! command -v himalaya &> /dev/null; then
        # Install Rust if needed
        if ! command -v cargo &> /dev/null; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
        fi
        export PATH="$HOME/.cargo/bin:$PATH"

        cargo install himalaya
        cp "$HOME/.cargo/bin/himalaya" "$INSTALL_DIR/" 2>/dev/null || true
    fi
    log "Himalaya: $(himalaya --version 2>/dev/null || echo 'installed')"
fi

# =============================================================================
# Configure OpenClaw for OpenRouter
# =============================================================================

# Determine user home directory
if [[ -n "$SUDO_USER" ]]; then
    USER_HOME=$(eval echo ~$SUDO_USER)
    OWNER="$SUDO_USER"
else
    USER_HOME="/home/opc"
    OWNER="opc"
fi

OPENCLAW_HOME="$USER_HOME/.openclaw"
mkdir -p "$OPENCLAW_HOME/agents/main/agent"

if [[ -n "$OPENROUTER_API_KEY" ]]; then
    log "Configuring OpenRouter..."

    cat > "$OPENCLAW_HOME/agents/main/agent/auth-profiles.json" << EOF
{
  "providers": {
    "openrouter": {
      "apiKey": "$OPENROUTER_API_KEY"
    }
  },
  "activeProfile": "openrouter"
}
EOF
fi

# Create main OpenClaw config
if [[ ! -f "$OPENCLAW_HOME/openclaw.json" ]]; then
    cat > "$OPENCLAW_HOME/openclaw.json" << 'EOF'
{
  "agents": {
    "defaults": {
      "model": "openrouter/anthropic/claude-3.5-sonnet",
      "workspace": "~/.openclaw/workspace"
    }
  },
  "channels": {
    "whatsapp": {
      "enabled": true,
      "dmPolicy": "allowlist"
    }
  }
}
EOF
fi

chown -R "$OWNER:$OWNER" "$OPENCLAW_HOME" 2>/dev/null || true

# =============================================================================
# Configure Himalaya (Email)
# =============================================================================

if [[ -n "$GMAIL_ADDRESS" ]] && [[ -n "$GMAIL_APP_PASSWORD" ]]; then
    log "Configuring Himalaya email..."

    HIMALAYA_CONFIG="$USER_HOME/.config/himalaya"
    mkdir -p "$HIMALAYA_CONFIG"

    cat > "$HIMALAYA_CONFIG/config.toml" << EOF
[accounts.gmail]
default = true
email = "$GMAIL_ADDRESS"
display-name = "Execwall"
folder.alias.sent = "[Gmail]/Sent Mail"
folder.alias.drafts = "[Gmail]/Drafts"

[accounts.gmail.backend]
type = "imap"
host = "imap.gmail.com"
port = 993
login = "$GMAIL_ADDRESS"

[accounts.gmail.backend.encryption]
type = "tls"

[accounts.gmail.backend.auth]
type = "password"
raw = "$GMAIL_APP_PASSWORD"

[accounts.gmail.message.send.backend]
type = "smtp"
host = "smtp.gmail.com"
port = 465
login = "$GMAIL_ADDRESS"

[accounts.gmail.message.send.backend.encryption]
type = "tls"

[accounts.gmail.message.send.backend.auth]
type = "password"
raw = "$GMAIL_APP_PASSWORD"

[accounts.gmail.message.send]
save-copy = false
EOF

    chown -R "$OWNER:$OWNER" "$HIMALAYA_CONFIG" 2>/dev/null || true
    chmod 600 "$HIMALAYA_CONFIG/config.toml"
fi

# =============================================================================
# Create Systemd Service (non-seccomp version)
# =============================================================================

log "Creating systemd service..."

cat > /etc/systemd/system/openclaw.service << EOF
[Unit]
Description=OpenClaw AI Agent Gateway with Execwall
After=network.target

[Service]
Type=simple
User=$OWNER
Environment=SHELL=/usr/local/bin/execwall-shell
Environment=EXECWALL_QUIET=1
Environment=HOME=$USER_HOME
WorkingDirectory=$USER_HOME
ExecStart=/usr/bin/openclaw gateway
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
log "Created openclaw.service"

# =============================================================================
# Create Helper Scripts
# =============================================================================

log "Creating helper scripts..."

cat > "$INSTALL_DIR/openclaw-start" << 'EOF'
#!/bin/bash
# Start OpenClaw with Execwall shell wrapper (quiet mode)
export SHELL=/usr/local/bin/execwall-shell
export EXECWALL_QUIET=1
exec openclaw gateway "$@"
EOF
chmod +x "$INSTALL_DIR/openclaw-start"

cat > "$INSTALL_DIR/openclaw-status" << 'EOF'
#!/bin/bash
echo "=== OpenClaw Processes ==="
pgrep -a openclaw || echo "Not running"
echo ""
echo "=== Execwall Version ==="
execwall --version 2>/dev/null || echo "Not found"
echo ""
echo "=== Service Status ==="
systemctl is-active openclaw 2>/dev/null || echo "Service not running"
EOF
chmod +x "$INSTALL_DIR/openclaw-status"

# =============================================================================
# Fix Permissions
# =============================================================================

chown -R "$OWNER:$OWNER" "$LOG_DIR" 2>/dev/null || true

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                  Installation Complete!                        ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}Installed Components:${NC}"
echo "  • Execwall:       $($INSTALL_DIR/execwall --version 2>/dev/null || echo 'installed')"
echo "  • OpenClaw:     $(openclaw --version 2>/dev/null || echo 'installed')"
echo "  • Himalaya:     $(himalaya --version 2>/dev/null || echo 'installed')"
echo "  • Node.js:      $(node --version 2>/dev/null || echo 'installed')"
echo ""
echo -e "${GREEN}Installed Files:${NC}"
echo "  • $INSTALL_DIR/execwall"
echo "  • $INSTALL_DIR/execwall-shell"
echo "  • $INSTALL_DIR/email"
echo "  • $INSTALL_DIR/send-email"
echo "  • $CONFIG_DIR/policy.yaml"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo ""
if [[ -z "$OPENROUTER_API_KEY" ]]; then
    echo "  1. Configure OpenRouter API key:"
    echo "     Edit $OPENCLAW_HOME/agents/main/agent/auth-profiles.json"
    echo ""
fi
if [[ -z "$GMAIL_ADDRESS" ]]; then
    echo "  2. Configure email (optional):"
    echo "     himalaya account configure"
    echo ""
fi
echo "  3. Start OpenClaw:"
echo "     openclaw-start"
echo "     # Or: sudo systemctl start openclaw"
echo ""
echo "  4. Link WhatsApp:"
echo "     Scan QR code shown in terminal"
echo ""
echo -e "${GREEN}Commands:${NC}"
echo "  • openclaw-start          - Start OpenClaw with Execwall"
echo "  • openclaw-status         - Check status"
echo "  • email <to> <subj> <body> - Send email"
echo "  • execwall --quiet          - Policy shell (quiet mode)"
echo ""
echo -e "${CYAN}Documentation: https://github.com/$GITHUB_REPO/blob/main/docs/ORACLE_CLOUD_DEPLOYMENT.md${NC}"
echo ""
