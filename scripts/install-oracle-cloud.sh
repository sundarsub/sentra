#!/bin/bash
# install-oracle-cloud.sh - OpenClaw Execution Firewall installer for Oracle Cloud
#
# This script installs Sentra, openclaw_launcher, python_runner, and sentra-shell
# on Oracle Cloud Linux (Oracle Linux 9, Ubuntu 22.04, or compatible)
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/sundarsub/sentra/main/scripts/install-oracle-cloud.sh | sudo bash
#
# Environment variables:
#   SENTRA_VERSION   - Specific version to install (default: latest)
#   SKIP_SYSTEMD     - Set to 1 to skip systemd service creation
#   OPENCLAW_BIN     - Path to OpenClaw binary (default: /usr/bin/openclaw)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GITHUB_REPO="sundarsub/sentra"
INSTALL_DIR="/usr/local/bin"
LIB_DIR="/usr/lib/sentra"
CONFIG_DIR="/etc/sentra"
LOG_DIR="/var/log/sentra"
OPENCLAW_BIN="${OPENCLAW_BIN:-/usr/bin/openclaw}"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     OpenClaw Execution Firewall - Oracle Cloud Installer     ║"
echo "║                                                              ║"
echo "║  Seccomp-locked AI agent sandbox with:                       ║"
echo "║  • Policy-enforced command governance                        ║"
echo "║  • WhatsApp/Telegram integration support                     ║"
echo "║  • Python sandbox isolation                                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        PLATFORM="linux-x86_64"
        ;;
    aarch64|arm64)
        PLATFORM="linux-aarch64"
        ;;
    *)
        echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
        echo "Supported: x86_64, aarch64"
        exit 1
        ;;
esac

echo -e "${GREEN}→ Detected platform: $PLATFORM${NC}"

# Detect OS
if [ -f /etc/oracle-release ]; then
    OS="oracle"
    echo -e "${GREEN}→ Detected OS: Oracle Linux${NC}"
elif [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo -e "${GREEN}→ Detected OS: $NAME${NC}"
else
    OS="unknown"
    echo -e "${YELLOW}→ Unknown OS, proceeding anyway${NC}"
fi

# Install dependencies
echo -e "${BLUE}→ Installing dependencies...${NC}"
case $OS in
    oracle|rhel|centos|fedora)
        dnf install -y curl tar gzip libseccomp || yum install -y curl tar gzip libseccomp
        ;;
    ubuntu|debian)
        apt-get update
        apt-get install -y curl tar gzip libseccomp2
        ;;
    *)
        echo -e "${YELLOW}→ Unknown package manager, assuming dependencies are installed${NC}"
        ;;
esac

# Get latest version if not specified
if [ -z "$SENTRA_VERSION" ]; then
    echo -e "${BLUE}→ Fetching latest release...${NC}"
    SENTRA_VERSION=$(curl -sSL "https://api.github.com/repos/$GITHUB_REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$SENTRA_VERSION" ]; then
        echo -e "${RED}Error: Could not determine latest version${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}→ Installing Sentra $SENTRA_VERSION${NC}"

# Download URL
DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/download/$SENTRA_VERSION/sentra-$PLATFORM.tar.gz"

# Create temporary directory
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# Download release
echo -e "${BLUE}→ Downloading from $DOWNLOAD_URL${NC}"
curl -sSL "$DOWNLOAD_URL" -o "$TMP_DIR/sentra.tar.gz"

# Extract
echo -e "${BLUE}→ Extracting...${NC}"
tar xzf "$TMP_DIR/sentra.tar.gz" -C "$TMP_DIR"

# Create directories
echo -e "${BLUE}→ Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$LIB_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Install binaries
echo -e "${BLUE}→ Installing binaries...${NC}"

# Find and install sentra
if [ -f "$TMP_DIR/sentra" ]; then
    cp "$TMP_DIR/sentra" "$INSTALL_DIR/sentra"
    chmod 755 "$INSTALL_DIR/sentra"
    echo -e "${GREEN}  ✓ Installed sentra${NC}"
else
    echo -e "${RED}  ✗ sentra binary not found in release${NC}"
    exit 1
fi

# Find and install openclaw_launcher
if [ -f "$TMP_DIR/openclaw_launcher" ]; then
    cp "$TMP_DIR/openclaw_launcher" "$INSTALL_DIR/openclaw_launcher"
    chmod 755 "$INSTALL_DIR/openclaw_launcher"
    echo -e "${GREEN}  ✓ Installed openclaw_launcher${NC}"
else
    echo -e "${YELLOW}  → openclaw_launcher not found, skipping${NC}"
fi

# Find and install python_runner
if [ -f "$TMP_DIR/python_runner" ]; then
    cp "$TMP_DIR/python_runner" "$LIB_DIR/python_runner"
    chmod 755 "$LIB_DIR/python_runner"
    echo -e "${GREEN}  ✓ Installed python_runner${NC}"
else
    echo -e "${YELLOW}  → python_runner not found, skipping${NC}"
fi

# Install sentra-shell wrapper
echo -e "${BLUE}→ Installing sentra-shell...${NC}"
cat > "$INSTALL_DIR/sentra-shell" << 'SHELL_EOF'
#!/bin/bash
# sentra-shell - Sentra REPL wrapper for OpenClaw
#
# This script is used as SHELL by OpenClaw to route all command execution
# through Sentra's policy enforcement.

set -e

SENTRA_BIN="${SENTRA_BIN:-/usr/local/bin/sentra}"
POLICY_FILE="${SENTRA_POLICY:-/etc/sentra/policy.yaml}"
PYTHON_RUNNER="${PYTHON_RUNNER:-/usr/lib/sentra/python_runner}"

# Check if Sentra exists
if [[ ! -x "$SENTRA_BIN" ]]; then
    echo "sentra-shell: ERROR: Sentra not found at $SENTRA_BIN" >&2
    exit 127
fi

# Build Sentra arguments
SENTRA_ARGS=()
if [[ -f "$POLICY_FILE" ]]; then
    SENTRA_ARGS+=("--policy" "$POLICY_FILE")
fi
if [[ -x "$PYTHON_RUNNER" ]]; then
    SENTRA_ARGS+=("--python-runner" "$PYTHON_RUNNER")
fi

# Handle different invocation modes
case "$1" in
    -c)
        # sh -c compatible mode: execute command string
        shift
        if [[ -z "$1" ]]; then
            echo "sentra-shell: -c requires a command string" >&2
            exit 1
        fi
        echo "$*" | "$SENTRA_BIN" "${SENTRA_ARGS[@]}" 2>&1
        exit ${PIPESTATUS[1]}
        ;;
    -i)
        # Interactive mode
        shift
        exec "$SENTRA_BIN" "${SENTRA_ARGS[@]}" "$@"
        ;;
    "")
        # No arguments: interactive REPL
        exec "$SENTRA_BIN" "${SENTRA_ARGS[@]}"
        ;;
    *)
        # Script file or command
        if [[ -f "$1" ]]; then
            cat "$1" | "$SENTRA_BIN" "${SENTRA_ARGS[@]}" 2>&1
            exit ${PIPESTATUS[1]}
        else
            echo "$*" | "$SENTRA_BIN" "${SENTRA_ARGS[@]}" 2>&1
            exit ${PIPESTATUS[1]}
        fi
        ;;
esac
SHELL_EOF
chmod 755 "$INSTALL_DIR/sentra-shell"
echo -e "${GREEN}  ✓ Installed sentra-shell${NC}"

# Install default policy if not exists
if [ ! -f "$CONFIG_DIR/policy.yaml" ]; then
    echo -e "${BLUE}→ Installing default policy...${NC}"
    if [ -f "$TMP_DIR/policy.yaml" ]; then
        cp "$TMP_DIR/policy.yaml" "$CONFIG_DIR/policy.yaml"
    else
        # Download policy from repo
        curl -sSL "https://raw.githubusercontent.com/$GITHUB_REPO/main/policy.yaml" -o "$CONFIG_DIR/policy.yaml"
    fi
    chmod 644 "$CONFIG_DIR/policy.yaml"
    echo -e "${GREEN}  ✓ Installed policy.yaml${NC}"
else
    echo -e "${YELLOW}  → policy.yaml exists, not overwriting${NC}"
fi

# Create systemd service
if [ "$SKIP_SYSTEMD" != "1" ] && command -v systemctl &> /dev/null; then
    echo -e "${BLUE}→ Creating systemd service...${NC}"

    cat > /etc/systemd/system/openclaw-firewall.service << EOF
[Unit]
Description=OpenClaw Execution Firewall
Documentation=https://github.com/sundarsub/sentra
After=network.target

[Service]
Type=simple
User=opc
Group=opc
ExecStart=$INSTALL_DIR/openclaw_launcher \\
    --openclaw-bin $OPENCLAW_BIN \\
    --seccomp-profile gateway \\
    --sentra-repl \\
    -- gateway
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/tmp /var/log/sentra
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo -e "${GREEN}  ✓ Created openclaw-firewall.service${NC}"
    echo -e "${YELLOW}  → Run 'systemctl enable --now openclaw-firewall' to start${NC}"
fi

# Verify installation
echo ""
echo -e "${BLUE}→ Verifying installation...${NC}"

if [ -x "$INSTALL_DIR/sentra" ]; then
    VERSION=$("$INSTALL_DIR/sentra" --version 2>&1 || echo "")
    if echo "$VERSION" | grep -q "GLIBC"; then
        echo -e "${YELLOW}  → sentra: Binary requires newer GLIBC${NC}"
        echo -e "${YELLOW}    To fix, build from source:${NC}"
        echo -e "${YELLOW}    curl https://sh.rustup.rs -sSf | sh${NC}"
        echo -e "${YELLOW}    git clone https://github.com/sundarsub/sentra.git${NC}"
        echo -e "${YELLOW}    cd sentra && cargo build --release${NC}"
        echo -e "${YELLOW}    sudo cp target/release/{sentra,openclaw_launcher,python_runner} /usr/local/bin/${NC}"
    elif [ -n "$VERSION" ]; then
        echo -e "${GREEN}  ✓ sentra: $VERSION${NC}"
    else
        echo -e "${GREEN}  ✓ sentra: installed${NC}"
    fi
else
    echo -e "${RED}  ✗ sentra not found${NC}"
fi

if [ -x "$INSTALL_DIR/openclaw_launcher" ]; then
    echo -e "${GREEN}  ✓ openclaw_launcher: installed${NC}"
fi

if [ -x "$LIB_DIR/python_runner" ]; then
    echo -e "${GREEN}  ✓ python_runner: installed${NC}"
fi

if [ -x "$INSTALL_DIR/sentra-shell" ]; then
    echo -e "${GREEN}  ✓ sentra-shell: installed${NC}"
fi

if [ -f "$CONFIG_DIR/policy.yaml" ]; then
    echo -e "${GREEN}  ✓ policy.yaml: installed${NC}"
fi

# Show available seccomp profiles
echo ""
echo -e "${BLUE}→ Available seccomp profiles:${NC}"
"$INSTALL_DIR/openclaw_launcher" --list-profiles 2>/dev/null | head -20 || echo "  (run openclaw_launcher --list-profiles to see)"

# Print summary
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Installation Complete!                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Installed components:"
echo -e "  • sentra           → $INSTALL_DIR/sentra"
echo -e "  • openclaw_launcher → $INSTALL_DIR/openclaw_launcher"
echo -e "  • python_runner    → $LIB_DIR/python_runner"
echo -e "  • sentra-shell     → $INSTALL_DIR/sentra-shell"
echo -e "  • policy.yaml      → $CONFIG_DIR/policy.yaml"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo ""
echo "1. Install OpenClaw (if not already installed):"
echo "   curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -"
echo "   sudo dnf install -y nodejs"
echo "   sudo npm install -g openclaw"
echo ""
echo "2. Configure your LLM API key:"
echo "   openclaw config set llm.provider gemini"
echo "   openclaw config set llm.apiKey 'YOUR_API_KEY'"
echo ""
echo "3. Start OpenClaw with execution firewall:"
echo "   openclaw_launcher --openclaw-bin /usr/bin/openclaw -- gateway"
echo ""
echo "   Or use systemd:"
echo "   sudo systemctl enable --now openclaw-firewall"
echo ""
echo -e "Documentation: ${BLUE}https://github.com/sundarsub/sentra/blob/main/docs/ORACLE_CLOUD_DEPLOYMENT.md${NC}"
