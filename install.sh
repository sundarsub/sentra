#!/bin/bash
# Sentra Easy Installer

set -e

echo "Installing Sentra..."

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$OS" = "darwin" ]; then
    if [ "$ARCH" = "arm64" ]; then
        ASSET="sentra-macos-aarch64.tar.gz"
    else
        ASSET="sentra-macos-x86_64.tar.gz"
    fi
elif [ "$OS" = "linux" ]; then
    if [ "$ARCH" = "aarch64" ]; then
        ASSET="sentra-linux-aarch64.tar.gz"
    else
        ASSET="sentra-linux-x86_64.tar.gz"
    fi
else
    echo "Unsupported OS: $OS"
    exit 1
fi

echo "Downloading $ASSET..."

# Download and extract
cd /tmp
rm -rf /tmp/sentra-install-tmp
mkdir -p /tmp/sentra-install-tmp
cd /tmp/sentra-install-tmp
curl -sL "https://github.com/sundarsub/sentra/releases/latest/download/$ASSET" | tar xz

# Install binary
sudo mv /tmp/sentra-install-tmp/sentra /usr/local/bin/
rm -rf /tmp/sentra-install-tmp
echo "✓ Installed sentra to /usr/local/bin/"

# Create config directory and download example policy
sudo mkdir -p /etc/sentra
sudo curl -sL "https://raw.githubusercontent.com/sundarsub/sentra/main/policy.yaml" -o /etc/sentra/policy.yaml
echo "✓ Installed example policy to /etc/sentra/policy.yaml"

echo ""
echo "Installation complete!"
echo ""
echo "Usage:"
echo "  sentra                              # Uses /etc/sentra/policy.yaml"
echo "  sentra --policy /path/to/policy.yaml"
echo ""
echo "Run 'sentra' to start!"
