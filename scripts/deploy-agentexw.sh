#!/bin/bash
# Deploy AgentExW to Oracle Cloud server
# Usage: ./scripts/deploy-agentexw.sh

set -e

SERVER="opc@193.122.147.218"
SSH_KEY="/Users/sundarsubramaniam/Downloads/ssh-key-2026-02-26.key"
SSH="ssh -i $SSH_KEY $SERVER"
SCP="scp -i $SSH_KEY"

echo "=== Building AgentExW for aarch64-unknown-linux-gnu ==="
cross build --release --target aarch64-unknown-linux-gnu --bin agentexw --bin whatsapp-svc --bin email-svc --bin calendar-svc

echo "=== Uploading binaries ==="
$SCP target/aarch64-unknown-linux-gnu/release/agentexw $SERVER:/tmp/
$SCP target/aarch64-unknown-linux-gnu/release/whatsapp-svc $SERVER:/tmp/
$SCP target/aarch64-unknown-linux-gnu/release/email-svc $SERVER:/tmp/
$SCP target/aarch64-unknown-linux-gnu/release/calendar-svc $SERVER:/tmp/

echo "=== Uploading tools ==="
$SCP tools/* $SERVER:/tmp/tools/

echo "=== Uploading systemd services ==="
$SCP systemd/*.service $SERVER:/tmp/

echo "=== Installing on server ==="
$SSH << 'REMOTE'
set -e

# Stop existing services
sudo systemctl stop agentexw 2>/dev/null || true
sudo systemctl stop whatsapp-svc 2>/dev/null || true
sudo systemctl stop email-svc 2>/dev/null || true
sudo systemctl stop calendar-svc 2>/dev/null || true

# Install binaries
sudo mv /tmp/agentexw /usr/local/bin/
sudo mv /tmp/whatsapp-svc /usr/local/bin/
sudo mv /tmp/email-svc /usr/local/bin/
sudo mv /tmp/calendar-svc /usr/local/bin/
sudo chmod +x /usr/local/bin/agentexw /usr/local/bin/whatsapp-svc /usr/local/bin/email-svc /usr/local/bin/calendar-svc

# Install tools
sudo mkdir -p /usr/lib/execwall/tools
sudo mv /tmp/tools/* /usr/lib/execwall/tools/
sudo chmod +x /usr/lib/execwall/tools/*

# Create data directories
sudo mkdir -p /var/lib/execwall/events
sudo mkdir -p /var/lib/execwall/scripts
sudo chown -R opc:opc /var/lib/execwall

# Install systemd services
sudo mv /tmp/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start services
sudo systemctl enable whatsapp-svc email-svc calendar-svc agentexw
sudo systemctl start whatsapp-svc email-svc calendar-svc agentexw

echo "=== Status ==="
sudo systemctl status agentexw --no-pager || true
REMOTE

echo "=== Deployment complete ==="
