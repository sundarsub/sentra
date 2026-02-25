#!/bin/bash
# OpenClaw Isolated Launch Script
#
# This script provides full network isolation by:
# 1. Creating a network namespace for OpenClaw
# 2. Setting up a veth pair so OpenClaw can ONLY reach Execwall
# 3. Running openclaw_launcher inside the namespace
#
# Usage: sudo ./launch_openclaw_isolated.sh [openclaw_args...]

set -e

# Configuration
EXECWALL_PORT="${EXECWALL_PORT:-9999}"
NAMESPACE="openclaw_ns"
VETH_HOST="veth_host"
VETH_CONTAINER="veth_oc"
HOST_IP="10.200.1.1"
CONTAINER_IP="10.200.1.2"
EXECWALL_BIN="${EXECWALL_BIN:-/usr/local/bin/execwall}"
OPENCLAW_BIN="${OPENCLAW_BIN:-/usr/local/bin/openclaw}"
LAUNCHER_BIN="${LAUNCHER_BIN:-/usr/local/bin/openclaw_launcher}"
PYTHON_RUNNER="${PYTHON_RUNNER:-/usr/lib/execwall/python_runner}"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║    OpenClaw Isolated Launch - Full Network Isolation     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)"
    exit 1
fi

# Cleanup function
cleanup() {
    echo ""
    echo "→ Cleaning up network namespace..."
    ip netns del "$NAMESPACE" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    echo "✓ Cleanup complete"
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Step 1: Create network namespace
echo "→ Creating network namespace: $NAMESPACE"
ip netns add "$NAMESPACE" 2>/dev/null || true

# Step 2: Create veth pair
echo "→ Creating veth pair..."
ip link add "$VETH_HOST" type veth peer name "$VETH_CONTAINER"
ip link set "$VETH_CONTAINER" netns "$NAMESPACE"

# Step 3: Configure host side
echo "→ Configuring host network..."
ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

# Step 4: Configure namespace side
echo "→ Configuring namespace network..."
ip netns exec "$NAMESPACE" ip addr add "$CONTAINER_IP/24" dev "$VETH_CONTAINER"
ip netns exec "$NAMESPACE" ip link set "$VETH_CONTAINER" up
ip netns exec "$NAMESPACE" ip link set lo up

# Step 5: Set up NAT for Execwall port forwarding
# OpenClaw at 10.200.1.2 connects to 10.200.1.1:$EXECWALL_PORT
# which is forwarded to host's Execwall on 127.0.0.1:$EXECWALL_PORT
echo "→ Setting up port forwarding to Execwall..."

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Forward traffic from veth to localhost
iptables -t nat -A PREROUTING -i "$VETH_HOST" -p tcp --dport "$EXECWALL_PORT" -j DNAT --to-destination "127.0.0.1:$EXECWALL_PORT"
iptables -A FORWARD -i "$VETH_HOST" -o lo -p tcp --dport "$EXECWALL_PORT" -j ACCEPT
iptables -A FORWARD -o "$VETH_HOST" -i lo -m state --state ESTABLISHED,RELATED -j ACCEPT

# Step 6: Start Execwall on host (if not running)
if ! nc -z 127.0.0.1 "$EXECWALL_PORT" 2>/dev/null; then
    echo "→ Starting Execwall API server on port $EXECWALL_PORT..."
    "$EXECWALL_BIN" --api --port "$EXECWALL_PORT" --python-runner "$PYTHON_RUNNER" &
    EXECWALL_PID=$!
    sleep 1
    echo "✓ Execwall started (PID: $EXECWALL_PID)"
else
    echo "✓ Execwall already running on port $EXECWALL_PORT"
fi

# Step 7: Run openclaw_launcher in the namespace
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Network Isolated Environment Ready"
echo "  OpenClaw can ONLY reach: $HOST_IP:$EXECWALL_PORT (Execwall)"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "→ Launching OpenClaw in isolated namespace..."

# Run in namespace with seccomp
ip netns exec "$NAMESPACE" "$LAUNCHER_BIN" \
    --openclaw-bin "$OPENCLAW_BIN" \
    --execwall-bin "$EXECWALL_BIN" \
    --port "$EXECWALL_PORT" \
    --skip-execwall \
    --verbose \
    "$@"

# Cleanup happens via trap
