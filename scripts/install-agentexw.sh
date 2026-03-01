#!/bin/bash
# AgentExW Installation Script
set -e

INSTALL_DIR="/usr/local/bin"
LIB_DIR="/usr/lib/execwall"
CONFIG_DIR="/etc/execwall"
DATA_DIR="/var/lib/execwall"
LOG_DIR="/var/log/execwall"
FUND_SCRIPTS_DIR="$DATA_DIR/fund-scripts"
FUND_LOGS_DIR="/var/log/fund"

echo "=== AgentExW Installation ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Create directories
echo "Creating directories..."
mkdir -p "$LIB_DIR" "$CONFIG_DIR" "$DATA_DIR/events" "$LOG_DIR" "$FUND_SCRIPTS_DIR" "$FUND_LOGS_DIR" /tmp/fund-output

# Create execwall user if not exists
if ! id -u execwall &>/dev/null; then
    echo "Creating execwall user..."
    useradd -r -s /bin/false -d "$DATA_DIR" -c "Execwall Service User" execwall
fi

# Build binaries (if source available)
if [ -f "Cargo.toml" ]; then
    echo "Building from source..."
    cargo build --release

    echo "Installing binaries..."
    cp target/release/agentexw "$INSTALL_DIR/"
    cp target/release/agentexw-listener "$INSTALL_DIR/"
    cp target/release/execwall "$INSTALL_DIR/"
    cp target/release/python_runner "$LIB_DIR/"
else
    echo "No Cargo.toml found - skipping build"
    echo "Make sure binaries are already installed in $INSTALL_DIR"
fi

# Set binary permissions
chmod 755 "$INSTALL_DIR/agentexw" "$INSTALL_DIR/agentexw-listener" 2>/dev/null || true
chmod 755 "$LIB_DIR/python_runner" 2>/dev/null || true

# Initialize SQLite database
echo "Initializing database..."
if [ ! -f "$DATA_DIR/agent_memory.db" ]; then
    if [ -f "schema/agentexw.sql" ]; then
        sqlite3 "$DATA_DIR/agent_memory.db" < schema/agentexw.sql
    else
        # Inline schema creation
        sqlite3 "$DATA_DIR/agent_memory.db" << 'EOSQL'
CREATE TABLE IF NOT EXISTS owner (
    id TEXT PRIMARY KEY,
    phone TEXT,
    email TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    phone TEXT UNIQUE,
    email TEXT UNIQUE,
    display_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS contact_scopes (
    id INTEGER PRIMARY KEY,
    contact_id TEXT NOT NULL REFERENCES contacts(id),
    instruction TEXT NOT NULL,
    topics_allow TEXT DEFAULT '[]',
    topics_deny TEXT DEFAULT '[]',
    tools_allow TEXT DEFAULT '[]',
    expires_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    created_by TEXT DEFAULT 'owner'
);
CREATE INDEX IF NOT EXISTS idx_scopes_contact ON contact_scopes(contact_id);

CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY,
    participant_id TEXT NOT NULL,
    participant_type TEXT NOT NULL,
    channel TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    message_id TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_convos_participant ON conversations(participant_id, created_at);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due TEXT,
    priority INTEGER DEFAULT 0,
    source TEXT DEFAULT 'manual',
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    tags TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    notified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reminders_status ON reminders(status, due);

CREATE TABLE IF NOT EXISTS pending_approvals (
    id INTEGER PRIMARY KEY,
    requested_by TEXT,
    tool TEXT NOT NULL,
    args TEXT,
    reason TEXT,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    decided_at TEXT,
    decision TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON pending_approvals(status);

CREATE TABLE IF NOT EXISTS execution_log (
    id INTEGER PRIMARY KEY,
    participant_id TEXT,
    tool TEXT NOT NULL,
    args TEXT,
    result TEXT,
    exit_code INTEGER,
    executed_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_execlog_time ON execution_log(executed_at);

CREATE TABLE IF NOT EXISTS fund_executions (
    id INTEGER PRIMARY KEY,
    script_name TEXT NOT NULL,
    args TEXT,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    executed_at TEXT DEFAULT (datetime('now'))
);
EOSQL
    fi
    echo "Database initialized at $DATA_DIR/agent_memory.db"
else
    echo "Database already exists at $DATA_DIR/agent_memory.db"
fi

# Set permissions
echo "Setting permissions..."
chown -R execwall:execwall "$DATA_DIR" "$LOG_DIR" /tmp/fund-output
chmod 750 "$DATA_DIR" "$LOG_DIR"
chmod 755 "$FUND_SCRIPTS_DIR"  # Scripts readable by all, writable only by root
chown root:execwall "$FUND_LOGS_DIR"
chmod 750 "$FUND_LOGS_DIR"

# Install systemd services
echo "Installing systemd services..."
if [ -d "systemd" ]; then
    cp systemd/agentexw.service /etc/systemd/system/
    cp systemd/agentexw-listener.service /etc/systemd/system/
    cp systemd/agentexw-watcher.service /etc/systemd/system/
    cp systemd/agentexw-watcher.path /etc/systemd/system/
fi

# Reload systemd
systemctl daemon-reload

# Enable services
echo "Enabling services..."
systemctl enable agentexw.service
systemctl enable agentexw-listener.service
systemctl enable agentexw-watcher.path

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo ""
echo "1. Set the owner (your phone/email):"
echo "   agentexw set-owner sundar --phone '+1234567890' --email 'you@example.com'"
echo ""
echo "2. Start the services:"
echo "   sudo systemctl start agentexw"
echo ""
echo "3. Check status:"
echo "   agentexw status"
echo "   sudo systemctl status agentexw"
echo ""
echo "4. View logs:"
echo "   journalctl -u agentexw -f"
echo ""
echo "5. Add contacts:"
echo "   agentexw add-contact ron --phone '+1234567890' --name 'Ron'"
echo "   agentexw set-scope ron 'Discuss execwall only' --allow 'execwall,pricing' --deny 'fund,personal'"
echo ""
echo "6. Add fund scripts to $FUND_SCRIPTS_DIR"
echo ""
