-- AgentExW Database Schema
-- Owner-controlled model with contact scoping

-- Owner table (single row)
CREATE TABLE IF NOT EXISTS owner (
    id TEXT PRIMARY KEY,
    phone TEXT,
    email TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Contacts the agent can interact with
CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    phone TEXT UNIQUE,
    email TEXT UNIQUE,
    display_name TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_seen_at TEXT
);

-- Owner's instructions about each contact
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

-- Conversations (owner sees all, contacts see only theirs)
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY,
    participant_id TEXT NOT NULL,
    participant_type TEXT NOT NULL,
    channel TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    message_id TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    processed TEXT  -- timestamp when message was processed by agent
);
CREATE INDEX IF NOT EXISTS idx_convos_participant ON conversations(participant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_convos_unprocessed ON conversations(role, processed) WHERE processed IS NULL;

-- Owner's tasks
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

-- Owner's notes
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    tags TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

-- Owner's reminders
CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    due TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    notified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_reminders_status ON reminders(status, due);

-- Pending approvals (owner approves)
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

-- Execution log (audit trail)
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

-- Fund script execution log
CREATE TABLE IF NOT EXISTS fund_executions (
    id INTEGER PRIMARY KEY,
    script_name TEXT NOT NULL,
    args TEXT,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    executed_at TEXT DEFAULT (datetime('now'))
);
