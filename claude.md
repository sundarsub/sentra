# Claude Code Memory - Execwall/AgentExW

## Oracle Cloud Instance

| Setting | Value |
|---------|-------|
| **Public IP** | 193.122.147.218 |
| **User** | opc |
| **SSH Key** | `/Users/sundarsubramaniam/Downloads/ssh-key-2026-02-26.key` |
| **Platform** | Oracle Linux (ARM64 Ampere A1) |

### SSH Command
```bash
ssh -i "/Users/sundarsubramaniam/Downloads/ssh-key-2026-02-26.key" opc@193.122.147.218
```

## Installed Components

| Component | Path | Status |
|-----------|------|--------|
| execwall | /usr/local/bin/execwall | Installed |
| openclaw_launcher | /usr/local/bin/openclaw_launcher | Installed |
| python_runner | /usr/lib/execwall/python_runner | Installed |
| execwall-shell | /usr/local/bin/execwall-shell | Installed |
| policy.yaml | /etc/execwall/policy.yaml | Configured |
| himalaya | /home/opc/.local/bin/himalaya | Installed |
| openclaw | /usr/bin/openclaw | Installed |

## Integrations

| Integration | Status | Notes |
|-------------|--------|-------|
| Email | ✅ Ready | Gmail via Himalaya |
| WhatsApp | ✅ Ready | Connected |
| Web Search | ✅ Ready | Tavily API (`websearch` command) |
| Web Browse | ✅ Ready | Firefox headless (`browse` command) |
| GitHub | ✅ Ready | gh CLI authenticated |
| Memory/DB | ✅ Ready | SQLite (`remember`, `recall`, `remind`, `tasks`) |
| Google Calendar | ✅ Ready | `gcal list` / `gcal add` |
| PDF Processing | ✅ Ready | `pdftext file.pdf` |
| Slack | ⏳ Needs webhook | `slack "message"` |
| Todoist | ⏳ Needs API key | `todo list` / `todo add` |
| Crypto Prices | ✅ Ready | `crypto bitcoin ethereum` |
| Calculator | ✅ Ready | `calc "sqrt(16)"` |
| Stock Prices | ✅ Ready | `stock AAPL GOOGL` |

## Secrets Location

Local: `/Users/sundarsubramaniam/execwall/secrets.env`
Oracle: `~/.openclaw/.env`

## Email Configuration

| Setting | Value |
|---------|-------|
| Email | execwall@gmail.com |
| Provider | Gmail |
| Config | ~/.config/himalaya/config.toml |

## OpenClaw Configuration

- **Config file**: `~/.openclaw/openclaw.json`
- **Model**: openrouter/auto (auto-selects best available)
- **Gateway port**: 18789

## Environment Variables

- `~/.openclaw/.env` - OPENROUTER_API_KEY
- `/etc/execwall/env` - OPENROUTER_API_KEY

## Quick Commands

```bash
# SSH to Oracle
ssh -i "/Users/sundarsubramaniam/Downloads/ssh-key-2026-02-26.key" opc@193.122.147.218

# Check OpenClaw status
sudo systemctl status openclaw

# View logs
journalctl -u openclaw -f

# Check email
~/.local/bin/himalaya envelope list

# Web search
~/.local/bin/websearch "your query here"

# Browse webpage (text)
~/.local/bin/browse "https://example.com"

# Browse webpage (screenshot)
~/.local/bin/browse "https://example.com" --screenshot /tmp/page.png

# GitHub
gh repo list
gh issue list -R sundarsub/execwall
gh pr list -R sundarsub/execwall

# Memory - Notes
~/.local/bin/remember "note content" "optional,tags"
~/.local/bin/recall              # list recent notes
~/.local/bin/recall "search"     # search notes

# Memory - Reminders
~/.local/bin/remind "task" "2026-02-27 14:00"
~/.local/bin/tasks               # list pending tasks
~/.local/bin/done 1              # mark task 1 as complete
```
