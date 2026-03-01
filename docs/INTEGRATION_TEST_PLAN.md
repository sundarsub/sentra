# OpenClaw Integration Test Plan

## Overview

Test all AI agent integrations on Oracle Cloud instance (193.122.147.218).

**Goal:** Verify each integration works end-to-end via WhatsApp/Email commands.

---

## Tier 1: Core Integrations (Already Installed)

### 1. Web Search (Tavily) ✅ INSTALLED

| Test | Command | Expected Result |
|------|---------|-----------------|
| Basic search | `websearch "weather in NYC"` | 5 results with titles, URLs, snippets |
| News search | `websearch "breaking news today"` | Recent news articles |
| Technical search | `websearch "python asyncio tutorial"` | Developer docs/tutorials |

**WhatsApp Test:**
> "Search for the latest AI news"

---

### 2. Web Browsing (Selenium/Firefox) ✅ INSTALLED

| Test | Command | Expected Result |
|------|---------|-----------------|
| Fetch text | `browse "https://example.com"` | Page title + body text |
| Screenshot | `browse "https://google.com" -s /tmp/g.png` | PNG file created |
| Dynamic page | `browse "https://news.ycombinator.com"` | JavaScript-rendered content |

**WhatsApp Test:**
> "Go to hacker news and tell me the top 3 stories"

---

### 3. Email (Himalaya) ✅ INSTALLED

| Test | Command | Expected Result |
|------|---------|-----------------|
| List inbox | `himalaya envelope list` | Recent emails listed |
| Read email | `himalaya message read <id>` | Email content displayed |
| Send email | `echo "Test" \| himalaya message send -t test@example.com -s "Subject"` | Email sent |

**WhatsApp Test:**
> "Check my email inbox"
> "Send an email to sundar@example.com saying hello"

---

### 4. Code Execution (Python Sandbox) ✅ INSTALLED

| Test | Command | Expected Result |
|------|---------|-----------------|
| Basic math | `python3 -c "print(2+2)"` | 4 |
| Data analysis | `python3 -c "import statistics; print(statistics.mean([1,2,3,4,5]))"` | 3 |
| File processing | `python3 -c "print(len(open('/etc/hosts').read()))"` | File size |

**WhatsApp Test:**
> "Calculate the factorial of 10"
> "What's the average of 45, 67, 89, 23, 56?"

---

## Tier 2: High Value (To Install)

### 5. GitHub (gh CLI)

**Install:**
```bash
sudo dnf install -y gh
gh auth login
```

| Test | Command | Expected Result |
|------|---------|-----------------|
| List repos | `gh repo list` | User's repositories |
| View issues | `gh issue list -R sundarsub/execwall` | Open issues |
| Create issue | `gh issue create -R sundarsub/execwall -t "Test" -b "Body"` | Issue created |
| PR status | `gh pr list -R sundarsub/execwall` | Open PRs |

**WhatsApp Test:**
> "Show me open issues on execwall repo"
> "Create an issue titled 'Add logging' on execwall"

---

### 6. SQLite Database

**Install:**
```bash
sudo dnf install -y sqlite
pip3 install sqlite-utils
```

**Setup:**
```bash
sqlite3 ~/data.db "CREATE TABLE notes (id INTEGER PRIMARY KEY, content TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);"
```

| Test | Command | Expected Result |
|------|---------|-----------------|
| Insert | `sqlite3 ~/data.db "INSERT INTO notes (content) VALUES ('Remember to buy milk');"` | Row inserted |
| Query | `sqlite3 ~/data.db "SELECT * FROM notes;"` | Notes listed |
| Search | `sqlite3 ~/data.db "SELECT * FROM notes WHERE content LIKE '%milk%';"` | Matching notes |

**WhatsApp Test:**
> "Remember that I need to call John tomorrow"
> "What do I need to remember?"

---

### 7. Calendar (Google Calendar API)

**Install:**
```bash
pip3 install gcsa google-auth-oauthlib
```

**Setup:** Requires OAuth credentials from Google Cloud Console.

| Test | Command | Expected Result |
|------|---------|-----------------|
| List events | `gcal list --days 7` | Upcoming events |
| Create event | `gcal create "Meeting" --start "2026-02-27 10:00"` | Event created |
| Delete event | `gcal delete <event_id>` | Event removed |

**WhatsApp Test:**
> "What's on my calendar this week?"
> "Schedule a meeting tomorrow at 2pm"

---

### 8. Task Management (Todoist API)

**Install:**
```bash
pip3 install todoist-api-python
```

**Setup:** Get API token from todoist.com/app/settings/integrations

| Test | Command | Expected Result |
|------|---------|-----------------|
| List tasks | `todoist list` | Active tasks |
| Add task | `todoist add "Buy groceries"` | Task created |
| Complete | `todoist complete <id>` | Task marked done |

**WhatsApp Test:**
> "Add a task: Review PR by Friday"
> "What are my open tasks?"

---

### 9. Slack Webhook

**Setup:** Create incoming webhook at api.slack.com

```bash
echo 'SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx' >> ~/.openclaw/.env
```

**Create command:**
```bash
cat > ~/.local/bin/slack-notify << 'EOF'
#!/bin/bash
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"$1\"}" \
  "$SLACK_WEBHOOK_URL"
EOF
chmod +x ~/.local/bin/slack-notify
```

| Test | Command | Expected Result |
|------|---------|-----------------|
| Send message | `slack-notify "Hello from OpenClaw"` | Message in Slack channel |

**WhatsApp Test:**
> "Send a slack message: Build completed successfully"

---

## Tier 3: Advanced (Optional)

### 10. Voice (ElevenLabs TTS)

**Install:**
```bash
pip3 install elevenlabs
echo 'ELEVENLABS_API_KEY=xxx' >> ~/.openclaw/.env
```

| Test | Command | Expected Result |
|------|---------|-----------------|
| Text to speech | `elevenlabs "Hello world" -o /tmp/hello.mp3` | Audio file created |

---

### 11. Image Generation (OpenAI DALL-E)

**Install:**
```bash
pip3 install openai
echo 'OPENAI_API_KEY=xxx' >> ~/.openclaw/.env
```

| Test | Command | Expected Result |
|------|---------|-----------------|
| Generate image | `dalle "A cat wearing a hat" -o /tmp/cat.png` | Image file created |

---

### 12. PDF Processing

**Install:**
```bash
pip3 install pypdf2 pdfplumber
```

| Test | Command | Expected Result |
|------|---------|-----------------|
| Extract text | `pdftext /path/to/doc.pdf` | Text content |
| Page count | `pdfinfo /path/to/doc.pdf` | Metadata |

---

### 13. Payments (Stripe)

**Install:**
```bash
pip3 install stripe
echo 'STRIPE_API_KEY=xxx' >> ~/.openclaw/.env
```

| Test | Command | Expected Result |
|------|---------|-----------------|
| List customers | `stripe customers list` | Customer list |
| Create invoice | `stripe invoice create --customer cus_xxx` | Invoice created |

---

## Test Execution Order

### Phase 1: Verify Existing (30 min)
1. [ ] Web Search - 3 queries
2. [ ] Web Browse - text + screenshot
3. [ ] Email - list + send
4. [ ] Python - 3 calculations

### Phase 2: Install GitHub + SQLite (1 hour)
5. [ ] Install gh CLI
6. [ ] Auth with GitHub
7. [ ] Test repo/issue commands
8. [ ] Install SQLite
9. [ ] Create notes table
10. [ ] Test CRUD operations

### Phase 3: Calendar + Tasks (2 hours)
11. [ ] Set up Google Calendar OAuth
12. [ ] Test calendar commands
13. [ ] Set up Todoist API
14. [ ] Test task commands

### Phase 4: Notifications (30 min)
15. [ ] Create Slack webhook
16. [ ] Test slack-notify

### Phase 5: Advanced (Optional)
17. [ ] ElevenLabs TTS
18. [ ] DALL-E images
19. [ ] PDF processing
20. [ ] Stripe (if needed)

---

## WhatsApp End-to-End Test Script

Send these messages via WhatsApp to test full integration:

```
1. "Search for Oracle Cloud free tier limits"
2. "Go to github.com/sundarsub/execwall and summarize the README"
3. "Check my email"
4. "Calculate compound interest on $1000 at 5% for 10 years"
5. "Show open issues on execwall"
6. "Remember: Meeting with John on Friday at 3pm"
7. "What do I need to remember?"
8. "Send a slack message: System check complete"
```

---

## Success Criteria

| Integration | Pass Criteria |
|-------------|---------------|
| Web Search | Returns relevant results in <5s |
| Web Browse | Extracts text, screenshots render correctly |
| Email | Can read inbox and send emails |
| Code Exec | Calculations return correct results |
| GitHub | Can list/create issues |
| SQLite | CRUD operations work |
| Calendar | Can view/create events |
| Tasks | Can add/complete tasks |
| Slack | Messages appear in channel |

---

## Troubleshooting

### Common Issues

1. **Timeout errors**: Increase timeout in Execwall policy
2. **Permission denied**: Check file permissions, run with correct user
3. **API rate limits**: Add delays between requests
4. **Auth failures**: Verify API keys in ~/.openclaw/.env

### Logs

```bash
# OpenClaw logs
journalctl -u openclaw -f

# Execwall audit
tail -f /var/log/execwall/audit.jsonl

# Command output
cat /tmp/openclaw/*.log
```
