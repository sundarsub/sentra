# Execwall OR Gate

Budget-based model routing proxy for OpenRouter.

```
┌──────────┐     ┌──────────────┐     ┌────────────┐
│ OpenClaw │────▶│ Execwall OR    │────▶│ OpenRouter │
│ (Agent)  │     │ Gate :8080   │     │            │
└──────────┘     └──────────────┘     └────────────┘
                        │
                 ┌──────┴──────┐
                 │ policy.yaml │
                 │ spend.jsonl │
                 └─────────────┘
```

## Features

- **Budget-based model selection**: Automatically degrades to cheaper models as budget depletes
- **Tiered routing**: Configure multiple tiers (premium → mid → economy)
- **Spend tracking**: Persistent JSONL log for cost tracking
- **JetPatch integration**: API endpoints for external budget management
- **OpenAI-compatible**: Drop-in replacement for OpenRouter endpoint

## Quick Start

### 1. Install dependencies

```bash
pip install -r execwall-or-gate/requirements.txt
```

### 2. Set OpenRouter API key

```bash
export OPENROUTER_API_KEY="your-key-here"
```

### 3. Run the gate

```bash
python -m execwall-or-gate.main
```

### 4. Send requests

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'
```

## Configuration

Configuration is in `policy.yaml` under the `cost_routing` section:

```yaml
cost_routing:
  # JetPatch console integration (future)
  console:
    enabled: false
    url: "https://console.jetpatch.com"
    sync_interval_seconds: 30
    api_key: "${JETPATCH_API_KEY}"

  # Spend tracking
  spend_log: "./spend.jsonl"

  # OpenRouter settings
  openrouter:
    base_url: "https://openrouter.ai/api/v1"
    api_key: "${OPENROUTER_API_KEY}"
    timeout_seconds: 120

  agents:
    agent-1:
      budget_total: 50.00
      budget_spent: 0.00
      budget_source: local
      period: daily
      hard_cap: true
      tiers:
        - threshold: 0.80    # >80% remaining
          models:
            - "anthropic/claude-3.5-sonnet"
            - "openai/gpt-4o"
        - threshold: 0.30    # 30-80% remaining
          models:
            - "anthropic/claude-3-haiku"
            - "openai/gpt-4o-mini"
        - threshold: 0.00    # <30% remaining
          models:
            - "mistralai/mistral-7b-instruct"
```

### Tier Logic

| Budget Remaining | Models Used |
|------------------|-------------|
| > 80% | Premium (claude-3.5-sonnet, gpt-4o) |
| 30-80% | Mid-tier (claude-3-haiku, gpt-4o-mini) |
| < 30% | Economy (mistral-7b-instruct) |
| 0% (hard_cap=true) | 402 error - budget exhausted |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | OpenAI-compatible chat proxy |
| `/api/health` | GET | Health check |
| `/api/spend/{agent_id}` | GET | Get spend for agent |
| `/api/spend` | GET | Get spend for all agents |
| `/api/budget/{agent_id}` | POST | Update budget (JetPatch) |
| `/api/reset/{agent_id}` | POST | Reset spend for agent |
| `/api/reload` | POST | Reload config from disk |

### Request Headers

| Header | Description |
|--------|-------------|
| `X-Agent-ID` | Agent identifier (defaults to "default") |
| `Authorization` | Passed to OpenRouter if no API key in config |

### Response Metadata

Responses include `_execwall` metadata:

```json
{
  "id": "gen-...",
  "model": "anthropic/claude-3.5-sonnet",
  "choices": [...],
  "usage": {"total_tokens": 100, "cost": 0.0015},
  "_execwall": {
    "agent_id": "agent-1",
    "cost": 0.0015,
    "budget_remaining": 49.9985,
    "models_allowed": ["anthropic/claude-3.5-sonnet", "openai/gpt-4o"]
  }
}
```

## Testing with Mock Server

For testing without real API calls, use the included mock OpenRouter server.

### Terminal 1: Start mock server

```bash
python -m execwall-or-gate.mock_openrouter
```

Mock server runs on port 9000 and logs all requests to `openrouter_requests.log`.

### Terminal 2: Update config and start gate

Edit `policy.yaml` to use mock:

```yaml
openrouter:
  base_url: "http://localhost:9000/v1"    # Mock server
  api_key: "${OPENROUTER_API_KEY}"
```

Then start the gate:

```bash
OPENROUTER_API_KEY="test-key" python -m execwall-or-gate.main
```

### Terminal 3: Run tests

```bash
# Test chat completion
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'

# Check spend
curl http://localhost:8080/api/spend/agent-1

# Simulate budget update from JetPatch
curl -X POST http://localhost:8080/api/budget/agent-1 \
  -H "Content-Type: application/json" \
  -d '{"budget_spent": 40.00}'

# Test with reduced budget (should use mid-tier models)
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "What tier?"}]}'

# Exhaust budget
curl -X POST http://localhost:8080/api/budget/agent-1 \
  -H "Content-Type: application/json" \
  -d '{"budget_spent": 50.00}'

# Test exhausted budget (should return 402)
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{"messages": [{"role": "user", "content": "Hello"}]}'

# Reset spend
curl -X POST http://localhost:8080/api/reset/agent-1
```

### Check mock logs

```bash
cat openrouter_requests.log
```

Shows exactly what was sent to OpenRouter:

```json
{
  "model": "openrouter/auto",
  "models": ["anthropic/claude-3.5-sonnet", "openai/gpt-4o"],
  "route": "fallback",
  "messages": [...]
}
```

## Architecture with OpenClaw

When running with Execwall's seccomp-locked OpenClaw:

```
┌─────────────────────────────────────────────────────────────┐
│                    LOOPBACK (127.0.0.1)                     │
│                                                             │
│  ┌──────────┐                                               │
│  │ OpenClaw │──┬──▶ Execwall      :9999  (code execution)     │
│  │ (locked) │  │                                            │
│  └──────────┘  └──▶ OR Gate     :8080  (LLM requests)       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                           │
                           ✗ Cannot reach internet directly
                           │
              ┌────────────▼────────────┐
              │  OR Gate forwards to    │
              │  OpenRouter externally  │
              └─────────────────────────┘
```

OpenClaw points its LLM client at `http://127.0.0.1:8080/v1/chat/completions`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENROUTER_API_KEY` | (required) | OpenRouter API key |
| `JETPATCH_API_KEY` | (optional) | JetPatch console API key |
| `CONFIG_PATH` | `./policy.yaml` | Path to config file |
| `ADAPTER_HOST` | `0.0.0.0` | Host to bind |
| `ADAPTER_PORT` | `8080` | Port to bind |

## Files

| File | Purpose |
|------|---------|
| `main.py` | FastAPI application |
| `config.py` | YAML config loading |
| `router.py` | Model selection logic |
| `spend.py` | Spend tracking |
| `mock_openrouter.py` | Mock server for testing |
| `spend.jsonl` | Append-only spend log (generated) |

## JetPatch Console Integration

The gate exposes APIs for JetPatch console to:

1. **Pull spend data**: `GET /api/spend/{agent_id}`
2. **Push budget updates**: `POST /api/budget/{agent_id}`

Future: Enable `console.enabled: true` in config for automatic sync.
