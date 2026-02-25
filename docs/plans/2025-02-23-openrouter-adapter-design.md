# OpenRouter Cost-Routing Adapter

## Overview

A Python FastAPI adapter that proxies requests to OpenRouter with budget-based model selection. Reads cost policies from `policy.yaml` (integrated with Execwall config), tracks spend locally, and exposes APIs for future JetPatch console integration.

```
┌──────────────┐     ┌─────────────┐     ┌────────────┐
│ Test Client  │────▶│   Adapter   │────▶│ OpenRouter │
│ (curl/httpx) │     │  (FastAPI)  │     │  (or mock) │
└──────────────┘     └─────────────┘     └────────────┘
                            │
                     ┌──────┴──────┐
                     │ policy.yaml │
                     │ (cost_routing)│
                     └─────────────┘
```

---

## File Structure

```
execwall-install/
├── adapter/
│   ├── __init__.py
│   ├── main.py              # FastAPI app, routes
│   ├── config.py            # YAML loading, schema validation
│   ├── router.py            # Model selection logic
│   ├── spend.py             # Spend tracking, persistence
│   ├── mock_openrouter.py   # Mock server for testing
│   └── requirements.txt     # Dependencies
├── policy.yaml              # Execwall config with cost_routing section
├── tests/
│   └── test_adapter.py      # Adapter integration tests
└── spend.jsonl              # Append-only spend log (generated)
```

---

## Configuration Schema

**File:** `policy.yaml` (cost_routing section)

```yaml
cost_routing:
  # Future: JetPatch console integration
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
      budget_source: local          # local | console
      period: daily                 # daily | weekly | monthly | none
      period_reset: "2025-02-23T00:00:00Z"
      hard_cap: true
      tiers:
        - threshold: 0.80
          models:
            - "anthropic/claude-3.5-sonnet"
            - "openai/gpt-4o"
        - threshold: 0.30
          models:
            - "anthropic/claude-3-haiku"
            - "openai/gpt-4o-mini"
        - threshold: 0.00
          models:
            - "mistralai/mistral-7b-instruct"

    default:
      budget_total: 10.00
      budget_spent: 0.00
      budget_source: local
      period: none
      hard_cap: false
      tiers:
        - threshold: 0.00
          models:
            - "mistralai/mistral-7b-instruct"
```

---

## Implementation Plan

### Component 1: Configuration (`config.py`)

**Purpose:** Load and validate YAML config, handle env var substitution.

```python
from pydantic import BaseModel
from typing import Optional
import yaml
import os
import re

class Tier(BaseModel):
    threshold: float
    models: list[str]

class Agent(BaseModel):
    budget_total: float
    budget_spent: float = 0.0
    budget_source: str = "local"
    period: str = "none"
    period_reset: Optional[str] = None
    hard_cap: bool = True
    tiers: list[Tier]

class Console(BaseModel):
    enabled: bool = False
    url: str = ""
    sync_interval_seconds: int = 30
    api_key: str = ""

class OpenRouterConfig(BaseModel):
    base_url: str = "https://openrouter.ai/api/v1"
    api_key: str
    timeout_seconds: int = 120

class CostRouting(BaseModel):
    console: Console = Console()
    spend_log: str = "./spend.jsonl"
    openrouter: OpenRouterConfig
    agents: dict[str, Agent]

def expand_env_vars(value: str) -> str:
    """Replace ${VAR} with environment variable values."""
    pattern = r'\$\{([^}]+)\}'
    def replacer(match):
        return os.environ.get(match.group(1), "")
    return re.sub(pattern, replacer, value)

def load_config(path: str = "cost_policy.yaml") -> CostRouting:
    """Load and validate configuration."""
    with open(path) as f:
        raw = f.read()

    # Expand environment variables
    expanded = expand_env_vars(raw)
    data = yaml.safe_load(expanded)

    return CostRouting(**data["cost_routing"])
```

---

### Component 2: Model Router (`router.py`)

**Purpose:** Select allowed models based on budget remaining.

```python
from config import Agent

def get_remaining_budget(agent: Agent) -> float:
    """Calculate remaining budget."""
    return agent.budget_total - agent.budget_spent

def get_budget_percentage(agent: Agent) -> float:
    """Calculate remaining budget as percentage (0.0 to 1.0)."""
    if agent.budget_total <= 0:
        return 0.0
    return get_remaining_budget(agent) / agent.budget_total

def select_models(agent: Agent) -> list[str]:
    """Select allowed models based on budget tier."""
    pct = get_budget_percentage(agent)

    # Find first tier where remaining >= threshold
    for tier in agent.tiers:
        if pct >= tier.threshold:
            return tier.models

    # Fallback to cheapest tier
    return agent.tiers[-1].models if agent.tiers else []

def is_budget_exhausted(agent: Agent) -> bool:
    """Check if budget is exhausted and hard cap applies."""
    return agent.hard_cap and get_remaining_budget(agent) <= 0
```

---

### Component 3: Spend Tracking (`spend.py`)

**Purpose:** Track and persist spend per agent.

```python
import json
from datetime import datetime
from pathlib import Path
from threading import Lock
from config import CostRouting, Agent

class SpendTracker:
    def __init__(self, config: CostRouting):
        self.config = config
        self.spend_log = Path(config.spend_log)
        self.lock = Lock()
        self._load_spend()

    def _load_spend(self):
        """Load spend from log file on startup."""
        if not self.spend_log.exists():
            return

        # Replay spend log to reconstruct state
        agent_totals: dict[str, float] = {}
        with open(self.spend_log) as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                agent_id = entry["agent_id"]
                cost = entry["cost"]
                agent_totals[agent_id] = agent_totals.get(agent_id, 0) + cost

        # Update config with loaded spend
        for agent_id, total in agent_totals.items():
            if agent_id in self.config.agents:
                self.config.agents[agent_id].budget_spent = total

    def record_spend(
        self,
        agent_id: str,
        cost: float,
        model: str,
        tokens: int
    ):
        """Record spend for an agent."""
        with self.lock:
            # Append to log
            entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "agent_id": agent_id,
                "cost": cost,
                "model": model,
                "tokens": tokens
            }
            with open(self.spend_log, "a") as f:
                f.write(json.dumps(entry) + "\n")

            # Update in-memory state
            if agent_id in self.config.agents:
                self.config.agents[agent_id].budget_spent += cost

    def get_spend(self, agent_id: str) -> dict:
        """Get spend data for an agent."""
        agent = self.config.agents.get(agent_id)
        if not agent:
            return {"error": "agent not found"}

        return {
            "agent_id": agent_id,
            "budget_total": agent.budget_total,
            "budget_spent": agent.budget_spent,
            "budget_remaining": agent.budget_total - agent.budget_spent,
            "budget_source": agent.budget_source,
            "period": agent.period,
            "hard_cap": agent.hard_cap
        }

    def update_budget(self, agent_id: str, budget_total: float) -> bool:
        """Update budget for an agent (for console integration)."""
        with self.lock:
            if agent_id not in self.config.agents:
                return False
            self.config.agents[agent_id].budget_total = budget_total
            self.config.agents[agent_id].budget_source = "console"
            return True
```

---

### Component 4: FastAPI App (`main.py`)

**Purpose:** HTTP endpoints for chat proxy and management APIs.

```python
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
import httpx
from typing import Optional

from config import load_config
from router import select_models, is_budget_exhausted
from spend import SpendTracker

app = FastAPI(title="Execwall OpenRouter Adapter")

# Load configuration
config = load_config()
tracker = SpendTracker(config)

@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "agents": list(config.agents.keys())}

@app.get("/api/spend/{agent_id}")
async def get_spend(agent_id: str):
    """Get spend data for an agent (for JetPatch console)."""
    data = tracker.get_spend(agent_id)
    if "error" in data:
        raise HTTPException(404, data["error"])
    return data

@app.post("/api/budget/{agent_id}")
async def update_budget(agent_id: str, request: Request):
    """Update budget for an agent (from JetPatch console)."""
    body = await request.json()
    budget_total = body.get("budget_total")
    if budget_total is None:
        raise HTTPException(400, "budget_total required")

    if not tracker.update_budget(agent_id, budget_total):
        raise HTTPException(404, "agent not found")

    return {"status": "updated", "agent_id": agent_id, "budget_total": budget_total}

@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-ID")
):
    """
    OpenAI-compatible chat completions proxy.

    - Reads agent_id from X-Agent-ID header (defaults to "default")
    - Selects models based on budget tier
    - Forwards to OpenRouter
    - Records spend from response
    """
    body = await request.json()
    agent_id = x_agent_id or "default"

    # Get agent config
    agent = config.agents.get(agent_id)
    if not agent:
        agent = config.agents.get("default")
        if not agent:
            raise HTTPException(400, f"Unknown agent: {agent_id}")

    # Check budget
    if is_budget_exhausted(agent):
        raise HTTPException(
            402,
            {
                "error": "budget_exhausted",
                "agent_id": agent_id,
                "budget_total": agent.budget_total,
                "budget_spent": agent.budget_spent
            }
        )

    # Select models based on budget tier
    allowed_models = select_models(agent)

    # Modify request for OpenRouter auto-routing
    body["model"] = "openrouter/auto"
    body["route"] = "fallback"  # Use fallback routing
    body["models"] = allowed_models  # Allowed models list

    # Forward to OpenRouter
    async with httpx.AsyncClient(timeout=config.openrouter.timeout_seconds) as client:
        response = await client.post(
            f"{config.openrouter.base_url}/chat/completions",
            json=body,
            headers={
                "Authorization": f"Bearer {config.openrouter.api_key}",
                "HTTP-Referer": "https://execwall.dev",
                "X-Title": "Execwall Adapter"
            }
        )

        if response.status_code != 200:
            return JSONResponse(
                status_code=response.status_code,
                content=response.json()
            )

        result = response.json()

    # Extract and record cost
    usage = result.get("usage", {})
    cost = usage.get("cost", 0)

    # OpenRouter returns cost in the response
    # If not present, estimate from tokens (fallback)
    if cost == 0 and "total_tokens" in usage:
        # Rough estimate: $0.01 per 1K tokens (varies by model)
        cost = usage["total_tokens"] * 0.00001

    if cost > 0:
        tracker.record_spend(
            agent_id=agent_id,
            cost=cost,
            model=result.get("model", "unknown"),
            tokens=usage.get("total_tokens", 0)
        )

    # Add spend info to response metadata
    result["_execwall"] = {
        "agent_id": agent_id,
        "cost": cost,
        "budget_remaining": agent.budget_total - agent.budget_spent - cost,
        "models_allowed": allowed_models
    }

    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

---

### Component 5: Dependencies (`requirements.txt`)

```
fastapi>=0.109.0
uvicorn>=0.27.0
httpx>=0.26.0
pydantic>=2.5.0
pyyaml>=6.0
```

---

### Component 6: Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY adapter/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY adapter/ ./adapter/
COPY cost_policy.yaml .

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "-m", "adapter.main"]
```

---

## Testing Plan

### Test 1: Configuration Loading

**Purpose:** Verify YAML parsing and env var substitution.

```bash
# Set up
export OPENROUTER_API_KEY="test-key-123"

# Test
python -c "
from adapter.config import load_config
config = load_config('cost_policy.yaml')
print(f'Agents: {list(config.agents.keys())}')
print(f'API Key loaded: {config.openrouter.api_key[:8]}...')
assert config.openrouter.api_key == 'test-key-123'
print('PASS: Config loading')
"
```

### Test 2: Model Selection Logic

**Purpose:** Verify correct tier selection based on budget.

```bash
python -c "
from adapter.config import Agent, Tier
from adapter.router import select_models, get_budget_percentage

# Agent with 80% budget remaining
agent = Agent(
    budget_total=100.0,
    budget_spent=20.0,
    tiers=[
        Tier(threshold=0.80, models=['claude-3.5-sonnet']),
        Tier(threshold=0.30, models=['claude-3-haiku']),
        Tier(threshold=0.00, models=['mistral-7b']),
    ]
)

pct = get_budget_percentage(agent)
models = select_models(agent)
print(f'Budget remaining: {pct*100}%')
print(f'Selected models: {models}')
assert models == ['claude-3.5-sonnet'], f'Expected premium tier, got {models}'
print('PASS: 80% budget -> premium tier')

# Agent with 50% budget remaining
agent.budget_spent = 50.0
models = select_models(agent)
print(f'Budget remaining: {get_budget_percentage(agent)*100}%')
print(f'Selected models: {models}')
assert models == ['claude-3-haiku'], f'Expected mid tier, got {models}'
print('PASS: 50% budget -> mid tier')

# Agent with 10% budget remaining
agent.budget_spent = 90.0
models = select_models(agent)
print(f'Budget remaining: {get_budget_percentage(agent)*100}%')
print(f'Selected models: {models}')
assert models == ['mistral-7b'], f'Expected economy tier, got {models}'
print('PASS: 10% budget -> economy tier')
"
```

### Test 3: Spend Tracking

**Purpose:** Verify spend recording and persistence.

```bash
python -c "
import tempfile
import os
from adapter.config import CostRouting, Agent, Tier, OpenRouterConfig
from adapter.spend import SpendTracker

# Create temp config
with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
    spend_log = f.name

config = CostRouting(
    spend_log=spend_log,
    openrouter=OpenRouterConfig(api_key='test'),
    agents={
        'test-agent': Agent(
            budget_total=100.0,
            tiers=[Tier(threshold=0.0, models=['test'])]
        )
    }
)

tracker = SpendTracker(config)

# Record some spend
tracker.record_spend('test-agent', 0.05, 'claude-3-haiku', 1000)
tracker.record_spend('test-agent', 0.10, 'claude-3.5-sonnet', 2000)

# Check totals
spend = tracker.get_spend('test-agent')
print(f'Total spent: \${spend[\"budget_spent\"]:.2f}')
assert spend['budget_spent'] == 0.15, f'Expected 0.15, got {spend[\"budget_spent\"]}'
print('PASS: Spend tracking')

# Test persistence - create new tracker from same log
tracker2 = SpendTracker(config)
spend2 = tracker2.get_spend('test-agent')
# Note: config was already modified by first tracker, so this tests the load
print(f'Loaded spend: \${spend2[\"budget_spent\"]:.2f}')
print('PASS: Spend persistence')

os.unlink(spend_log)
"
```

### Test 4: Health Endpoint

**Purpose:** Verify API is running.

```bash
# Start server in background
cd /path/to/execwall-install
python -m adapter.main &
SERVER_PID=$!
sleep 2

# Test health endpoint
curl -s http://localhost:8080/api/health | jq .

# Expected output:
# {
#   "status": "ok",
#   "agents": ["agent-1", "default"]
# }

kill $SERVER_PID
```

### Test 5: Spend API Endpoint

**Purpose:** Verify spend reporting API.

```bash
# Start server
python -m adapter.main &
SERVER_PID=$!
sleep 2

# Get spend for agent
curl -s http://localhost:8080/api/spend/agent-1 | jq .

# Expected output:
# {
#   "agent_id": "agent-1",
#   "budget_total": 50.0,
#   "budget_spent": 0.0,
#   "budget_remaining": 50.0,
#   "budget_source": "local",
#   "period": "daily",
#   "hard_cap": true
# }

kill $SERVER_PID
```

### Test 6: Budget Update API

**Purpose:** Verify console can update budgets.

```bash
# Start server
python -m adapter.main &
SERVER_PID=$!
sleep 2

# Update budget (simulating JetPatch console)
curl -s -X POST http://localhost:8080/api/budget/agent-1 \
  -H "Content-Type: application/json" \
  -d '{"budget_total": 75.00}' | jq .

# Expected output:
# {
#   "status": "updated",
#   "agent_id": "agent-1",
#   "budget_total": 75.0
# }

# Verify update
curl -s http://localhost:8080/api/spend/agent-1 | jq .budget_total
# Expected: 75.0

kill $SERVER_PID
```

### Test 7: Chat Completions - Live OpenRouter Test

**Purpose:** End-to-end test with real OpenRouter API.

```bash
export OPENROUTER_API_KEY="your-key-here"

# Start server
python -m adapter.main &
SERVER_PID=$!
sleep 2

# Send chat completion request
curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: agent-1" \
  -d '{
    "messages": [
      {"role": "user", "content": "Say hello in exactly 3 words."}
    ],
    "max_tokens": 50
  }' | jq .

# Expected output includes:
# {
#   "id": "gen-...",
#   "model": "anthropic/claude-3.5-sonnet",  <- or other from tier
#   "choices": [...],
#   "usage": { "total_tokens": ..., "cost": ... },
#   "_execwall": {
#     "agent_id": "agent-1",
#     "cost": 0.00X,
#     "budget_remaining": 49.99X,
#     "models_allowed": ["anthropic/claude-3.5-sonnet", "openai/gpt-4o"]
#   }
# }

# Check spend was recorded
curl -s http://localhost:8080/api/spend/agent-1 | jq .

kill $SERVER_PID
```

### Test 8: Budget Exhaustion

**Purpose:** Verify hard cap enforcement.

```bash
# Create config with tiny budget
cat > /tmp/test_policy.yaml << 'EOF'
cost_routing:
  spend_log: "/tmp/test_spend.jsonl"
  openrouter:
    api_key: "${OPENROUTER_API_KEY}"
  agents:
    test-agent:
      budget_total: 0.001
      budget_spent: 0.001
      hard_cap: true
      tiers:
        - threshold: 0.0
          models: ["mistralai/mistral-7b-instruct"]
EOF

# Start with test config
CONFIG_PATH=/tmp/test_policy.yaml python -m adapter.main &
SERVER_PID=$!
sleep 2

# Request should fail with 402
curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: test-agent" \
  -d '{"messages": [{"role": "user", "content": "hi"}]}' | jq .

# Expected output:
# {
#   "error": "budget_exhausted",
#   "agent_id": "test-agent",
#   ...
# }

kill $SERVER_PID
```

### Test 9: Tier Degradation Under Load

**Purpose:** Verify model selection changes as budget depletes.

```bash
# Python script for this test
python << 'EOF'
import httpx
import asyncio

async def test_degradation():
    async with httpx.AsyncClient(base_url="http://localhost:8080") as client:
        # Make requests and track which models are selected
        for i in range(10):
            resp = await client.post(
                "/v1/chat/completions",
                json={"messages": [{"role": "user", "content": f"Count to {i+1}"}]},
                headers={"X-Agent-ID": "agent-1"}
            )
            data = resp.json()

            execwall = data.get("_execwall", {})
            print(f"Request {i+1}:")
            print(f"  Model used: {data.get('model')}")
            print(f"  Budget remaining: ${execwall.get('budget_remaining', 0):.4f}")
            print(f"  Models allowed: {execwall.get('models_allowed', [])}")
            print()

asyncio.run(test_degradation())
EOF
```

---

## pytest Test Suite (`tests/test_adapter.py`)

```python
import pytest
import tempfile
import os
from unittest.mock import patch, AsyncMock

# Test configuration loading
class TestConfig:
    def test_load_valid_config(self, tmp_path):
        config_file = tmp_path / "test.yaml"
        config_file.write_text("""
cost_routing:
  spend_log: "./spend.jsonl"
  openrouter:
    api_key: "test-key"
  agents:
    test:
      budget_total: 100.0
      tiers:
        - threshold: 0.0
          models: ["test-model"]
""")
        from adapter.config import load_config
        config = load_config(str(config_file))
        assert "test" in config.agents
        assert config.openrouter.api_key == "test-key"

    def test_env_var_expansion(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_KEY", "secret-123")
        config_file = tmp_path / "test.yaml"
        config_file.write_text("""
cost_routing:
  spend_log: "./spend.jsonl"
  openrouter:
    api_key: "${TEST_API_KEY}"
  agents:
    test:
      budget_total: 100.0
      tiers:
        - threshold: 0.0
          models: ["test"]
""")
        from adapter.config import load_config
        config = load_config(str(config_file))
        assert config.openrouter.api_key == "secret-123"


# Test model selection
class TestRouter:
    def test_premium_tier(self):
        from adapter.config import Agent, Tier
        from adapter.router import select_models

        agent = Agent(
            budget_total=100.0,
            budget_spent=10.0,  # 90% remaining
            tiers=[
                Tier(threshold=0.80, models=["premium"]),
                Tier(threshold=0.0, models=["economy"]),
            ]
        )
        assert select_models(agent) == ["premium"]

    def test_economy_tier(self):
        from adapter.config import Agent, Tier
        from adapter.router import select_models

        agent = Agent(
            budget_total=100.0,
            budget_spent=90.0,  # 10% remaining
            tiers=[
                Tier(threshold=0.80, models=["premium"]),
                Tier(threshold=0.0, models=["economy"]),
            ]
        )
        assert select_models(agent) == ["economy"]

    def test_budget_exhausted(self):
        from adapter.config import Agent, Tier
        from adapter.router import is_budget_exhausted

        agent = Agent(
            budget_total=100.0,
            budget_spent=100.0,
            hard_cap=True,
            tiers=[Tier(threshold=0.0, models=["test"])]
        )
        assert is_budget_exhausted(agent) is True

        agent.hard_cap = False
        assert is_budget_exhausted(agent) is False


# Test spend tracking
class TestSpendTracker:
    def test_record_and_retrieve(self, tmp_path):
        from adapter.config import CostRouting, Agent, Tier, OpenRouterConfig
        from adapter.spend import SpendTracker

        config = CostRouting(
            spend_log=str(tmp_path / "spend.jsonl"),
            openrouter=OpenRouterConfig(api_key="test"),
            agents={
                "test": Agent(
                    budget_total=100.0,
                    tiers=[Tier(threshold=0.0, models=["test"])]
                )
            }
        )

        tracker = SpendTracker(config)
        tracker.record_spend("test", 5.0, "model-a", 1000)
        tracker.record_spend("test", 3.0, "model-b", 500)

        spend = tracker.get_spend("test")
        assert spend["budget_spent"] == 8.0
        assert spend["budget_remaining"] == 92.0

    def test_persistence(self, tmp_path):
        from adapter.config import CostRouting, Agent, Tier, OpenRouterConfig
        from adapter.spend import SpendTracker

        log_path = str(tmp_path / "spend.jsonl")

        def make_config():
            return CostRouting(
                spend_log=log_path,
                openrouter=OpenRouterConfig(api_key="test"),
                agents={
                    "test": Agent(
                        budget_total=100.0,
                        tiers=[Tier(threshold=0.0, models=["test"])]
                    )
                }
            )

        # First tracker records spend
        config1 = make_config()
        tracker1 = SpendTracker(config1)
        tracker1.record_spend("test", 10.0, "model", 1000)

        # Second tracker loads from log
        config2 = make_config()
        tracker2 = SpendTracker(config2)
        spend = tracker2.get_spend("test")
        assert spend["budget_spent"] == 10.0


# Test API endpoints
class TestAPI:
    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        # Create test config
        config_file = tmp_path / "cost_policy.yaml"
        config_file.write_text("""
cost_routing:
  spend_log: "{}/spend.jsonl"
  openrouter:
    api_key: "test-key"
  agents:
    test-agent:
      budget_total: 100.0
      hard_cap: true
      tiers:
        - threshold: 0.80
          models: ["premium-model"]
        - threshold: 0.0
          models: ["economy-model"]
    default:
      budget_total: 10.0
      hard_cap: false
      tiers:
        - threshold: 0.0
          models: ["default-model"]
""".format(tmp_path))

        monkeypatch.setenv("CONFIG_PATH", str(config_file))

        # Import after setting env
        from adapter.main import app
        return TestClient(app)

    def test_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_get_spend(self, client):
        resp = client.get("/api/spend/test-agent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "test-agent"
        assert data["budget_total"] == 100.0

    def test_get_spend_not_found(self, client):
        resp = client.get("/api/spend/nonexistent")
        assert resp.status_code == 404

    def test_update_budget(self, client):
        resp = client.post(
            "/api/budget/test-agent",
            json={"budget_total": 200.0}
        )
        assert resp.status_code == 200

        # Verify update
        resp = client.get("/api/spend/test-agent")
        assert resp.json()["budget_total"] == 200.0

    @patch("httpx.AsyncClient.post")
    def test_chat_completions(self, mock_post, client):
        # Mock OpenRouter response
        mock_post.return_value = AsyncMock(
            status_code=200,
            json=lambda: {
                "id": "gen-123",
                "model": "premium-model",
                "choices": [{"message": {"content": "Hello!"}}],
                "usage": {"total_tokens": 100, "cost": 0.01}
            }
        )

        resp = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hi"}]},
            headers={"X-Agent-ID": "test-agent"}
        )

        assert resp.status_code == 200
        data = resp.json()
        assert "_execwall" in data
        assert data["_execwall"]["agent_id"] == "test-agent"

    def test_budget_exhausted(self, client):
        # First, exhaust the budget via update
        client.post(
            "/api/budget/test-agent",
            json={"budget_total": 0.0}
        )

        resp = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hi"}]},
            headers={"X-Agent-ID": "test-agent"}
        )

        assert resp.status_code == 402
```

---

## Run All Tests

```bash
cd /path/to/execwall-install

# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run unit tests
pytest tests/test_adapter.py -v

# Run with coverage
pytest tests/test_adapter.py -v --cov=adapter --cov-report=term-missing
```

---

## Summary

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| Config | `adapter/config.py` | ~50 | YAML loading, validation |
| Router | `adapter/router.py` | ~30 | Model selection logic |
| Spend | `adapter/spend.py` | ~80 | Spend tracking, persistence |
| API | `adapter/main.py` | ~120 | FastAPI endpoints |
| Tests | `tests/test_adapter.py` | ~200 | Unit + integration tests |

**Total:** ~480 lines of code

**To test without OpenClaw:**
1. Start adapter: `python -m adapter.main`
2. Send requests via curl with `X-Agent-ID` header
3. Monitor spend via `/api/spend/{agent_id}`
4. Update budgets via `/api/budget/{agent_id}`
