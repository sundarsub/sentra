"""
Mock OpenRouter Server
======================
Logs all incoming requests to a file and returns fake responses.
Used for testing the adapter without real API calls.

Usage:
    python -m adapter.mock_openrouter

Logs to: ./openrouter_requests.log
Listens on: http://localhost:9000
"""

from fastapi import FastAPI, Request
from datetime import datetime
import json
import random
import uvicorn

app = FastAPI(title="Mock OpenRouter")

LOG_FILE = "./openrouter_requests.log"

# Fake costs per model ($ per 1K tokens)
MODEL_COSTS = {
    "anthropic/claude-3.5-sonnet": 0.015,
    "anthropic/claude-3-haiku": 0.00025,
    "openai/gpt-4o": 0.01,
    "openai/gpt-4o-mini": 0.00015,
    "mistralai/mistral-7b-instruct": 0.00007,
}


def log_request(method: str, path: str, headers: dict, body: dict):
    """Append request details to log file."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": method,
        "path": path,
        "headers": {k: v for k, v in headers.items() if k.lower() != "authorization"},
        "body": body,
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry, indent=2) + "\n" + "=" * 60 + "\n")

    # Also print to console
    print(f"\n{'='*60}")
    print(f"[{entry['timestamp']}] {method} {path}")
    print(f"Headers: {json.dumps(entry['headers'], indent=2)}")
    print(f"Body: {json.dumps(body, indent=2)}")
    print(f"{'='*60}\n")


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """Mock chat completions endpoint."""
    body = await request.json()
    headers = dict(request.headers)

    log_request("POST", "/v1/chat/completions", headers, body)

    # Extract what adapter sent
    requested_model = body.get("model", "unknown")
    allowed_models = body.get("models", [])
    messages = body.get("messages", [])

    # Pick a model from allowed list (or use requested)
    if allowed_models:
        selected_model = allowed_models[0]  # Pick first allowed
    else:
        selected_model = requested_model

    # Generate fake response
    prompt_tokens = sum(len(m.get("content", "")) // 4 for m in messages)
    completion_tokens = random.randint(20, 100)
    total_tokens = prompt_tokens + completion_tokens

    # Calculate fake cost
    cost_per_1k = MODEL_COSTS.get(selected_model, 0.001)
    cost = (total_tokens / 1000) * cost_per_1k

    response = {
        "id": f"gen-mock-{random.randint(1000, 9999)}",
        "object": "chat.completion",
        "created": int(datetime.utcnow().timestamp()),
        "model": selected_model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"[MOCK RESPONSE from {selected_model}] I received your message. Allowed models were: {allowed_models}"
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "cost": round(cost, 6)
        }
    }

    # Log what we're returning
    print(f">>> Responding with model: {selected_model}")
    print(f">>> Cost: ${cost:.6f}")
    print(f">>> Allowed models received: {allowed_models}")

    return response


@app.get("/v1/models")
async def list_models(request: Request):
    """Mock models list endpoint."""
    log_request("GET", "/v1/models", dict(request.headers), {})

    return {
        "data": [
            {"id": model, "object": "model"}
            for model in MODEL_COSTS.keys()
        ]
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mock-openrouter"}


if __name__ == "__main__":
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║              MOCK OPENROUTER SERVER                       ║
╠═══════════════════════════════════════════════════════════╣
║  Endpoint: http://localhost:9000/v1/chat/completions      ║
║  Log file: {LOG_FILE:<44} ║
║                                                           ║
║  This server logs all requests and returns fake responses ║
║  Use it to test the adapter without real API calls        ║
╚═══════════════════════════════════════════════════════════╝
""")
    uvicorn.run(app, host="0.0.0.0", port=9000)
