"""
Sentra OR Gate - Budget-based Model Routing for OpenRouter

OpenAI-compatible proxy that routes requests to OpenRouter
with budget-based model selection.

Endpoints:
    POST /v1/chat/completions  - Chat completions proxy
    GET  /api/health           - Health check
    GET  /api/spend/{agent_id} - Get spend for agent
    GET  /api/spend            - Get spend for all agents
    POST /api/budget/{agent_id} - Update budget (JetPatch console)
    POST /api/reset/{agent_id}  - Reset spend for agent

Usage:
    python -m sentra-or-gate.main
"""

import os
from typing import Optional

import httpx
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .config import get_config, reload_config
from .router import get_routing_info, is_budget_exhausted, select_models
from .spend import SpendTracker

# Initialize FastAPI app
app = FastAPI(
    title="Sentra OR Gate",
    description="Budget-based model routing for OpenRouter",
    version="0.1.0",
)

# Load configuration and initialize spend tracker
config = get_config()
tracker = SpendTracker(config)


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "sentra-or-gate",
        "agents": list(config.agents.keys()),
        "openrouter_url": config.openrouter.base_url,
    }


@app.get("/api/spend/{agent_id}")
async def get_spend(agent_id: str):
    """
    Get spend data for an agent.

    Used by JetPatch console to pull spend information.
    """
    data = tracker.get_spend(agent_id)
    if "error" in data:
        raise HTTPException(status_code=404, detail=data)
    return data


@app.get("/api/spend")
async def get_all_spend():
    """Get spend data for all agents."""
    return tracker.get_all_spend()


@app.post("/api/budget/{agent_id}")
async def update_budget(agent_id: str, request: Request):
    """
    Update budget for an agent.

    Used by JetPatch console to push budget updates.

    Body:
        {"budget_total": 100.0}
        or
        {"budget_total": 100.0, "budget_spent": 25.0}
    """
    body = await request.json()

    budget_total = body.get("budget_total")
    budget_spent = body.get("budget_spent")

    if budget_total is None and budget_spent is None:
        raise HTTPException(
            status_code=400,
            detail="budget_total or budget_spent required",
        )

    if not tracker.update_budget(agent_id, budget_total, budget_spent):
        raise HTTPException(status_code=404, detail="agent not found")

    return {
        "status": "updated",
        "agent_id": agent_id,
        "budget_total": config.agents[agent_id].budget_total,
        "budget_spent": config.agents[agent_id].budget_spent,
    }


@app.post("/api/reset/{agent_id}")
async def reset_spend(agent_id: str):
    """Reset spend for an agent (period reset)."""
    if not tracker.reset_spend(agent_id):
        raise HTTPException(status_code=404, detail="agent not found")

    return {
        "status": "reset",
        "agent_id": agent_id,
        "budget_spent": 0.0,
    }


@app.post("/api/reload")
async def reload():
    """Reload configuration from disk."""
    global config, tracker
    config = reload_config()
    tracker = SpendTracker(config)
    return {
        "status": "reloaded",
        "agents": list(config.agents.keys()),
    }


@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    x_agent_id: Optional[str] = Header(None, alias="X-Agent-ID"),
    authorization: Optional[str] = Header(None),
):
    """
    OpenAI-compatible chat completions proxy.

    Headers:
        X-Agent-ID: Agent identifier (defaults to "default")
        Authorization: Passed through to OpenRouter if no API key configured

    Request body is forwarded to OpenRouter with modified model selection.
    Response includes _sentra metadata with spend info.
    """
    body = await request.json()
    agent_id = x_agent_id or "default"

    # Get agent config
    agent = config.agents.get(agent_id)
    if not agent:
        agent = config.agents.get("default")
        if not agent:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unknown_agent",
                    "agent_id": agent_id,
                    "available_agents": list(config.agents.keys()),
                },
            )
        agent_id = "default"

    # Check budget exhaustion
    if is_budget_exhausted(agent):
        routing = get_routing_info(agent)
        raise HTTPException(
            status_code=402,
            detail={
                "error": "budget_exhausted",
                "agent_id": agent_id,
                **routing,
            },
        )

    # Select models based on budget tier
    allowed_models = select_models(agent)

    # Prepare request for OpenRouter
    # Use "openrouter/auto" with models list for auto-routing
    original_model = body.get("model", "")
    body["model"] = "openrouter/auto"
    body["models"] = allowed_models
    body["route"] = "fallback"  # Fallback through models list

    # Determine API key - prefer config, then fall back to Authorization header
    api_key = config.openrouter.api_key
    if not api_key and authorization:
        # Use passed-through authorization
        api_key = authorization.replace("Bearer ", "")

    # For local testing, allow requests without auth if config has API key
    if not api_key:
        # Last resort: check for a mock/test key
        api_key = os.environ.get("OPENROUTER_API_KEY", "")

    # Forward to OpenRouter
    async with httpx.AsyncClient(timeout=config.openrouter.timeout_seconds) as client:
        try:
            response = await client.post(
                f"{config.openrouter.base_url}/chat/completions",
                json=body,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "HTTP-Referer": "https://sentra.dev",
                    "X-Title": "Sentra OR Gate",
                    "Content-Type": "application/json",
                },
            )
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail="OpenRouter request timed out",
            )
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=502,
                detail=f"OpenRouter request failed: {str(e)}",
            )

        # Handle non-200 responses
        if response.status_code != 200:
            return JSONResponse(
                status_code=response.status_code,
                content=response.json(),
            )

        result = response.json()

    # Extract cost from response
    usage = result.get("usage", {})
    cost = usage.get("cost", 0)

    # If cost not in response, estimate from tokens
    if cost == 0 and "total_tokens" in usage:
        # Rough estimate: varies by model, use conservative estimate
        cost = usage["total_tokens"] * 0.00001

    # Record spend
    if cost > 0:
        tracker.record_spend(
            agent_id=agent_id,
            cost=cost,
            model=result.get("model", "unknown"),
            tokens=usage.get("total_tokens", 0),
            request_id=result.get("id"),
        )

    # Add Sentra metadata to response
    result["_sentra"] = {
        "agent_id": agent_id,
        "cost": round(cost, 6),
        "budget_remaining": round(agent.budget_total - agent.budget_spent - cost, 6),
        "models_allowed": allowed_models,
        "original_model": original_model,
    }

    return result


def main():
    """Run the adapter server."""
    host = os.environ.get("ADAPTER_HOST", "0.0.0.0")
    port = int(os.environ.get("ADAPTER_PORT", "8080"))

    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║                    SENTRA OR GATE                             ║
║           Budget-based Routing for OpenRouter                 ║
╠═══════════════════════════════════════════════════════════════╣
║  Endpoint: http://{host}:{port}/v1/chat/completions{' ' * (16 - len(str(port)))}║
║  Health:   http://{host}:{port}/api/health{' ' * (22 - len(str(port)))}║
║                                                               ║
║  Agents: {', '.join(config.agents.keys()):<52} ║
║  OpenRouter: {config.openrouter.base_url:<44} ║
╚═══════════════════════════════════════════════════════════════╝
""")

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
