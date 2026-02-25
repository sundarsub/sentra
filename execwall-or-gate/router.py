"""
Model selection logic for budget-based routing.

Selects allowed models based on remaining budget percentage.
"""

from .config import Agent


def get_remaining_budget(agent: Agent) -> float:
    """Calculate remaining budget in dollars."""
    return agent.budget_total - agent.budget_spent


def get_budget_percentage(agent: Agent) -> float:
    """
    Calculate remaining budget as percentage (0.0 to 1.0).

    Returns:
        Float between 0.0 and 1.0 representing remaining budget.
        Returns 0.0 if budget_total is zero or negative.
    """
    if agent.budget_total <= 0:
        return 0.0
    remaining = get_remaining_budget(agent)
    if remaining <= 0:
        return 0.0
    return remaining / agent.budget_total


def select_models(agent: Agent) -> list[str]:
    """
    Select allowed models based on budget tier.

    Tiers are evaluated in order. First tier where remaining budget
    percentage >= threshold is selected.

    Args:
        agent: Agent configuration with budget and tiers

    Returns:
        List of allowed model identifiers for OpenRouter
    """
    pct = get_budget_percentage(agent)

    # Find first tier where remaining >= threshold
    for tier in agent.tiers:
        if pct >= tier.threshold:
            return tier.models

    # Fallback to last (cheapest) tier
    if agent.tiers:
        return agent.tiers[-1].models

    return []


def is_budget_exhausted(agent: Agent) -> bool:
    """
    Check if budget is exhausted and requests should be blocked.

    Returns:
        True if hard_cap is enabled and budget is exhausted.
        False otherwise (requests continue with cheapest tier).
    """
    if not agent.hard_cap:
        return False
    return get_remaining_budget(agent) <= 0


def get_routing_info(agent: Agent) -> dict:
    """
    Get full routing information for an agent.

    Returns:
        Dictionary with budget status and selected models.
    """
    remaining = get_remaining_budget(agent)
    pct = get_budget_percentage(agent)
    models = select_models(agent)
    exhausted = is_budget_exhausted(agent)

    # Find which tier we're in
    current_tier = None
    for i, tier in enumerate(agent.tiers):
        if pct >= tier.threshold:
            current_tier = i
            break

    return {
        "budget_total": agent.budget_total,
        "budget_spent": agent.budget_spent,
        "budget_remaining": remaining,
        "budget_percentage": round(pct * 100, 2),
        "current_tier": current_tier,
        "models_allowed": models,
        "hard_cap": agent.hard_cap,
        "exhausted": exhausted,
    }
