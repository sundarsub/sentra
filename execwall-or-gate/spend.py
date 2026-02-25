"""
Spend tracking and persistence for the adapter.

Maintains an append-only JSONL log for crash recovery and
updates in-memory budget_spent values.
"""

import json
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Optional

from .config import CostRouting


class SpendTracker:
    """
    Tracks and persists spend per agent.

    Uses an append-only JSONL log for durability. On startup,
    replays the log to reconstruct current spend totals.
    """

    def __init__(self, config: CostRouting):
        """
        Initialize spend tracker.

        Args:
            config: Cost routing configuration
        """
        self.config = config
        self.spend_log = Path(config.spend_log)
        self.lock = Lock()
        self._load_spend()

    def _load_spend(self) -> None:
        """Load spend from log file on startup."""
        if not self.spend_log.exists():
            return

        # Replay spend log to reconstruct state
        agent_totals: dict[str, float] = {}

        with open(self.spend_log) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    agent_id = entry.get("agent_id")
                    cost = entry.get("cost", 0)
                    if agent_id:
                        agent_totals[agent_id] = agent_totals.get(agent_id, 0) + cost
                except json.JSONDecodeError:
                    continue  # Skip malformed lines

        # Update config with loaded spend
        for agent_id, total in agent_totals.items():
            if agent_id in self.config.agents:
                self.config.agents[agent_id].budget_spent = total

    def record_spend(
        self,
        agent_id: str,
        cost: float,
        model: str,
        tokens: int,
        request_id: Optional[str] = None,
    ) -> None:
        """
        Record spend for an agent.

        Args:
            agent_id: Agent identifier
            cost: Cost in dollars
            model: Model that was used
            tokens: Total tokens consumed
            request_id: Optional request ID for correlation
        """
        with self.lock:
            # Create log entry
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "agent_id": agent_id,
                "cost": cost,
                "model": model,
                "tokens": tokens,
            }
            if request_id:
                entry["request_id"] = request_id

            # Append to log
            with open(self.spend_log, "a") as f:
                f.write(json.dumps(entry) + "\n")

            # Update in-memory state
            if agent_id in self.config.agents:
                self.config.agents[agent_id].budget_spent += cost

    def get_spend(self, agent_id: str) -> dict:
        """
        Get spend data for an agent.

        Args:
            agent_id: Agent identifier

        Returns:
            Dictionary with budget info or error
        """
        agent = self.config.agents.get(agent_id)
        if not agent:
            return {"error": "agent_not_found", "agent_id": agent_id}

        remaining = agent.budget_total - agent.budget_spent

        return {
            "agent_id": agent_id,
            "budget_total": agent.budget_total,
            "budget_spent": round(agent.budget_spent, 6),
            "budget_remaining": round(remaining, 6),
            "budget_source": agent.budget_source,
            "period": agent.period,
            "period_reset": agent.period_reset,
            "hard_cap": agent.hard_cap,
        }

    def get_all_spend(self) -> dict:
        """
        Get spend data for all agents.

        Returns:
            Dictionary mapping agent_id to spend data
        """
        return {
            agent_id: self.get_spend(agent_id)
            for agent_id in self.config.agents.keys()
        }

    def update_budget(
        self,
        agent_id: str,
        budget_total: Optional[float] = None,
        budget_spent: Optional[float] = None,
    ) -> bool:
        """
        Update budget for an agent (for JetPatch console integration).

        Args:
            agent_id: Agent identifier
            budget_total: New total budget (optional)
            budget_spent: New spent amount (optional, for sync)

        Returns:
            True if updated, False if agent not found
        """
        with self.lock:
            if agent_id not in self.config.agents:
                return False

            agent = self.config.agents[agent_id]

            if budget_total is not None:
                agent.budget_total = budget_total

            if budget_spent is not None:
                agent.budget_spent = budget_spent

            # Mark as console-managed if budget was updated
            agent.budget_source = "console"

            return True

    def reset_spend(self, agent_id: str) -> bool:
        """
        Reset spend for an agent (for period resets).

        Args:
            agent_id: Agent identifier

        Returns:
            True if reset, False if agent not found
        """
        with self.lock:
            if agent_id not in self.config.agents:
                return False

            # Log the reset
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "agent_id": agent_id,
                "event": "reset",
                "previous_spent": self.config.agents[agent_id].budget_spent,
            }
            with open(self.spend_log, "a") as f:
                f.write(json.dumps(entry) + "\n")

            # Reset in-memory
            self.config.agents[agent_id].budget_spent = 0.0
            self.config.agents[agent_id].period_reset = datetime.utcnow().isoformat() + "Z"

            return True
