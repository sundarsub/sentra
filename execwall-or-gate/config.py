"""
Configuration loading for Execwall OpenRouter Adapter.

Loads cost_routing section from policy.yaml with env var substitution.
"""

import os
import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel


class Tier(BaseModel):
    """Budget tier with threshold and allowed models."""
    threshold: float
    models: list[str]


class Agent(BaseModel):
    """Agent budget configuration."""
    budget_total: float
    budget_spent: float = 0.0
    budget_source: str = "local"  # local | console
    period: str = "none"  # daily | weekly | monthly | none
    period_reset: Optional[str] = None
    hard_cap: bool = True
    tiers: list[Tier]


class Console(BaseModel):
    """JetPatch console integration settings."""
    enabled: bool = False
    url: str = ""
    sync_interval_seconds: int = 30
    api_key: str = ""


class OpenRouterConfig(BaseModel):
    """OpenRouter API settings."""
    base_url: str = "https://openrouter.ai/api/v1"
    api_key: str = ""
    timeout_seconds: int = 120


class CostRouting(BaseModel):
    """Cost routing configuration."""
    console: Console = Console()
    spend_log: str = "./spend.jsonl"
    openrouter: OpenRouterConfig
    agents: dict[str, Agent]


def expand_env_vars(value: str) -> str:
    """Replace ${VAR} with environment variable values."""
    pattern = r'\$\{([^}]+)\}'

    def replacer(match):
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    return re.sub(pattern, replacer, value)


def load_config(path: Optional[str] = None) -> CostRouting:
    """
    Load cost_routing configuration from policy.yaml.

    Args:
        path: Path to policy.yaml. Defaults to CONFIG_PATH env var or ./policy.yaml

    Returns:
        CostRouting configuration object
    """
    if path is None:
        path = os.environ.get("CONFIG_PATH", "./policy.yaml")

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    # Read and expand environment variables
    raw = config_path.read_text()
    expanded = expand_env_vars(raw)

    # Parse YAML
    data = yaml.safe_load(expanded)

    if "cost_routing" not in data:
        raise ValueError("No 'cost_routing' section found in config")

    return CostRouting(**data["cost_routing"])


# Singleton config instance
_config: Optional[CostRouting] = None


def get_config() -> CostRouting:
    """Get or load the configuration singleton."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config() -> CostRouting:
    """Force reload configuration from disk."""
    global _config
    _config = load_config()
    return _config
