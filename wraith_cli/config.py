"""
WRAITH configuration system.

Centralised config with LLM, RL, and scan settings.
Persists to ~/.wraith/config.json.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class RLStrategy(str, Enum):
    EPSILON_GREEDY = "epsilon_greedy"
    UCB1 = "ucb1"
    THOMPSON = "thompson"


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: LLMProvider = LLMProvider.OPENAI
    model: str = "gpt-4o"
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.2
    max_tokens: int = 4096

    def resolve_api_key(self) -> str:
        """Resolve API key from config or environment."""
        if self.api_key:
            return self.api_key
        env_map = {
            LLMProvider.OPENAI: "OPENAI_API_KEY",
            LLMProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
        }
        env_var = env_map.get(self.provider, "")
        return os.environ.get(env_var, "")


@dataclass
class RLConfig:
    """Reinforcement learning configuration."""
    enabled: bool = True
    strategy: RLStrategy = RLStrategy.UCB1
    epsilon: float = 0.15
    exploration_decay: float = 0.995
    learning_rate: float = 0.1
    policy_path: Path = field(default_factory=lambda: Path.home() / ".wraith" / "rl_policy.json")


@dataclass
class ScanConfig:
    """Scan configuration."""
    max_files: int = 500
    max_depth: int = 10
    timeout_seconds: int = 300
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build",
    ])
    parallel_agents: int = 4


@dataclass
class WraithConfig:
    """Top-level configuration."""
    llm: LLMConfig = field(default_factory=LLMConfig)
    rl: RLConfig = field(default_factory=RLConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    nvd_api_key: str = ""
    config_path: Path = field(default_factory=lambda: Path.home() / ".wraith" / "config.json")

    def save(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "llm": {"provider": self.llm.provider.value, "model": self.llm.model},
            "rl": {"strategy": self.rl.strategy.value, "epsilon": self.rl.epsilon},
        }
        self.config_path.write_text(json.dumps(data, indent=2))

    def load(self) -> None:
        if not self.config_path.exists():
            return
        try:
            data = json.loads(self.config_path.read_text())
            if "llm" in data:
                self.llm.provider = LLMProvider(data["llm"].get("provider", "openai"))
                self.llm.model = data["llm"].get("model", "gpt-4o")
            if "rl" in data:
                self.rl.strategy = RLStrategy(data["rl"].get("strategy", "ucb1"))
                self.rl.epsilon = data["rl"].get("epsilon", 0.15)
        except Exception:
            pass
