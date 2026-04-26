"""
Experience replay buffer for offline policy improvement.

Stores (state, action, reward, next_state) transitions from past scans.
Enables batch learning and counterfactual analysis.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Experience:
    """A single experience transition."""
    state: dict[str, Any]       # Target fingerprint, scan phase, findings so far
    action: str                 # Vulnerability class explored
    reward: float               # Reward received
    next_state: dict[str, Any]  # Updated state after action
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "action": self.action,
            "reward": self.reward,
            "next_state": self.next_state,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Experience":
        return cls(
            state=data["state"],
            action=data["action"],
            reward=data["reward"],
            next_state=data["next_state"],
            metadata=data.get("metadata", {}),
        )


class ExperienceReplay:
    """Replay buffer for storing and sampling past scan experiences.

    Features:
    - Prioritised replay (higher reward experiences sampled more often)
    - Batch sampling for policy updates
    - Persistence to disk for cross-session learning
    """

    def __init__(self, capacity: int = 10000, priority_alpha: float = 0.6) -> None:
        self.capacity = capacity
        self.priority_alpha = priority_alpha
        self.buffer: list[Experience] = []
        self.priorities: list[float] = []

    def add(self, experience: Experience) -> None:
        """Add an experience to the buffer."""
        if len(self.buffer) >= self.capacity:
            # Remove lowest priority
            min_idx = self.priorities.index(min(self.priorities))
            self.buffer.pop(min_idx)
            self.priorities.pop(min_idx)

        self.buffer.append(experience)
        # Priority based on absolute reward (higher reward = higher priority)
        priority = (abs(experience.reward) + 0.01) ** self.priority_alpha
        self.priorities.append(priority)

    def sample(self, batch_size: int) -> list[Experience]:
        """Sample a batch of experiences, weighted by priority."""
        if not self.buffer:
            return []

        k = min(batch_size, len(self.buffer))
        total = sum(self.priorities)
        if total == 0:
            return random.sample(self.buffer, k)

        weights = [p / total for p in self.priorities]
        indices = random.choices(range(len(self.buffer)), weights=weights, k=k)
        return [self.buffer[i] for i in indices]

    def sample_by_action(self, action: str, k: int = 10) -> list[Experience]:
        """Sample experiences for a specific action (vulnerability class)."""
        matching = [e for e in self.buffer if e.action == action]
        if not matching:
            return []
        return random.sample(matching, min(k, len(matching)))

    def get_action_stats(self) -> dict[str, dict[str, float]]:
        """Get aggregate statistics per action."""
        stats: dict[str, dict[str, Any]] = {}
        for exp in self.buffer:
            action = exp.action
            if action not in stats:
                stats[action] = {"count": 0, "total_reward": 0.0, "rewards": []}
            stats[action]["count"] += 1
            stats[action]["total_reward"] += exp.reward
            stats[action]["rewards"].append(exp.reward)

        result = {}
        for action, s in stats.items():
            rewards = s["rewards"]
            result[action] = {
                "count": s["count"],
                "mean_reward": sum(rewards) / len(rewards) if rewards else 0.0,
                "max_reward": max(rewards) if rewards else 0.0,
                "total_reward": s["total_reward"],
            }
        return result

    def save(self, path: Path) -> None:
        """Persist buffer to disk."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "capacity": self.capacity,
            "experiences": [e.to_dict() for e in self.buffer],
        }
        path.write_text(json.dumps(data, indent=2, default=str))

    def load(self, path: Path) -> None:
        """Load buffer from disk."""
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            self.capacity = data.get("capacity", self.capacity)
            self.buffer = [Experience.from_dict(e) for e in data.get("experiences", [])]
            self.priorities = [
                (abs(e.reward) + 0.01) ** self.priority_alpha for e in self.buffer
            ]
        except Exception:
            pass

    def __len__(self) -> int:
        return len(self.buffer)
