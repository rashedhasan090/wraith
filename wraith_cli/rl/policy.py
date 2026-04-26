"""
RL Policy management — load, save, and coordinate bandit strategies.

The policy persists across scans in ~/.wraith/rl_policy.json, enabling
cross-session learning.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wraith_cli.config import RLConfig, RLStrategy
from wraith_cli.rl.bandit import (
    EpsilonGreedy,
    MultiArmedBandit,
    ThompsonSampling,
    UCB1,
    VULN_CLASSES,
)
from wraith_cli.rl.memory import ExperienceReplay
from wraith_cli.rl.reward import RewardShaper


class RLPolicy:
    """Top-level RL policy coordinator.

    Manages the bandit strategy, reward shaping, and experience replay
    buffer. Handles persistence for cross-session learning.
    """

    def __init__(self, config: RLConfig | None = None) -> None:
        self.config = config or RLConfig()
        self.bandit = self._create_bandit()
        self.reward_shaper = RewardShaper()
        self.replay = ExperienceReplay(capacity=10000)
        self.episode_count: int = 0

    def _create_bandit(self) -> MultiArmedBandit:
        """Create the appropriate bandit strategy."""
        match self.config.strategy:
            case RLStrategy.EPSILON_GREEDY:
                return EpsilonGreedy(
                    epsilon=self.config.epsilon,
                    decay=self.config.exploration_decay,
                )
            case RLStrategy.UCB1:
                return UCB1(c=2.0)
            case RLStrategy.THOMPSON:
                return ThompsonSampling()
            case _:
                return UCB1(c=2.0)

    def select_actions(self, k: int = 4) -> list[str]:
        """Select k vulnerability classes to explore in parallel."""
        return self.bandit.select_k_arms(k)

    def update_from_findings(self, findings: list[dict[str, Any]], actions_taken: list[str]) -> dict[str, float]:
        """Update policy based on scan findings.

        Returns dict of action → reward for logging.
        """
        action_rewards: dict[str, float] = {}

        # Compute reward per finding
        for finding in findings:
            reward = self.reward_shaper.compute_reward(finding)
            vuln_class = finding.get("vuln_class", "unknown")
            if vuln_class in action_rewards:
                action_rewards[vuln_class] += reward
            else:
                action_rewards[vuln_class] = reward

        # Update bandit for each action taken
        for action in actions_taken:
            reward = action_rewards.get(action, 0.0)
            self.bandit.update(action, reward, self.config.learning_rate)

        self.episode_count += 1
        return action_rewards

    def get_stats(self) -> dict[str, Any]:
        """Get comprehensive RL statistics."""
        bandit_stats = self.bandit.get_stats()
        reward_stats = self.reward_shaper.get_stats()
        replay_stats = self.replay.get_action_stats()

        # Sort arms by Q-value for display
        sorted_arms = sorted(
            bandit_stats["arms"].values(),
            key=lambda a: a["q_value"],
            reverse=True,
        )

        return {
            "strategy": self.config.strategy.value,
            "episode_count": self.episode_count,
            "epsilon": getattr(self.bandit, "epsilon", None),
            "bandit": bandit_stats,
            "reward": reward_stats,
            "replay_size": len(self.replay),
            "top_arms": sorted_arms[:10],
            "replay_stats": replay_stats,
        }

    def save(self, path: Path | None = None) -> None:
        """Persist policy to disk."""
        policy_path = path or self.config.policy_path
        if not policy_path:
            return
        policy_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "strategy": self.config.strategy.value,
            "episode_count": self.episode_count,
            "bandit": self.bandit.get_stats(),
            "reward_seen_classes": list(self.reward_shaper.seen_classes),
        }
        policy_path.write_text(json.dumps(data, indent=2))

        # Save replay buffer separately
        replay_path = policy_path.parent / "rl_replay.json"
        self.replay.save(replay_path)

    def load(self, path: Path | None = None) -> None:
        """Load policy from disk."""
        policy_path = path or self.config.policy_path
        if not policy_path or not policy_path.exists():
            return

        try:
            data = json.loads(policy_path.read_text())
            self.episode_count = data.get("episode_count", 0)
            if "bandit" in data:
                self.bandit.load_stats(data["bandit"])
            if "reward_seen_classes" in data:
                self.reward_shaper.seen_classes = set(data["reward_seen_classes"])

            # Load replay buffer
            replay_path = policy_path.parent / "rl_replay.json"
            self.replay.load(replay_path)
        except Exception:
            pass
