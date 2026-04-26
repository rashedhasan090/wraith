"""
Reward shaping for vulnerability discovery.

Translates scan findings into scalar reward signals for the RL bandit.
Reward is shaped by:
- Finding severity (critical=10, high=7, medium=4, low=1, info=0.5)
- Confidence score (0-1)
- Novelty bonus (higher reward for first-time discovery of a vuln class)
- Chain bonus (extra reward if finding contributes to an attack chain)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SEVERITY_REWARDS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
    "info": 0.5,
}


@dataclass
class RewardShaper:
    """Computes reward signals from vulnerability findings."""

    novelty_bonus: float = 2.0        # Bonus for first discovery of a vuln class
    chain_bonus: float = 1.5          # Bonus if finding is part of an attack chain
    false_positive_penalty: float = -3.0  # Penalty for findings marked as FP
    seen_classes: set[str] = field(default_factory=set)
    total_reward: float = 0.0
    episode_rewards: list[float] = field(default_factory=list)

    def compute_reward(self, finding: dict[str, Any]) -> float:
        """Compute reward for a single finding.

        Args:
            finding: Dict with keys like 'severity', 'confidence',
                     'vuln_class', 'in_chain', 'false_positive'.

        Returns:
            Scalar reward value.
        """
        severity = finding.get("severity", "medium").lower()
        confidence = finding.get("confidence", 0.5)
        vuln_class = finding.get("vuln_class", "unknown")
        in_chain = finding.get("in_chain", False)
        is_fp = finding.get("false_positive", False)

        if is_fp:
            return self.false_positive_penalty

        # Base reward from severity
        base = SEVERITY_REWARDS.get(severity, 1.0)

        # Scale by confidence
        reward = base * confidence

        # Novelty bonus for first-time class discovery
        if vuln_class not in self.seen_classes:
            reward += self.novelty_bonus
            self.seen_classes.add(vuln_class)

        # Chain participation bonus
        if in_chain:
            reward += self.chain_bonus

        self.total_reward += reward
        self.episode_rewards.append(reward)
        return reward

    def compute_episode_reward(self, findings: list[dict[str, Any]]) -> float:
        """Compute total reward for a scan episode."""
        return sum(self.compute_reward(f) for f in findings)

    def get_stats(self) -> dict[str, Any]:
        eps = self.episode_rewards
        return {
            "total_reward": round(self.total_reward, 2),
            "episodes": len(eps),
            "mean_reward": round(sum(eps) / len(eps), 2) if eps else 0.0,
            "max_reward": round(max(eps), 2) if eps else 0.0,
            "seen_classes": len(self.seen_classes),
        }
