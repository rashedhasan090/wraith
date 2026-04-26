"""
Multi-armed bandit algorithms for vulnerability exploration.

The RL exploration engine selects which vulnerability classes (arms) to
pursue during a scan. Each arm represents a vulnerability category
(e.g., SQL injection, XSS, SSRF). The reward signal comes from
confirmed findings — their severity × confidence × novelty bonus.

Supported strategies:
- Epsilon-Greedy: explore with probability ε, exploit otherwise
- UCB1: Upper Confidence Bound for optimal explore/exploit tradeoff
- Thompson Sampling: Bayesian approach using Beta distributions
"""

from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ── Vulnerability classes (arms) ─────────────────────────────────────────

VULN_CLASSES = [
    "sql_injection",
    "xss_reflected",
    "xss_stored",
    "command_injection",
    "path_traversal",
    "ssrf",
    "idor",
    "auth_bypass",
    "jwt_weakness",
    "insecure_deserialization",
    "xxe",
    "open_redirect",
    "cors_misconfiguration",
    "security_misconfiguration",
    "sensitive_data_exposure",
    "broken_access_control",
    "crypto_weakness",
    "race_condition",
    "business_logic_flaw",
    "prompt_injection",
    "llm_data_exfil",
    "api_bola",
    "api_broken_auth",
    "dependency_cve",
]


@dataclass
class ArmStats:
    """Statistics for a single arm (vulnerability class)."""
    name: str
    pulls: int = 0
    total_reward: float = 0.0
    q_value: float = 0.0          # estimated action-value
    alpha: float = 1.0            # Beta distribution α (Thompson)
    beta_param: float = 1.0       # Beta distribution β (Thompson)
    last_reward: float = 0.0
    best_reward: float = 0.0

    def update(self, reward: float, learning_rate: float = 0.1) -> None:
        """Update arm statistics with a new reward observation."""
        self.pulls += 1
        self.total_reward += reward
        self.last_reward = reward
        self.best_reward = max(self.best_reward, reward)
        # Incremental Q-value update
        self.q_value += learning_rate * (reward - self.q_value)
        # Thompson Sampling update (Beta-Bernoulli model)
        if reward > 0:
            self.alpha += reward / 10.0  # normalised
        else:
            self.beta_param += 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "pulls": self.pulls,
            "total_reward": round(self.total_reward, 3),
            "q_value": round(self.q_value, 3),
            "alpha": round(self.alpha, 3),
            "beta": round(self.beta_param, 3),
            "last_reward": round(self.last_reward, 3),
            "best_reward": round(self.best_reward, 3),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArmStats":
        return cls(
            name=data["name"],
            pulls=data.get("pulls", 0),
            total_reward=data.get("total_reward", 0.0),
            q_value=data.get("q_value", 0.0),
            alpha=data.get("alpha", 1.0),
            beta_param=data.get("beta", 1.0),
            last_reward=data.get("last_reward", 0.0),
            best_reward=data.get("best_reward", 0.0),
        )


class MultiArmedBandit(ABC):
    """Base class for multi-armed bandit strategies."""

    def __init__(self, arms: list[str] | None = None) -> None:
        arm_names = arms or VULN_CLASSES
        self.arms: dict[str, ArmStats] = {name: ArmStats(name=name) for name in arm_names}
        self.total_steps: int = 0

    @abstractmethod
    def select_arm(self) -> str:
        """Select which vulnerability class to explore next."""
        ...

    def update(self, arm_name: str, reward: float, learning_rate: float = 0.1) -> None:
        """Update arm statistics after observing a reward."""
        if arm_name in self.arms:
            self.arms[arm_name].update(reward, learning_rate)
            self.total_steps += 1

    def select_k_arms(self, k: int) -> list[str]:
        """Select k arms for parallel exploration."""
        selected = []
        for _ in range(min(k, len(self.arms))):
            arm = self.select_arm()
            if arm not in selected:
                selected.append(arm)
            else:
                # If duplicate, pick a random unexplored arm
                remaining = [a for a in self.arms if a not in selected]
                if remaining:
                    selected.append(random.choice(remaining))
        return selected

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_steps": self.total_steps,
            "arms": {name: arm.to_dict() for name, arm in self.arms.items()},
        }

    def load_stats(self, data: dict[str, Any]) -> None:
        self.total_steps = data.get("total_steps", 0)
        for name, arm_data in data.get("arms", {}).items():
            if name in self.arms:
                self.arms[name] = ArmStats.from_dict(arm_data)


class EpsilonGreedy(MultiArmedBandit):
    """Epsilon-greedy exploration strategy.

    With probability ε, select a random arm (explore).
    With probability 1-ε, select the arm with highest Q-value (exploit).
    """

    def __init__(self, epsilon: float = 0.15, decay: float = 0.995, arms: list[str] | None = None) -> None:
        super().__init__(arms)
        self.epsilon = epsilon
        self.decay = decay
        self.initial_epsilon = epsilon

    def select_arm(self) -> str:
        if random.random() < self.epsilon:
            # Explore: random arm
            choice = random.choice(list(self.arms.keys()))
            return choice
        else:
            # Exploit: best Q-value (with random tiebreak)
            max_q = max(arm.q_value for arm in self.arms.values())
            best_arms = [name for name, arm in self.arms.items() if arm.q_value == max_q]
            return random.choice(best_arms)

    def update(self, arm_name: str, reward: float, learning_rate: float = 0.1) -> None:
        super().update(arm_name, reward, learning_rate)
        # Decay epsilon after each update
        self.epsilon = max(0.01, self.epsilon * self.decay)


class UCB1(MultiArmedBandit):
    """Upper Confidence Bound (UCB1) strategy.

    Selects the arm that maximises: Q(a) + c * sqrt(ln(N) / n(a))
    where N = total steps, n(a) = times arm a was pulled, c = exploration constant.

    Provides optimal explore/exploit tradeoff with theoretical guarantees.
    """

    def __init__(self, c: float = 2.0, arms: list[str] | None = None) -> None:
        super().__init__(arms)
        self.c = c

    def select_arm(self) -> str:
        # Pull each arm at least once
        for name, arm in self.arms.items():
            if arm.pulls == 0:
                return name

        total = max(self.total_steps, 1)
        best_score = -float("inf")
        best_arm = list(self.arms.keys())[0]

        for name, arm in self.arms.items():
            ucb_score = arm.q_value + self.c * math.sqrt(math.log(total) / max(arm.pulls, 1))
            if ucb_score > best_score:
                best_score = ucb_score
                best_arm = name

        return best_arm


class ThompsonSampling(MultiArmedBandit):
    """Thompson Sampling — Bayesian approach.

    Models each arm's reward as a Beta distribution.
    Samples from each arm's posterior and selects the arm with
    the highest sampled value. Naturally balances exploration/exploitation.
    """

    def select_arm(self) -> str:
        best_sample = -1.0
        best_arm = list(self.arms.keys())[0]

        for name, arm in self.arms.items():
            # Sample from Beta distribution
            sample = random.betavariate(
                max(arm.alpha, 0.01),
                max(arm.beta_param, 0.01),
            )
            if sample > best_sample:
                best_sample = sample
                best_arm = name

        return best_arm
