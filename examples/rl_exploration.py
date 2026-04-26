#!/usr/bin/env python3
"""Example: Explore RL bandit arm selection."""

from wraith_cli.rl.bandit import EpsilonGreedy, UCB1, ThompsonSampling
from wraith_cli.rl.reward import RewardShaper

# Compare strategies
for Strategy in [EpsilonGreedy, UCB1, ThompsonSampling]:
    bandit = Strategy()
    shaper = RewardShaper()

    print(f"\n{'='*50}")
    print(f"Strategy: {Strategy.__name__}")
    print(f"{'='*50}")

    # Simulate 20 rounds
    for round_num in range(20):
        arm = bandit.select_arm()
        # Simulate finding with varying success
        import random
        if random.random() < 0.3:  # 30% chance of finding something
            reward = shaper.compute_reward({
                "severity": random.choice(["critical", "high", "medium", "low"]),
                "confidence": random.random(),
                "vuln_class": arm,
            })
        else:
            reward = 0.0
        bandit.update(arm, reward)

    # Show top arms
    stats = bandit.get_stats()
    sorted_arms = sorted(stats["arms"].values(), key=lambda a: a["q_value"], reverse=True)
    for arm in sorted_arms[:5]:
        if arm["pulls"] > 0:
            print(f"  {arm['name']:30s}  Q={arm['q_value']:.3f}  pulls={arm['pulls']}")
