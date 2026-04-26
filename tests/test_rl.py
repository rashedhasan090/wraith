"""Tests for the RL bandit system."""

import pytest
from wraith_cli.rl.bandit import (
    EpsilonGreedy,
    UCB1,
    ThompsonSampling,
    ArmStats,
    VULN_CLASSES,
)
from wraith_cli.rl.reward import RewardShaper
from wraith_cli.rl.memory import ExperienceReplay, Experience


class TestArmStats:
    def test_initial_state(self):
        arm = ArmStats(name="sql_injection")
        assert arm.pulls == 0
        assert arm.q_value == 0.0

    def test_update(self):
        arm = ArmStats(name="xss")
        arm.update(5.0, learning_rate=0.1)
        assert arm.pulls == 1
        assert arm.total_reward == 5.0
        assert arm.q_value == pytest.approx(0.5)

    def test_serialization(self):
        arm = ArmStats(name="test", pulls=5, q_value=2.0)
        data = arm.to_dict()
        restored = ArmStats.from_dict(data)
        assert restored.name == "test"
        assert restored.pulls == 5


class TestEpsilonGreedy:
    def test_initialization(self):
        bandit = EpsilonGreedy(epsilon=0.1)
        assert len(bandit.arms) == len(VULN_CLASSES)

    def test_select_arm(self):
        bandit = EpsilonGreedy(epsilon=1.0)  # Always explore
        arm = bandit.select_arm()
        assert arm in VULN_CLASSES

    def test_exploit_mode(self):
        bandit = EpsilonGreedy(epsilon=0.0)  # Always exploit
        bandit.update("sql_injection", 10.0)
        # Should always pick sql_injection (highest Q)
        selections = [bandit.select_arm() for _ in range(10)]
        assert all(s == "sql_injection" for s in selections)

    def test_epsilon_decay(self):
        bandit = EpsilonGreedy(epsilon=0.5, decay=0.9)
        initial = bandit.epsilon
        bandit.update("xss_reflected", 1.0)
        assert bandit.epsilon < initial

    def test_select_k_arms(self):
        bandit = EpsilonGreedy()
        selected = bandit.select_k_arms(4)
        assert len(selected) == 4
        assert len(set(selected)) == 4  # All unique


class TestUCB1:
    def test_pulls_all_arms_first(self):
        bandit = UCB1(arms=["a", "b", "c"])
        seen = set()
        for _ in range(3):
            arm = bandit.select_arm()
            seen.add(arm)
            bandit.update(arm, 1.0)
        assert seen == {"a", "b", "c"}


class TestThompsonSampling:
    def test_selection(self):
        bandit = ThompsonSampling(arms=["a", "b"])
        arm = bandit.select_arm()
        assert arm in ("a", "b")


class TestRewardShaper:
    def test_basic_reward(self):
        shaper = RewardShaper()
        reward = shaper.compute_reward({
            "severity": "high",
            "confidence": 0.9,
            "vuln_class": "sql_injection",
        })
        assert reward > 0

    def test_novelty_bonus(self):
        shaper = RewardShaper()
        r1 = shaper.compute_reward({"severity": "medium", "confidence": 0.5, "vuln_class": "xss"})
        r2 = shaper.compute_reward({"severity": "medium", "confidence": 0.5, "vuln_class": "xss"})
        assert r1 > r2  # First occurrence has novelty bonus

    def test_false_positive_penalty(self):
        shaper = RewardShaper()
        reward = shaper.compute_reward({"false_positive": True, "vuln_class": "x"})
        assert reward < 0


class TestExperienceReplay:
    def test_add_and_sample(self):
        replay = ExperienceReplay(capacity=100)
        exp = Experience(state={}, action="sqli", reward=5.0, next_state={})
        replay.add(exp)
        assert len(replay) == 1
        batch = replay.sample(1)
        assert len(batch) == 1

    def test_capacity(self):
        replay = ExperienceReplay(capacity=3)
        for i in range(5):
            replay.add(Experience(state={}, action=f"a{i}", reward=float(i), next_state={}))
        assert len(replay) == 3

    def test_persistence(self, tmp_path):
        replay = ExperienceReplay()
        replay.add(Experience(state={"a": 1}, action="test", reward=1.0, next_state={}))
        path = tmp_path / "replay.json"
        replay.save(path)

        replay2 = ExperienceReplay()
        replay2.load(path)
        assert len(replay2) == 1
