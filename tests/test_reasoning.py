"""Tests for reasoning chain."""

from wraith_cli.reasoning.chain import ReasoningChain, StepType


class TestReasoningChain:
    def test_chain_building(self):
        chain = ReasoningChain(agent_name="test")
        chain.observe("Found 10 files")
        chain.infer("Likely a Python project", confidence=0.8)
        chain.conclude("Analysis complete", confidence=0.9)
        assert len(chain.steps) == 3

    def test_step_types(self):
        chain = ReasoningChain(agent_name="test")
        chain.observe("obs").infer("inf").assume("asm").conclude("done")
        types = [s.step_type for s in chain.steps]
        assert types == [StepType.OBSERVE, StepType.INFER, StepType.ASSUME, StepType.CONCLUDE]

    def test_serialization(self):
        chain = ReasoningChain(agent_name="test")
        chain.observe("test").conclude("done", confidence=0.95)
        data = chain.to_dict()
        assert data["agent"] == "test"
        assert len(data["steps"]) == 2
        assert data["conclusion"]["confidence"] == 0.95
