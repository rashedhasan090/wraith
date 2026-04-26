"""
Typed reasoning chain for agent decision transparency.

Every agent builds a reasoning chain during execution, recording:
- Observations (raw data gathered)
- Inferences (conclusions drawn from observations)
- Assumptions (things assumed without direct evidence)
- Conclusions (final decisions with confidence scores)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class StepType(str, Enum):
    OBSERVE = "observe"
    INFER = "infer"
    ASSUME = "assume"
    CONCLUDE = "conclude"


@dataclass
class ReasoningStep:
    """A single step in the reasoning chain."""
    step_type: StepType
    content: str
    confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.step_type.value,
            "content": self.content,
            "confidence": round(self.confidence, 2),
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class ReasoningChain:
    """A chain of reasoning steps building toward a conclusion."""
    agent_name: str
    steps: list[ReasoningStep] = field(default_factory=list)

    def observe(self, content: str, **meta: Any) -> "ReasoningChain":
        self.steps.append(ReasoningStep(StepType.OBSERVE, content, metadata=meta))
        return self

    def infer(self, content: str, confidence: float = 0.7, **meta: Any) -> "ReasoningChain":
        self.steps.append(ReasoningStep(StepType.INFER, content, confidence, metadata=meta))
        return self

    def assume(self, content: str, confidence: float = 0.5, **meta: Any) -> "ReasoningChain":
        self.steps.append(ReasoningStep(StepType.ASSUME, content, confidence, metadata=meta))
        return self

    def conclude(self, content: str, confidence: float = 0.8, **meta: Any) -> "ReasoningChain":
        self.steps.append(ReasoningStep(StepType.CONCLUDE, content, confidence, metadata=meta))
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_name,
            "steps": [s.to_dict() for s in self.steps],
            "conclusion": self.steps[-1].to_dict() if self.steps else None,
        }

    def __str__(self) -> str:
        lines = [f"Reasoning Chain ({self.agent_name}):"]
        for i, step in enumerate(self.steps, 1):
            icon = {"observe": "👁", "infer": "🧠", "assume": "⚠️", "conclude": "✅"}[step.step_type.value]
            lines.append(f"  {i}. {icon} [{step.step_type.value}] {step.content}")
        return "\n".join(lines)
