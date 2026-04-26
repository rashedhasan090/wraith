"""
Base agent framework for WRAITH.

Every agent inherits from BaseAgent, which provides:
- LLM integration (OpenAI, Anthropic, Ollama — async)
- Reasoning chain management
- Inter-agent communication via message bus
- Short-term memory
- Tool execution framework
"""

from __future__ import annotations

import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from wraith_cli.config import LLMProvider, WraithConfig
from wraith_cli.reasoning.chain import ReasoningChain


@dataclass
class AgentResult:
    """Standardised result from any agent."""
    agent_name: str
    agent_id: str
    success: bool = True
    findings: list[dict[str, Any]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    reasoning_chain: Optional[ReasoningChain] = None
    execution_time_ms: float = 0.0
    token_usage: dict[str, int] = field(default_factory=lambda: {"input": 0, "output": 0})

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "success": self.success,
            "findings": self.findings,
            "data": self.data,
            "errors": self.errors,
            "reasoning_chain": self.reasoning_chain.to_dict() if self.reasoning_chain else None,
            "execution_time_ms": self.execution_time_ms,
            "token_usage": self.token_usage,
        }


class AgentMemory:
    """Short-term memory for agent context within a scan session."""

    def __init__(self) -> None:
        self._store: list[dict[str, Any]] = []
        self._context: dict[str, Any] = {}

    def remember(self, key: str, value: Any) -> None:
        self._store.append({"key": key, "value": value, "ts": time.time()})

    def recall(self, key: str) -> Optional[Any]:
        for item in reversed(self._store):
            if item["key"] == key:
                return item["value"]
        return None

    def set_context(self, key: str, value: Any) -> None:
        self._context[key] = value

    def get_context(self, key: str, default: Any = None) -> Any:
        return self._context.get(key, default)

    def get_summary(self, max_items: int = 10) -> str:
        items = self._store[-max_items:]
        if not items:
            return "No prior context."
        return "\n".join(f"- {i['key']}: {str(i['value'])[:200]}" for i in items)


class MessageBus:
    """Inter-agent pub/sub message bus for collaborative analysis."""

    def __init__(self) -> None:
        self._messages: list[dict[str, Any]] = []
        self._subscribers: dict[str, list[str]] = {}

    def publish(self, sender: str, topic: str, data: Any) -> None:
        self._messages.append({
            "id": str(uuid.uuid4())[:8],
            "sender": sender,
            "topic": topic,
            "data": data,
            "ts": time.time(),
        })

    def get_messages(self, topic: str | None = None, since: float = 0) -> list[dict[str, Any]]:
        msgs = [m for m in self._messages if m["ts"] > since]
        if topic:
            msgs = [m for m in msgs if m["topic"] == topic]
        return msgs

    def get_findings_from(self, sender: str) -> list[dict[str, Any]]:
        findings = []
        for msg in self._messages:
            if msg["sender"] == sender and "findings" in msg.get("data", {}):
                findings.extend(msg["data"]["findings"])
        return findings


class BaseAgent(ABC):
    """Abstract base agent — all WRAITH agents inherit from this."""

    name: str = "base"
    description: str = "Base agent"

    def __init__(self, config: WraithConfig, bus: MessageBus | None = None) -> None:
        self.config = config
        self.bus = bus or MessageBus()
        self.memory = AgentMemory()
        self.agent_id = f"{self.name}-{str(uuid.uuid4())[:6]}"
        self._llm_client: Any = None

    def create_chain(self) -> ReasoningChain:
        return ReasoningChain(agent_name=self.name)

    def publish(self, topic: str, data: Any) -> None:
        if self.bus:
            self.bus.publish(self.name, topic, data)

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call the configured LLM and return the response text."""
        provider = self.config.llm.provider
        api_key = self.config.llm.resolve_api_key()
        model = self.config.llm.model

        if provider == LLMProvider.OPENAI:
            return await self._call_openai(api_key, model, system_prompt, user_prompt)
        elif provider == LLMProvider.ANTHROPIC:
            return await self._call_anthropic(api_key, model, system_prompt, user_prompt)
        elif provider == LLMProvider.OLLAMA:
            return await self._call_ollama(model, system_prompt, user_prompt)
        else:
            raise ValueError(f"Unknown provider: {provider}")

    async def _call_openai(self, api_key: str, model: str, system: str, user: str) -> str:
        import openai
        client = openai.AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=self.config.llm.temperature,
            max_tokens=self.config.llm.max_tokens,
        )
        return response.choices[0].message.content or ""

    async def _call_anthropic(self, api_key: str, model: str, system: str, user: str) -> str:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=model,
            max_tokens=self.config.llm.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text if response.content else ""

    async def _call_ollama(self, model: str, system: str, user: str) -> str:
        import httpx
        base_url = self.config.llm.base_url or "http://localhost:11434"
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{base_url}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                },
            )
            data = resp.json()
            return data.get("message", {}).get("content", "")

    async def _call_llm_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """Call LLM and parse JSON response."""
        response = await self._call_llm(
            system_prompt + "\n\nAlways respond with valid JSON.",
            user_prompt,
        )
        # Extract JSON from response (handle markdown code blocks)
        text = response.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object in the response
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
            return {"raw_response": response, "parse_error": True}

    @abstractmethod
    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        """Execute the agent's analysis. Must be implemented by subclasses."""
        ...

    async def run(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        """Run the agent with timing and error handling."""
        start = time.time()
        try:
            result = await self.execute(task, context)
        except Exception as exc:
            result = AgentResult(
                agent_name=self.name,
                agent_id=self.agent_id,
                success=False,
                errors=[str(exc)],
            )
        result.execution_time_ms = (time.time() - start) * 1000
        return result
