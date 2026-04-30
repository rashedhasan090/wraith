"""
Zero-day hypothesis engine — predicts novel vulnerability classes.

Studies CVE evolution trajectories to predict where new vuln classes
will emerge. Uses creative ideation to imagine novel attack vectors.
"""

from __future__ import annotations

import json
from typing import Any

from wraith_cli.agents.base import BaseAgent, AgentResult
from wraith_cli.knowledge.zero_day import ZeroDayHypothesisEngine


class ZeroDayAgent(BaseAgent):
    """Predicts novel vulnerability classes from CVE evolution."""

    name = "zero_day"
    description = "Generates zero-day vulnerability hypotheses from CVE evolutionary analysis"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.hypothesis_engine = ZeroDayHypothesisEngine()

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        recon_data = context.get("recon_data", {})
        existing_findings = task.get("existing_findings", [])

        chain.observe("Starting zero-day hypothesis generation")
        chain.observe(f"Technology stack: {recon_data.get('technologies', [])}")
        chain.observe(f"Existing findings: {len(existing_findings)}")

        deterministic = self.hypothesis_engine.generate(recon_data, existing_findings, limit=8)
        chain.infer(
            f"Offline hypothesis engine generated {len(deterministic)} evidence-backed hypotheses"
        )

        llm_hypotheses: list[dict[str, Any]] = []
        try:
            result = await self._call_llm_json(
                system_prompt=(
                    "You are a vulnerability researcher specialising in zero-day discovery. "
                    "Based on the target's technology stack and known vulnerability patterns, "
                    "generate hypotheses about NOVEL vulnerability classes that haven't been "
                    "widely discovered yet. Think creatively:\n"
                    "1. Study how CVE patterns evolved for this tech stack\n"
                    "2. Project evolutionary trajectories\n"
                    "3. Imagine novel attack vectors at component boundaries\n"
                    "4. Consider emerging attack surfaces (LLM integration, supply chain, etc.)\n"
                    "For each hypothesis, specify a validation experiment. Keep all validation "
                    "experiments defensive: authorised lab tests, benign canaries, property tests, "
                    "or local fixtures only."
                ),
                user_prompt=(
                    f"Technologies: {recon_data.get('technologies', [])}\n"
                    f"Languages: {recon_data.get('languages', {})}\n"
                    f"Dependencies: {json.dumps(recon_data.get('dependencies', [])[:15], indent=2)}\n"
                    f"Known vulns in this target: {json.dumps([f.get('title') for f in existing_findings[:10]])}\n\n"
                    "Return JSON 'hypotheses' array. Each hypothesis:\n"
                    '- "title": hypothesis name\n'
                    '- "description": detailed hypothesis\n'
                    '- "novel_class": proposed new vulnerability class name\n'
                    '- "affected_components": which components are at risk\n'
                    '- "evolutionary_basis": which existing CVE patterns led to this prediction\n'
                    '- "validation_experiment": how to test this hypothesis\n'
                    '- "evidence": target-specific evidence signals, not generic warnings\n'
                    '- "negative_controls": validation cases that should stay safe\n'
                    '- "estimated_severity": critical/high/medium\n'
                    '- "confidence": 0.0-1.0 (be honest — these are speculative)\n'
                ),
            )

            raw_hypotheses = result.get("hypotheses", [])
            existing_titles = {h.get("title", "") for h in deterministic}
            llm_hypotheses = self.hypothesis_engine.normalize_llm_hypotheses(
                raw_hypotheses,
                existing_titles=existing_titles,
            )
            chain.infer(f"LLM generated {len(llm_hypotheses)} normalized hypotheses")
        except Exception as e:
            chain.assume(f"LLM hypothesis expansion unavailable: {e}")

        findings = self._merge_and_rank(deterministic, llm_hypotheses)

        chain.conclude(
            f"Zero-day hypothesis generation complete: {len(findings)} hypotheses",
            confidence=0.72 if deterministic else 0.35,
        )

        self.publish("zero_day.complete", {"hypotheses": findings})
        return AgentResult(
            agent_name=self.name,
            agent_id=self.agent_id,
            success=True,
            findings=findings,
            data={
                "offline_hypotheses": len(deterministic),
                "llm_hypotheses": len(llm_hypotheses),
                "methodology": "evidence_weighted_hypothesis_generation",
            },
            reasoning_chain=chain,
        )

    def _merge_and_rank(
        self,
        deterministic: list[dict[str, Any]],
        llm_hypotheses: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Deduplicate and rank hypotheses by rigor, novelty, then confidence."""
        merged: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for hypothesis in deterministic + llm_hypotheses:
            key = (
                str(hypothesis.get("vuln_class", "")).lower(),
                str(hypothesis.get("title", "")).lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(hypothesis)

        merged.sort(
            key=lambda item: (
                item.get("rigor_score", 0.0),
                item.get("novelty_score", 0.0),
                item.get("confidence", 0.0),
            ),
            reverse=True,
        )
        for index, hypothesis in enumerate(merged, 1):
            hypothesis.setdefault("id", f"ZD-HYP-{index:03d}")
        return merged
