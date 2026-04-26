"""
PoC generator agent — creates safe, runnable proof-of-concept exploits.

All PoCs use benign payloads: timing-based SQLi, alert() XSS markers,
read-only IDOR probes. No destructive operations.
"""

from __future__ import annotations

import json
from typing import Any

from wraith_cli.agents.base import BaseAgent, AgentResult


class PoCGeneratorAgent(BaseAgent):
    """Generate safe proof-of-concept exploit scripts."""

    name = "poc_generator"
    description = "Creates safe, runnable PoC scripts for confirmed vulnerabilities"

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        findings = task.get("findings", [])

        # Only generate PoCs for high/critical findings
        exploitable = [f for f in findings if f.get("severity") in ("critical", "high")]
        chain.observe(f"Generating PoCs for {len(exploitable)} high/critical findings")

        if not exploitable:
            chain.conclude("No high-severity findings for PoC generation", confidence=1.0)
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=True, findings=[], reasoning_chain=chain,
            )

        pocs = []
        for finding in exploitable[:5]:
            try:
                poc = await self._generate_poc(finding)
                if poc:
                    pocs.append(poc)
                    chain.infer(f"Generated PoC for: {finding.get('title', 'unknown')}")
            except Exception as e:
                chain.assume(f"PoC generation failed for {finding.get('title')}: {e}")

        chain.conclude(f"Generated {len(pocs)} proof-of-concept scripts", confidence=0.85)

        self.publish("poc_generator.complete", {"pocs": pocs})
        return AgentResult(
            agent_name=self.name, agent_id=self.agent_id,
            success=True, findings=pocs, reasoning_chain=chain,
        )

    async def _generate_poc(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        """Generate a safe PoC for a single finding."""
        result = await self._call_llm_json(
            system=(
                "You are a security researcher writing proof-of-concept exploit scripts. "
                "CRITICAL SAFETY RULES:\n"
                "- Use ONLY benign payloads (timing-based SQLi, alert() XSS, read-only probes)\n"
                "- NO destructive operations, NO data exfiltration, NO privilege escalation\n"
                "- Include a SAFETY WARNING header in every script\n"
                "- Scripts must require explicit --confirm flag to execute\n"
                "- Target only the specified URL/path\n"
            ),
            user=(
                f"Vulnerability: {json.dumps(finding, indent=2)}\n\n"
                "Generate a Python PoC script. Return JSON:\n"
                '- "title": PoC title\n'
                '- "language": "python"\n'
                '- "script": the full Python script as a string\n'
                '- "setup": setup instructions\n'
                '- "expected_output": what confirms the vuln\n'
                '- "safety_notes": why this is safe\n'
                '- "requires": list of pip packages\n'
            ),
        )
        if result.get("parse_error"):
            return None
        result["source"] = "poc_generator"
        result["vuln_class"] = finding.get("vuln_class", "unknown")
        result["severity"] = finding.get("severity", "high")
        return result
