"""
Remediation agent — prioritised fix recommendations with code patches.
"""

from __future__ import annotations

import json
from typing import Any

from wraith_cli.agents.base import BaseAgent, AgentResult


class RemediationAgent(BaseAgent):
    """Generates prioritised remediation recommendations."""

    name = "remediation"
    description = "Produces prioritised fix recommendations with code patches"

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        findings = task.get("findings", [])

        chain.observe(f"Generating remediation for {len(findings)} findings")

        if not findings:
            chain.conclude("No findings to remediate", confidence=1.0)
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=True, findings=[], reasoning_chain=chain,
            )

        try:
            result = await self._call_llm_json(
                system=(
                    "You are a senior security engineer. For each vulnerability finding, "
                    "provide a specific, actionable remediation with code examples where "
                    "applicable. Prioritise by risk (severity × exploitability). "
                    "Group related fixes together."
                ),
                user=(
                    f"Findings to remediate:\n{json.dumps(findings[:20], indent=2)}\n\n"
                    "Return JSON 'remediations' array. Each item:\n"
                    '- "priority": P1/P2/P3/P4\n'
                    '- "title": fix description\n'
                    '- "finding_ids": which findings this addresses\n'
                    '- "fix_type": code_change/config_change/upgrade/architecture\n'
                    '- "description": detailed fix instructions\n'
                    '- "code_example": code snippet if applicable\n'
                    '- "effort": low/medium/high\n'
                    '- "risk_reduction": description of risk reduced\n'
                ),
            )

            remediations = result.get("remediations", [])
            chain.conclude(f"Generated {len(remediations)} remediation recommendations", confidence=0.9)

            self.publish("remediation.complete", {"remediations": remediations})
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=True, findings=remediations,
                data={"remediation_count": len(remediations)},
                reasoning_chain=chain,
            )

        except Exception as e:
            chain.conclude(f"Remediation generation failed: {e}", confidence=0.3)
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=False, errors=[str(e)], reasoning_chain=chain,
            )
