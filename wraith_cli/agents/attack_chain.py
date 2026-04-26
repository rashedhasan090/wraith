"""
Attack chain synthesis agent — MITRE ATT&CK mapped multi-step attack paths.

Takes individual vulnerability findings and synthesises them into realistic
attack chains showing how an attacker could chain multiple issues.
"""

from __future__ import annotations

import json
from typing import Any

from wraith_cli.agents.base import BaseAgent, AgentResult


class AttackChainAgent(BaseAgent):
    """Synthesises multi-step attack paths from individual vulnerabilities."""

    name = "attack_chain"
    description = "Combines vulnerabilities into attack chains using MITRE ATT&CK"

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        vulnerabilities = task.get("vulnerabilities", [])
        recon_data = context.get("recon_data", {})

        chain.observe(f"Synthesising attack chains from {len(vulnerabilities)} findings")

        if not vulnerabilities:
            chain.conclude("No vulnerabilities to chain", confidence=1.0)
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=True, findings=[], reasoning_chain=chain,
            )

        # Use LLM to synthesise chains
        try:
            result = await self._call_llm_json(
                system=(
                    "You are a red team operator synthesising multi-step attack chains. "
                    "Given individual vulnerability findings, identify how an attacker could "
                    "chain them together for maximum impact. Map each step to MITRE ATT&CK "
                    "techniques. Be realistic — only chain vulns that are logically connected."
                ),
                user=(
                    f"Vulnerabilities:\n{json.dumps(vulnerabilities[:20], indent=2)}\n\n"
                    f"Attack surface: {json.dumps(recon_data.get('technologies', []))}\n"
                    f"Entry points: {len(recon_data.get('entry_points', []))}\n\n"
                    "Return JSON 'chains' array. Each chain:\n"
                    '- "name": attack chain name\n'
                    '- "steps": [{step_num, description, technique_id, vulnerability_used}]\n'
                    '- "total_impact": description of full chain impact\n'
                    '- "severity": critical/high/medium\n'
                    '- "likelihood": high/medium/low\n'
                    '- "mitigations": list of recommended mitigations\n'
                ),
            )

            chains = result.get("chains", [])
            chain.infer(f"Synthesised {len(chains)} attack chains")

            findings = []
            for i, ac in enumerate(chains, 1):
                findings.append({
                    "id": f"CHAIN-{i:03d}",
                    "type": "attack_chain",
                    "title": f"[Attack Chain] {ac.get('name', 'Unknown')}",
                    "vuln_class": "attack_chain",
                    "severity": ac.get("severity", "high"),
                    "steps": ac.get("steps", []),
                    "total_impact": ac.get("total_impact", ""),
                    "likelihood": ac.get("likelihood", "medium"),
                    "mitigations": ac.get("mitigations", []),
                    "confidence": 0.8,
                    "source": "attack_chain",
                })

            chain.conclude(f"Attack chain synthesis complete: {len(findings)} chains", confidence=0.85)
            self.publish("attack_chain.complete", {"chains": findings})

            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=True, findings=findings, reasoning_chain=chain,
            )

        except Exception as e:
            chain.conclude(f"Chain synthesis failed: {e}", confidence=0.3)
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=False, errors=[str(e)], reasoning_chain=chain,
            )
