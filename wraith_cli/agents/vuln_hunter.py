"""
Vulnerability hunter agent — OWASP Top 10 + LLM semantic analysis.

Combines pattern-based OWASP detection with LLM-driven semantic hunting
to find both known and novel vulnerabilities.
"""

from __future__ import annotations

import json
from typing import Any

from wraith_cli.agents.base import BaseAgent, AgentResult


class VulnHunterAgent(BaseAgent):
    """Vulnerability detection through OWASP patterns and LLM reasoning."""

    name = "vuln_hunter"
    description = "Hunts for exploitable vulnerabilities using OWASP/CWE patterns and LLM reasoning"

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        recon_data = context.get("recon_data", {})
        code_findings = context.get("code_analyst_findings", [])
        rl_targets = task.get("rl_targets", [])  # RL-selected vuln classes

        chain.observe("Starting vulnerability hunting")
        chain.observe(f"RL-selected targets: {rl_targets}")
        chain.observe(f"Recon context: {len(recon_data.get('entry_points', []))} entry points")

        all_vulns: list[dict[str, Any]] = []

        # Phase 1: OWASP pattern analysis via LLM
        chain.observe("Phase 1: OWASP Top 10 analysis")
        try:
            owasp_vulns = await self._owasp_analysis(recon_data, code_findings, rl_targets)
            all_vulns.extend(owasp_vulns)
            chain.infer(f"OWASP analysis: {len(owasp_vulns)} findings")
        except Exception as e:
            chain.assume(f"OWASP analysis error: {e}")

        # Phase 2: Deep semantic hunt for RL-selected classes
        chain.observe("Phase 2: RL-targeted semantic hunt")
        for vuln_class in rl_targets:
            try:
                targeted_vulns = await self._targeted_hunt(vuln_class, recon_data, code_findings)
                all_vulns.extend(targeted_vulns)
                chain.infer(f"Targeted hunt ({vuln_class}): {len(targeted_vulns)} findings")
            except Exception as e:
                chain.assume(f"Hunt for {vuln_class} failed: {e}")

        # Phase 3: Validate and deduplicate
        validated = self._deduplicate(all_vulns)
        for i, v in enumerate(validated, 1):
            v.setdefault("id", f"WRAITH-{i:04d}")

        chain.conclude(f"Hunting complete: {len(validated)} validated findings", confidence=0.85)

        self.publish("vuln_hunter.complete", {
            "findings": validated,
            "count": len(validated),
        })

        return AgentResult(
            agent_name=self.name, agent_id=self.agent_id,
            success=True, findings=validated,
            data={"severity_breakdown": self._severity_breakdown(validated)},
            reasoning_chain=chain,
        )

    async def _owasp_analysis(
        self, recon_data: dict, code_findings: list, rl_targets: list,
    ) -> list[dict[str, Any]]:
        """LLM-powered OWASP Top 10 analysis."""
        result = await self._call_llm_json(
            system=(
                "You are an expert penetration tester. Analyse the target's attack surface "
                "for OWASP Top 10 vulnerabilities. For each finding, assess real exploitability "
                "in this specific context. Be precise — no generic warnings."
            ),
            user=(
                f"Target technologies: {recon_data.get('technologies', [])}\n"
                f"Entry points: {json.dumps(recon_data.get('entry_points', [])[:15], indent=2)}\n"
                f"Dependencies: {json.dumps(recon_data.get('dependencies', [])[:15], indent=2)}\n"
                f"Prior code findings: {json.dumps(code_findings[:10], indent=2)}\n"
                f"RL focus areas: {rl_targets}\n\n"
                "Return JSON with 'findings' array. Each finding needs:\n"
                '- "title", "severity" (critical/high/medium/low), "cwe", '
                '"vuln_class", "description", "evidence", "confidence" (0-1), '
                '"owasp_category", "attack_scenario"\n'
            ),
        )
        findings = result.get("findings", [])
        for f in findings:
            f["source"] = "vuln_hunter"
        return findings

    async def _targeted_hunt(
        self, vuln_class: str, recon_data: dict, code_findings: list,
    ) -> list[dict[str, Any]]:
        """Deep hunt for a specific vulnerability class (RL-selected)."""
        result = await self._call_llm_json(
            system=(
                f"You are hunting specifically for {vuln_class} vulnerabilities. "
                "Be thorough — examine every entry point, dependency, and code pattern "
                "for this specific vulnerability class. Think like an attacker."
            ),
            user=(
                f"Vulnerability class to hunt: {vuln_class}\n"
                f"Technologies: {recon_data.get('technologies', [])}\n"
                f"Entry points: {json.dumps(recon_data.get('entry_points', [])[:10], indent=2)}\n"
                f"Dependencies: {json.dumps(recon_data.get('dependencies', [])[:10], indent=2)}\n\n"
                "Return JSON 'findings' array with: title, severity, cwe, vuln_class, "
                "description, evidence, confidence, attack_scenario.\n"
                "If no findings for this class, return empty array."
            ),
        )
        findings = result.get("findings", [])
        for f in findings:
            f["source"] = "vuln_hunter"
            f["vuln_class"] = vuln_class
            f["rl_targeted"] = True
        return findings

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("title", ""), f.get("file", ""), f.get("line", 0))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _severity_breakdown(self, findings: list[dict]) -> dict[str, int]:
        breakdown: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "medium")
            breakdown[sev] = breakdown.get(sev, 0) + 1
        return breakdown
