"""
CVE intelligence agent — real NVD/CVE API correlation.

Queries the NVD API v2.0 to find known CVEs for detected dependencies,
then uses LLM reasoning to assess real-world exploitability in context.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from wraith_cli.agents.base import BaseAgent, AgentResult


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEIntelAgent(BaseAgent):
    """CVE database correlation and exploitability assessment."""

    name = "cve_intel"
    description = "Correlates dependencies with NVD/CVE database and assesses exploitability"

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        recon_data = context.get("recon_data", {})
        dependencies = recon_data.get("dependencies", [])

        chain.observe(f"Starting CVE intelligence for {len(dependencies)} dependencies")

        if not dependencies:
            chain.conclude("No dependencies to analyse", confidence=1.0)
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=True, findings=[], reasoning_chain=chain,
            )

        # Phase 1: Query NVD API for each dependency
        chain.observe("Phase 1: Querying NVD API")
        cve_matches: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            for dep in dependencies[:30]:  # Rate limit friendly
                try:
                    cves = await self._query_nvd(client, dep["name"], dep.get("version", ""))
                    cve_matches.extend(cves)
                except Exception as e:
                    chain.assume(f"NVD query failed for {dep['name']}: {e}")

        chain.infer(f"Found {len(cve_matches)} CVE matches from NVD")

        # Phase 2: LLM contextual exploitability assessment
        chain.observe("Phase 2: Contextual exploitability assessment")
        findings = []
        if cve_matches:
            try:
                findings = await self._assess_exploitability(cve_matches, dependencies, recon_data)
                chain.infer(f"Assessed {len(findings)} CVEs for exploitability")
            except Exception as e:
                chain.assume(f"LLM assessment unavailable: {e}")
                # Fall back to raw CVE data
                for cve in cve_matches:
                    findings.append({
                        "type": "known_cve",
                        "vuln_class": "dependency_cve",
                        "title": f"{cve.get('id', 'Unknown')} in {cve.get('package', '')}",
                        "severity": cve.get("severity", "medium"),
                        "cve_id": cve.get("id", ""),
                        "description": cve.get("description", ""),
                        "cvss": cve.get("cvss", 0.0),
                        "confidence": 0.9,
                        "source": "cve_intel",
                    })

        chain.conclude(f"CVE intelligence complete: {len(findings)} findings", confidence=0.9)

        self.publish("cve_intel.complete", {"findings": findings})
        return AgentResult(
            agent_name=self.name, agent_id=self.agent_id,
            success=True, findings=findings, reasoning_chain=chain,
        )

    async def _query_nvd(self, client: httpx.AsyncClient, package: str, version: str) -> list[dict]:
        """Query the NVD API for CVEs affecting a package."""
        params = {"keywordSearch": package, "resultsPerPage": 5}
        nvd_key = self.config.nvd_api_key
        headers = {"apiKey": nvd_key} if nvd_key else {}

        resp = await client.get(NVD_API_BASE, params=params, headers=headers)
        if resp.status_code != 200:
            return []

        data = resp.json()
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc_data = cve.get("descriptions", [])
            description = next((d["value"] for d in desc_data if d.get("lang") == "en"), "")

            # Extract CVSS score
            metrics = cve.get("metrics", {})
            cvss = 0.0
            severity = "medium"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "MEDIUM").lower()
                    break

            results.append({
                "id": cve_id,
                "package": package,
                "version": version,
                "description": description[:500],
                "cvss": cvss,
                "severity": severity,
            })
        return results

    async def _assess_exploitability(
        self, cve_matches: list[dict], dependencies: list[dict], recon_data: dict,
    ) -> list[dict[str, Any]]:
        """LLM assessment of real-world exploitability."""
        result = await self._call_llm_json(
            system=(
                "You are a vulnerability analyst. For each CVE, assess whether it is "
                "actually exploitable in this specific deployment context. Consider the "
                "technology stack, how the dependency is used, and whether the vulnerable "
                "code path is reachable."
            ),
            user=(
                f"CVE matches: {json.dumps(cve_matches[:15], indent=2)}\n"
                f"Technology stack: {recon_data.get('technologies', [])}\n"
                f"Entry points: {len(recon_data.get('entry_points', []))}\n\n"
                "Return JSON 'findings' array with: title, cve_id, severity, cvss, "
                "vuln_class (use 'dependency_cve'), exploitable (bool), "
                "exploitability_reasoning, confidence, recommended_action.\n"
            ),
        )
        findings = result.get("findings", [])
        for f in findings:
            f["source"] = "cve_intel"
            f["vuln_class"] = "dependency_cve"
        return findings
