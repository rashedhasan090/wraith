"""
API security scanner agent — OWASP API Top 10 testing.

Scans REST and GraphQL APIs for broken auth, BOLA, mass assignment,
rate limiting issues, and other API-specific vulnerabilities.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from wraith_cli.agents.base import BaseAgent, AgentResult


class APISecurityAgent(BaseAgent):
    """API security testing for OWASP API Top 10."""

    name = "api_security"
    description = "Scans APIs for OWASP API Top 10 vulnerabilities"

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        target_url = task.get("target_url", "")
        recon_data = context.get("recon_data", {})
        endpoints = recon_data.get("entry_points", [])

        chain.observe(f"Starting API security scan: {target_url}")
        chain.observe(f"Endpoints to test: {len(endpoints)}")

        findings = []

        # Phase 1: Endpoint discovery and fingerprinting
        chain.observe("Phase 1: API fingerprinting")
        api_info = await self._fingerprint_api(target_url)
        chain.infer(f"API type: {api_info.get('type', 'unknown')}")

        # Phase 2: OWASP API Top 10 tests
        chain.observe("Phase 2: OWASP API Top 10 testing")
        try:
            api_findings = await self._test_owasp_api(target_url, endpoints, api_info, recon_data)
            findings.extend(api_findings)
            chain.infer(f"API testing: {len(api_findings)} findings")
        except Exception as e:
            chain.assume(f"API testing failed: {e}")

        chain.conclude(f"API security scan complete: {len(findings)} findings", confidence=0.8)

        self.publish("api_security.complete", {"findings": findings})
        return AgentResult(
            agent_name=self.name, agent_id=self.agent_id,
            success=True, findings=findings, reasoning_chain=chain,
        )

    async def _fingerprint_api(self, url: str) -> dict[str, Any]:
        """Determine API type and version."""
        info: dict[str, Any] = {"type": "REST", "version": "unknown"}
        if not url:
            return info

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Check for GraphQL
                for path in ["/graphql", "/api/graphql"]:
                    try:
                        resp = await client.post(
                            url.rstrip("/") + path,
                            json={"query": "{ __schema { types { name } } }"},
                        )
                        if resp.status_code == 200 and "__schema" in resp.text:
                            info["type"] = "GraphQL"
                            return info
                    except Exception:
                        pass

                # Check for OpenAPI/Swagger
                for path in ["/openapi.json", "/swagger.json", "/api-docs"]:
                    try:
                        resp = await client.get(url.rstrip("/") + path)
                        if resp.status_code == 200:
                            info["has_docs"] = True
                            break
                    except Exception:
                        pass
        except Exception:
            pass
        return info

    async def _test_owasp_api(
        self, url: str, endpoints: list, api_info: dict, recon_data: dict,
    ) -> list[dict[str, Any]]:
        """LLM-powered OWASP API Top 10 analysis."""
        result = await self._call_llm_json(
            system=(
                "You are an API security expert. Analyse the target API for OWASP API Top 10 "
                "vulnerabilities. Consider the endpoints, technology stack, and authentication "
                "mechanisms. Be specific about which endpoints are vulnerable and why."
            ),
            user=(
                f"API URL: {url}\n"
                f"API type: {api_info}\n"
                f"Endpoints: {json.dumps(endpoints[:15], indent=2)}\n"
                f"Technologies: {recon_data.get('technologies', [])}\n\n"
                "Test for:\n"
                "API1: Broken Object Level Authorization (BOLA)\n"
                "API2: Broken Authentication\n"
                "API3: Broken Object Property Level Authorization\n"
                "API4: Unrestricted Resource Consumption\n"
                "API5: Broken Function Level Authorization\n"
                "API6: Server-Side Request Forgery\n"
                "API7: Security Misconfiguration\n"
                "API8: Lack of Protection from Automated Threats\n"
                "API9: Improper Inventory Management\n"
                "API10: Unsafe Consumption of APIs\n\n"
                "Return JSON 'findings' array with: title, api_category (API1-API10), "
                "severity, endpoint, description, evidence, confidence, vuln_class.\n"
            ),
        )
        findings = result.get("findings", [])
        for f in findings:
            f["source"] = "api_security"
            f.setdefault("vuln_class", f"api_{f.get('api_category', 'unknown').lower()}")
        return findings
