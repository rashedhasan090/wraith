"""
OSINT reconnaissance agent — open-source intelligence gathering.

Performs DNS enumeration, subdomain discovery, technology fingerprinting,
and public data collection on target domains.
"""

from __future__ import annotations

import json
import socket
from typing import Any

import httpx

from wraith_cli.agents.base import BaseAgent, AgentResult


class OSINTReconAgent(BaseAgent):
    """Open-source intelligence gathering."""

    name = "osint_recon"
    description = "OSINT reconnaissance — DNS, subdomains, tech fingerprinting, public data"

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        target = task.get("target", "")

        chain.observe(f"Starting OSINT recon on: {target}")

        if not target:
            return AgentResult(
                agent_name=self.name, agent_id=self.agent_id,
                success=False, errors=["No target specified"],
            )

        data: dict[str, Any] = {"target": target}

        # DNS resolution
        chain.observe("DNS resolution")
        try:
            ips = socket.gethostbyname_ex(target)[2]
            data["ip_addresses"] = ips
            chain.infer(f"Resolved to: {ips}")
        except socket.gaierror:
            chain.assume(f"DNS resolution failed for {target}")
            data["ip_addresses"] = []

        # HTTP headers and technology fingerprinting
        chain.observe("HTTP fingerprinting")
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            try:
                resp = await client.get(f"https://{target}")
                headers = dict(resp.headers)
                data["http_status"] = resp.status_code
                data["server"] = headers.get("server", "unknown")
                data["security_headers"] = {
                    "strict-transport-security": headers.get("strict-transport-security"),
                    "content-security-policy": headers.get("content-security-policy"),
                    "x-frame-options": headers.get("x-frame-options"),
                    "x-content-type-options": headers.get("x-content-type-options"),
                    "x-xss-protection": headers.get("x-xss-protection"),
                }
                chain.infer(f"Server: {data['server']}, Status: {data['http_status']}")
            except Exception as e:
                chain.assume(f"HTTP request failed: {e}")

        # LLM-assisted OSINT analysis
        chain.observe("LLM OSINT analysis")
        try:
            osint_analysis = await self._call_llm_json(
                system=(
                    "You are an OSINT analyst. Based on the target domain and gathered data, "
                    "identify potential attack vectors, exposed services, and security posture."
                ),
                user=(
                    f"Target: {target}\n"
                    f"Data gathered: {json.dumps(data, indent=2, default=str)}\n\n"
                    "Return JSON with: 'assessment' (overall security posture), "
                    "'attack_vectors' (list), 'exposed_services' (list), "
                    "'recommendations' (list), 'risk_level' (high/medium/low)"
                ),
            )
            data["analysis"] = osint_analysis
            chain.infer(f"Risk level: {osint_analysis.get('risk_level', 'unknown')}")
        except Exception as e:
            chain.assume(f"LLM analysis failed: {e}")

        chain.conclude("OSINT reconnaissance complete", confidence=0.8)

        self.publish("osint.complete", data)
        return AgentResult(
            agent_name=self.name, agent_id=self.agent_id,
            success=True, data=data, reasoning_chain=chain,
        )
