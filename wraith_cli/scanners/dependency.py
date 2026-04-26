"""Dependency scanner — cross-references installed packages with CVE data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx


class DependencyScanner:
    """Scan project dependencies for known CVEs."""

    OSV_API = "https://api.osv.dev/v1/query"

    async def scan_requirements(self, path: str) -> list[dict[str, Any]]:
        """Scan a requirements.txt file."""
        deps = self._parse_requirements(Path(path))
        return await self._check_cves(deps, "PyPI")

    async def scan_package_json(self, path: str) -> list[dict[str, Any]]:
        """Scan a package.json file."""
        deps = self._parse_package_json(Path(path))
        return await self._check_cves(deps, "npm")

    def _parse_requirements(self, path: Path) -> list[dict[str, str]]:
        deps = []
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    parts = line.split("==")
                    name = parts[0].split(">=")[0].split("<=")[0].strip()
                    version = parts[1].strip() if len(parts) > 1 else ""
                    deps.append({"name": name, "version": version})
        except Exception:
            pass
        return deps

    def _parse_package_json(self, path: Path) -> list[dict[str, str]]:
        deps = []
        try:
            pkg = json.loads(path.read_text())
            for name, ver in {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}.items():
                deps.append({"name": name, "version": ver.lstrip("^~>=")})
        except Exception:
            pass
        return deps

    async def _check_cves(self, deps: list[dict], ecosystem: str) -> list[dict[str, Any]]:
        """Check dependencies against OSV.dev API."""
        findings = []
        async with httpx.AsyncClient(timeout=15.0) as client:
            for dep in deps[:50]:
                if not dep["version"]:
                    continue
                try:
                    resp = await client.post(
                        self.OSV_API,
                        json={
                            "package": {
                                "name": dep["name"],
                                "ecosystem": ecosystem,
                            },
                            "version": dep["version"],
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for vuln in data.get("vulns", []):
                            severity = "medium"
                            cvss = 0.0
                            for s in vuln.get("severity", []):
                                if s.get("type") == "CVSS_V3":
                                    score_str = s.get("score", "")
                                    try:
                                        # Parse CVSS vector for score
                                        cvss = float(score_str) if score_str.replace(".", "").isdigit() else 0.0
                                    except ValueError:
                                        pass
                            if cvss >= 9.0:
                                severity = "critical"
                            elif cvss >= 7.0:
                                severity = "high"
                            elif cvss >= 4.0:
                                severity = "medium"

                            findings.append({
                                "type": "dependency_cve",
                                "vuln_class": "dependency_cve",
                                "title": f"{vuln.get('id', 'Unknown')} in {dep['name']}=={dep['version']}",
                                "severity": severity,
                                "cve_id": vuln.get("id", ""),
                                "package": dep["name"],
                                "installed_version": dep["version"],
                                "summary": vuln.get("summary", "")[:300],
                                "confidence": 0.95,
                                "source": "dependency_scanner",
                            })
                except Exception:
                    pass
        return findings
