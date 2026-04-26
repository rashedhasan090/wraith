"""Web scanner — real HTTP-based vulnerability probing."""

from __future__ import annotations

from typing import Any

import httpx


class WebScanner:
    """HTTP-based web vulnerability scanner."""

    XSS_PROBE = "<wraith'\">"
    SQLI_PROBE = "wraith' OR '1'='1"
    TRAVERSAL_PROBE = "../../../../etc/passwd"

    async def scan_url(self, url: str) -> list[dict[str, Any]]:
        """Run basic web security checks against a URL."""
        findings = []
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            findings.extend(await self._check_headers(client, url))
            findings.extend(await self._check_cors(client, url))
            findings.extend(await self._check_sensitive_paths(client, url))
        return findings

    async def _check_headers(self, client: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
        """Check for missing security headers."""
        findings = []
        try:
            resp = await client.get(url)
            headers = resp.headers

            security_headers = {
                "strict-transport-security": ("Missing HSTS header", "medium"),
                "content-security-policy": ("Missing CSP header", "medium"),
                "x-frame-options": ("Missing X-Frame-Options (clickjacking)", "low"),
                "x-content-type-options": ("Missing X-Content-Type-Options", "low"),
            }

            for header, (title, severity) in security_headers.items():
                if header not in headers:
                    findings.append({
                        "type": "missing_header",
                        "vuln_class": "security_misconfiguration",
                        "title": title,
                        "severity": severity,
                        "confidence": 0.95,
                        "source": "web_scanner",
                        "url": url,
                    })
        except Exception:
            pass
        return findings

    async def _check_cors(self, client: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
        """Check for overly permissive CORS."""
        findings = []
        try:
            resp = await client.get(url, headers={"Origin": "https://evil.com"})
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == "*" or acao == "https://evil.com":
                findings.append({
                    "type": "cors_misconfiguration",
                    "vuln_class": "cors_misconfiguration",
                    "title": f"Overly permissive CORS: {acao}",
                    "severity": "medium",
                    "confidence": 0.9,
                    "source": "web_scanner",
                    "url": url,
                })
        except Exception:
            pass
        return findings

    async def _check_sensitive_paths(self, client: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
        """Check for exposed sensitive endpoints."""
        findings = []
        base = url.rstrip("/")
        sensitive = [
            (".env", "Environment file exposed"),
            (".git/config", "Git config exposed"),
            ("debug", "Debug endpoint exposed"),
            ("admin", "Admin panel accessible"),
            (".DS_Store", "macOS metadata exposed"),
            ("wp-admin", "WordPress admin exposed"),
            ("phpinfo.php", "PHP info exposed"),
        ]
        for path, title in sensitive:
            try:
                resp = await client.get(f"{base}/{path}")
                if resp.status_code == 200 and len(resp.text) > 50:
                    findings.append({
                        "type": "sensitive_exposure",
                        "vuln_class": "sensitive_data_exposure",
                        "title": title,
                        "severity": "medium" if "admin" not in path else "high",
                        "confidence": 0.7,
                        "source": "web_scanner",
                        "url": f"{base}/{path}",
                    })
            except Exception:
                pass
        return findings
