"""
Multi-format report generation — JSON, Markdown, HTML.

Produces structured vulnerability assessment reports with executive
summaries, detailed findings, attack chains, and remediation plans.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ReportGenerator:
    """Generate structured vulnerability reports."""

    def __init__(self, scan_data: dict[str, Any]) -> None:
        self.scan_data = scan_data
        self.findings = scan_data.get("findings", [])
        self.chains = scan_data.get("attack_chains", [])
        self.remediations = scan_data.get("remediations", [])
        self.recon = scan_data.get("recon_data", {})
        self.rl_stats = scan_data.get("rl_stats", {})

    def to_json(self, path: Path) -> None:
        """Export full report as JSON."""
        report = self._build_report()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str))

    def to_markdown(self, path: Path) -> None:
        """Export report as Markdown."""
        report = self._build_report()
        md = self._render_markdown(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md)

    def to_html(self, path: Path) -> None:
        """Export report as standalone HTML."""
        report = self._build_report()
        html = self._render_html(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html)

    def _build_report(self) -> dict[str, Any]:
        severity_counts = {}
        for f in self.findings:
            s = f.get("severity", "medium")
            severity_counts[s] = severity_counts.get(s, 0) + 1

        return {
            "meta": {
                "tool": "WRAITH CLI",
                "version": "0.3.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": self.recon.get("target", "unknown"),
            },
            "executive_summary": {
                "total_findings": len(self.findings),
                "severity_breakdown": severity_counts,
                "attack_chains": len(self.chains),
                "technologies": self.recon.get("technologies", []),
                "risk_rating": self._overall_risk(severity_counts),
            },
            "findings": self.findings,
            "attack_chains": self.chains,
            "remediations": self.remediations,
            "rl_stats": self.rl_stats,
            "recon": self.recon,
        }

    def _overall_risk(self, counts: dict[str, int]) -> str:
        if counts.get("critical", 0) > 0:
            return "CRITICAL"
        if counts.get("high", 0) > 0:
            return "HIGH"
        if counts.get("medium", 0) > 0:
            return "MEDIUM"
        return "LOW"

    def _render_markdown(self, report: dict) -> str:
        meta = report["meta"]
        summary = report["executive_summary"]
        lines = [
            f"# WRAITH Vulnerability Assessment Report",
            f"",
            f"**Target:** {meta['target']}",
            f"**Date:** {meta['timestamp']}",
            f"**Tool:** {meta['tool']} v{meta['version']}",
            f"",
            f"## Executive Summary",
            f"",
            f"- **Total findings:** {summary['total_findings']}",
            f"- **Risk rating:** {summary['risk_rating']}",
            f"- **Attack chains:** {summary['attack_chains']}",
            f"- **Technologies:** {', '.join(summary['technologies'])}",
            f"",
            f"### Severity Breakdown",
            f"",
        ]
        for sev, count in sorted(summary["severity_breakdown"].items()):
            lines.append(f"- {sev.upper()}: {count}")

        lines.extend(["", "## Findings", ""])
        for i, f in enumerate(report["findings"], 1):
            sev = f.get("severity", "medium").upper()
            lines.append(f"### {i}. [{sev}] {f.get('title', 'Unknown')}")
            lines.append(f"")
            if f.get("cwe"):
                lines.append(f"- **CWE:** {f['cwe']}")
            if f.get("file"):
                lines.append(f"- **File:** `{f['file']}`")
            if f.get("description"):
                lines.append(f"- **Description:** {f['description']}")
            if f.get("confidence"):
                lines.append(f"- **Confidence:** {f['confidence']:.0%}")
            lines.append("")

        if report["attack_chains"]:
            lines.extend(["## Attack Chains", ""])
            for chain in report["attack_chains"]:
                lines.append(f"### {chain.get('title', 'Chain')}")
                for step in chain.get("steps", []):
                    lines.append(f"  {step.get('step_num', '?')}. {step.get('description', '')}")
                lines.append("")

        if report["remediations"]:
            lines.extend(["## Remediation Plan", ""])
            for r in report["remediations"]:
                lines.append(f"### [{r.get('priority', 'P3')}] {r.get('title', 'Fix')}")
                lines.append(f"{r.get('description', '')}")
                lines.append("")

        if report.get("rl_stats"):
            lines.extend([
                "## RL Agent Statistics", "",
                f"- **Strategy:** {report['rl_stats'].get('strategy', 'N/A')}",
                f"- **Episodes:** {report['rl_stats'].get('episode_count', 0)}",
                f"- **Replay buffer:** {report['rl_stats'].get('replay_size', 0)} experiences",
                "",
            ])

        return "\n".join(lines)

    def _render_html(self, report: dict) -> str:
        md = self._render_markdown(report)
        # Simple HTML wrapper
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WRAITH Report — {report['meta']['target']}</title>
<style>
body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.6; color: #1a1a1a; }}
h1 {{ color: #dc2626; border-bottom: 3px solid #dc2626; padding-bottom: 0.5rem; }}
h2 {{ color: #991b1b; margin-top: 2rem; }}
h3 {{ color: #374151; }}
code {{ background: #f3f4f6; padding: 0.15em 0.4em; border-radius: 3px; font-size: 0.9em; }}
pre {{ background: #1f2937; color: #f9fafb; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
</style>
</head>
<body>
<pre>{md}</pre>
</body>
</html>"""
