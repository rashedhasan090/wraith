"""
Code analyst agent — static analysis with LLM-powered semantic understanding.

Reads real source files, performs pattern matching for dangerous functions,
and uses LLM reasoning to identify complex vulnerabilities that static
analysis tools miss (business logic flaws, race conditions, etc.).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from wraith_cli.agents.base import BaseAgent, AgentResult


# Dangerous patterns by language
DANGEROUS_PATTERNS: dict[str, list[dict[str, str]]] = {
    "Python": [
        {"pattern": r"eval\s*\(", "cwe": "CWE-95", "desc": "Use of eval()"},
        {"pattern": r"exec\s*\(", "cwe": "CWE-95", "desc": "Use of exec()"},
        {"pattern": r"pickle\.loads?\s*\(", "cwe": "CWE-502", "desc": "Unsafe deserialization (pickle)"},
        {"pattern": r"yaml\.load\s*\(", "cwe": "CWE-502", "desc": "Unsafe YAML load"},
        {"pattern": r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True", "cwe": "CWE-78", "desc": "Shell injection risk"},
        {"pattern": r"os\.system\s*\(", "cwe": "CWE-78", "desc": "OS command execution"},
        {"pattern": r"__import__\s*\(", "cwe": "CWE-94", "desc": "Dynamic import"},
        {"pattern": r"render_template_string\s*\(", "cwe": "CWE-1336", "desc": "SSTI via template string"},
        {"pattern": r"\.format\(.*request\.", "cwe": "CWE-134", "desc": "Format string with user input"},
        {"pattern": r"cursor\.execute\s*\([^,]*%", "cwe": "CWE-89", "desc": "SQL injection (string formatting)"},
        {"pattern": r"cursor\.execute\s*\([^,]*\+", "cwe": "CWE-89", "desc": "SQL injection (concatenation)"},
        {"pattern": r"SECRET_KEY\s*=\s*['\"]", "cwe": "CWE-798", "desc": "Hardcoded secret key"},
        {"pattern": r"password\s*=\s*['\"](?!\\{)", "cwe": "CWE-798", "desc": "Hardcoded password"},
    ],
    "JavaScript": [
        {"pattern": r"eval\s*\(", "cwe": "CWE-95", "desc": "Use of eval()"},
        {"pattern": r"innerHTML\s*=", "cwe": "CWE-79", "desc": "innerHTML assignment (XSS)"},
        {"pattern": r"document\.write\s*\(", "cwe": "CWE-79", "desc": "document.write (XSS)"},
        {"pattern": r"\.html\s*\(", "cwe": "CWE-79", "desc": "jQuery .html() (XSS)"},
        {"pattern": r"child_process\.", "cwe": "CWE-78", "desc": "Child process execution"},
        {"pattern": r"new\s+Function\s*\(", "cwe": "CWE-95", "desc": "Dynamic function creation"},
        {"pattern": r"require\s*\(\s*[^'\"]", "cwe": "CWE-94", "desc": "Dynamic require"},
        {"pattern": r"\.query\s*\([^,]*\+", "cwe": "CWE-89", "desc": "SQL concatenation"},
    ],
    "Java": [
        {"pattern": r"Runtime\.getRuntime\(\)\.exec", "cwe": "CWE-78", "desc": "Runtime exec"},
        {"pattern": r"ProcessBuilder\s*\(", "cwe": "CWE-78", "desc": "Process execution"},
        {"pattern": r"ObjectInputStream", "cwe": "CWE-502", "desc": "Java deserialization"},
        {"pattern": r"Statement\.execute", "cwe": "CWE-89", "desc": "Non-prepared SQL statement"},
        {"pattern": r"createQuery\s*\([^?]*\+", "cwe": "CWE-89", "desc": "HQL injection"},
    ],
}

EXTENSION_TO_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "JavaScript",
    ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP",
}


class CodeAnalystAgent(BaseAgent):
    """Static code analysis with LLM-powered semantic understanding."""

    name = "code_analyst"
    description = "Analyses source code for vulnerabilities using pattern matching and LLM reasoning"

    async def execute(self, task: dict[str, Any], context: dict[str, Any]) -> AgentResult:
        chain = self.create_chain()
        scan_config = task.get("scan_config", {})
        recon_data = context.get("recon_data", {})

        target = scan_config.get("target", ".")
        chain.observe(f"Starting code analysis on: {target}")

        # Get file list from recon or enumerate ourselves
        files = recon_data.get("files", [])
        if not files:
            target_path = Path(target).resolve()
            exclude = set(scan_config.get("exclude_patterns", [
                "node_modules", ".git", "__pycache__", "venv", ".venv",
            ]))
            files = self._get_source_files(target_path, exclude)

        chain.observe(f"Analysing {len(files)} source files")

        # Phase 1: Pattern-based scanning
        pattern_findings = self._pattern_scan(files)
        chain.infer(f"Pattern scan: {len(pattern_findings)} potential issues")

        # Phase 2: LLM semantic analysis on high-risk files
        sensitive_files = recon_data.get("sensitive_files", [])
        llm_findings = []
        if sensitive_files:
            chain.observe(f"LLM semantic analysis on {len(sensitive_files[:10])} sensitive files")
            try:
                llm_findings = await self._semantic_analysis(sensitive_files[:10])
                chain.infer(f"LLM analysis: {len(llm_findings)} additional findings")
            except Exception as e:
                chain.assume(f"LLM analysis unavailable: {e}")

        all_findings = pattern_findings + llm_findings

        chain.conclude(
            f"Code analysis complete: {len(all_findings)} findings",
            confidence=0.85,
        )

        self.publish("code_analyst.complete", {"findings": all_findings})
        return AgentResult(
            agent_name=self.name, agent_id=self.agent_id,
            success=True, findings=all_findings,
            data={"pattern_count": len(pattern_findings), "llm_count": len(llm_findings)},
            reasoning_chain=chain,
        )

    def _get_source_files(self, root: Path, exclude: set[str]) -> list[str]:
        import os
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for f in filenames:
                if any(f.endswith(ext) for ext in EXTENSION_TO_LANG):
                    files.append(os.path.join(dirpath, f))
        return files[:500]

    def _pattern_scan(self, files: list[str]) -> list[dict[str, Any]]:
        """Scan files for dangerous patterns."""
        findings = []
        for fpath in files:
            ext = Path(fpath).suffix.lower()
            lang = EXTENSION_TO_LANG.get(ext)
            if not lang or lang not in DANGEROUS_PATTERNS:
                continue
            try:
                content = Path(fpath).read_text(errors="ignore")
                for line_no, line in enumerate(content.split("\n"), 1):
                    for pattern_def in DANGEROUS_PATTERNS[lang]:
                        if re.search(pattern_def["pattern"], line):
                            findings.append({
                                "type": "code_vulnerability",
                                "vuln_class": self._cwe_to_class(pattern_def["cwe"]),
                                "title": pattern_def["desc"],
                                "file": fpath,
                                "line": line_no,
                                "code": line.strip()[:200],
                                "cwe": pattern_def["cwe"],
                                "severity": self._cwe_severity(pattern_def["cwe"]),
                                "confidence": 0.7,
                                "source": "code_analyst",
                            })
            except (OSError, UnicodeDecodeError):
                continue
        return findings

    async def _semantic_analysis(self, files: list[str]) -> list[dict[str, Any]]:
        """Use LLM for deep semantic vulnerability analysis."""
        from rich.console import Console as _C
        _console = _C()
        findings = []
        batch = files[:5]  # Limit to avoid token explosion
        for i, fpath in enumerate(batch, 1):
            fname = Path(fpath).name
            _console.print(f"    [dim]LLM analysing ({i}/{len(batch)}): {fname}[/]")
            try:
                content = Path(fpath).read_text(errors="ignore")[:8000]
            except Exception:
                continue

            result = await self._call_llm_json(
                system=(
                    "You are an expert code auditor. Analyse the following source code "
                    "for security vulnerabilities. Focus on logic flaws, race conditions, "
                    "and complex vulnerabilities that pattern matching would miss. "
                    "Return JSON with 'findings' array."
                ),
                user=(
                    f"File: {fpath}\n\n```\n{content}\n```\n\n"
                    "For each finding, provide:\n"
                    '- "title": description\n'
                    '- "severity": critical/high/medium/low\n'
                    '- "cwe": CWE ID\n'
                    '- "vuln_class": category (e.g., sql_injection, auth_bypass)\n'
                    '- "explanation": detailed reasoning\n'
                    '- "line": approximate line number\n'
                    '- "confidence": 0.0-1.0\n'
                ),
            )
            for f in result.get("findings", []):
                f["file"] = fpath
                f["source"] = "code_analyst_llm"
                findings.append(f)
        return findings

    def _cwe_to_class(self, cwe: str) -> str:
        mapping = {
            "CWE-89": "sql_injection", "CWE-79": "xss_reflected",
            "CWE-78": "command_injection", "CWE-95": "command_injection",
            "CWE-94": "command_injection", "CWE-502": "insecure_deserialization",
            "CWE-798": "sensitive_data_exposure", "CWE-22": "path_traversal",
            "CWE-1336": "xss_stored", "CWE-134": "command_injection",
        }
        return mapping.get(cwe, "security_misconfiguration")

    def _cwe_severity(self, cwe: str) -> str:
        high_cwes = {"CWE-89", "CWE-78", "CWE-95", "CWE-502", "CWE-94", "CWE-1336"}
        medium_cwes = {"CWE-79", "CWE-22", "CWE-134"}
        if cwe in high_cwes:
            return "high"
        if cwe in medium_cwes:
            return "medium"
        return "low"
