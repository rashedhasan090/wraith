"""Vulnerability pattern knowledge base."""

from __future__ import annotations

from typing import Any

VULN_PATTERNS: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "severity": "high",
        "indicators": ["cursor.execute", ".query(", "raw SQL", "string format + SQL"],
        "mitre_techniques": ["T1190"],
    },
    "xss_reflected": {
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "severity": "medium",
        "indicators": ["innerHTML", "document.write", "render_template_string"],
        "mitre_techniques": ["T1189"],
    },
    "command_injection": {
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "severity": "critical",
        "indicators": ["os.system", "subprocess", "exec(", "eval("],
        "mitre_techniques": ["T1059"],
    },
    "ssrf": {
        "cwe": "CWE-918",
        "owasp": "A10:2021",
        "severity": "high",
        "indicators": ["requests.get(user_input)", "urllib.urlopen", "fetch(user_url)"],
        "mitre_techniques": ["T1090"],
    },
    "insecure_deserialization": {
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "severity": "high",
        "indicators": ["pickle.loads", "yaml.load", "ObjectInputStream"],
        "mitre_techniques": ["T1059"],
    },
    "auth_bypass": {
        "cwe": "CWE-287",
        "owasp": "A07:2021",
        "severity": "critical",
        "indicators": ["jwt.decode(verify=False)", "admin check missing", "IDOR"],
        "mitre_techniques": ["T1078"],
    },
    "prompt_injection": {
        "cwe": "CWE-77",
        "owasp": "LLM01",
        "severity": "high",
        "indicators": ["user_input + system_prompt", "no input sanitisation for LLM"],
        "mitre_techniques": ["T1059"],
    },
}


class VulnPatterns:
    """Query the vulnerability pattern knowledge base."""

    def get_pattern(self, vuln_class: str) -> dict[str, Any] | None:
        return VULN_PATTERNS.get(vuln_class)

    def get_all(self) -> dict[str, dict[str, Any]]:
        return VULN_PATTERNS

    def get_by_owasp(self, owasp_id: str) -> list[dict[str, Any]]:
        return [
            {"class": k, **v}
            for k, v in VULN_PATTERNS.items()
            if v.get("owasp") == owasp_id
        ]

    def get_indicators(self, vuln_class: str) -> list[str]:
        p = VULN_PATTERNS.get(vuln_class, {})
        return p.get("indicators", [])
