"""Code scanner — AST-based static analysis."""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Any


class CodeScanner:
    """Static code analysis using AST parsing and pattern matching."""

    def scan_file(self, filepath: str) -> list[dict[str, Any]]:
        """Scan a single Python file using AST."""
        findings = []
        try:
            source = Path(filepath).read_text(errors="ignore")
            tree = ast.parse(source, filename=filepath)
            findings.extend(self._check_ast(tree, filepath))
        except (SyntaxError, UnicodeDecodeError):
            pass
        return findings

    def scan_directory(self, directory: str, exclude: set[str] | None = None) -> list[dict[str, Any]]:
        """Scan all Python files in a directory."""
        exclude = exclude or {"node_modules", ".git", "__pycache__", "venv"}
        findings = []
        for dirpath, dirnames, filenames in os.walk(directory):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for f in filenames:
                if f.endswith(".py"):
                    findings.extend(self.scan_file(os.path.join(dirpath, f)))
        return findings

    def _check_ast(self, tree: ast.AST, filepath: str) -> list[dict[str, Any]]:
        """Check AST for dangerous patterns."""
        findings = []
        for node in ast.walk(tree):
            # Check for eval/exec calls
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name in ("eval", "exec"):
                    findings.append({
                        "file": filepath,
                        "line": node.lineno,
                        "type": "dangerous_function",
                        "title": f"Use of {func_name}()",
                        "cwe": "CWE-95",
                        "severity": "high",
                        "confidence": 0.8,
                    })
                elif func_name in ("os.system", "subprocess.call"):
                    findings.append({
                        "file": filepath,
                        "line": node.lineno,
                        "type": "command_execution",
                        "title": f"OS command execution via {func_name}()",
                        "cwe": "CWE-78",
                        "severity": "high",
                        "confidence": 0.7,
                    })
                elif func_name in ("pickle.loads", "pickle.load"):
                    findings.append({
                        "file": filepath,
                        "line": node.lineno,
                        "type": "deserialization",
                        "title": "Unsafe pickle deserialization",
                        "cwe": "CWE-502",
                        "severity": "high",
                        "confidence": 0.9,
                    })

            # Check for hardcoded secrets
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        if any(s in name_lower for s in ("secret", "password", "api_key", "token")):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                findings.append({
                                    "file": filepath,
                                    "line": node.lineno,
                                    "type": "hardcoded_secret",
                                    "title": f"Hardcoded secret: {target.id}",
                                    "cwe": "CWE-798",
                                    "severity": "medium",
                                    "confidence": 0.75,
                                })
        return findings

    def _get_func_name(self, node: ast.Call) -> str:
        """Extract function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
        return ""
