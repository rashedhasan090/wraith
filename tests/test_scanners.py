"""Tests for scanner modules."""

import os
import pytest
from wraith_cli.scanners.code import CodeScanner


class TestCodeScanner:
    def test_scan_dangerous_eval(self, tmp_path):
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text("result = eval(user_input)\n")

        scanner = CodeScanner()
        findings = scanner.scan_file(str(vuln_file))
        assert len(findings) >= 1
        assert findings[0]["cwe"] == "CWE-95"

    def test_scan_hardcoded_secret(self, tmp_path):
        vuln_file = tmp_path / "config.py"
        vuln_file.write_text('SECRET_KEY = "hardcoded_value"\n')

        scanner = CodeScanner()
        findings = scanner.scan_file(str(vuln_file))
        assert any(f["cwe"] == "CWE-798" for f in findings)

    def test_scan_clean_file(self, tmp_path):
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("x = 1 + 2\nprint(x)\n")

        scanner = CodeScanner()
        findings = scanner.scan_file(str(clean_file))
        assert len(findings) == 0

    def test_scan_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(x)\n")
        (tmp_path / "b.py").write_text("x = 1\n")

        scanner = CodeScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert len(findings) >= 1
