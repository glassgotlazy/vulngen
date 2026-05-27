"""
vulngen/sast/semgrep_runner.py
-------------------------------
Semgrep runner — supports Python, C/C++, JavaScript, Java.

Rulesets used (Section IV-A):
  p/security-audit
  p/owasp-top-ten
  p/cwe-top-25

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from loguru import logger

from vulngen.sast.ensemble import empty_findings


CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)

LANGUAGE_EXT = {
    "python": ".py",
    "cpp": ".cpp",
    "javascript": ".js",
    "java": ".java",
}

SEMGREP_RULESETS = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/cwe-top-25",
]

SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


class SemgrepRunner:
    """Runs Semgrep with security rulesets and returns normalised findings."""

    TOOL = "semgrep"

    def run(self, code: str, language: str) -> dict:
        ext = LANGUAGE_EXT.get(language)
        if not ext:
            return empty_findings(self.TOOL)

        with tempfile.NamedTemporaryFile(
            suffix=ext, mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)

        try:
            cmd = [
                "semgrep",
                "--json",
                "--quiet",
                "--timeout", "30",
            ]
            for ruleset in SEMGREP_RULESETS:
                cmd += ["--config", ruleset]
            cmd.append(str(tmp_path))

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            return self._parse(result.stdout)

        except FileNotFoundError:
            logger.warning("Semgrep not found. Install: pip install semgrep")
            return empty_findings(self.TOOL)
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep timed out")
            return empty_findings(self.TOOL)
        finally:
            tmp_path.unlink(missing_ok=True)

    def _parse(self, raw_json: str) -> dict:
        findings = empty_findings(self.TOOL)
        findings["raw_output"] = raw_json

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return findings

        results = data.get("results", [])
        cwes: set = set()
        locations = []
        max_sev = ""

        for r in results:
            # Extract CWE from rule metadata
            metadata = r.get("extra", {}).get("metadata", {})
            for val in metadata.values():
                if isinstance(val, str):
                    for m in CWE_PATTERN.finditer(val):
                        cwes.add(f"CWE-{m.group(1)}")

            # Extract CWE from message
            msg = r.get("extra", {}).get("message", "")
            for m in CWE_PATTERN.finditer(msg):
                cwes.add(f"CWE-{m.group(1)}")

            sev_raw = r.get("extra", {}).get("severity", "").upper()
            sev = SEVERITY_MAP.get(sev_raw, "")
            if sev and (not max_sev or sev > max_sev):
                max_sev = sev

            locations.append({
                "line": r.get("start", {}).get("line"),
                "col": r.get("start", {}).get("col"),
                "message": msg[:200],
                "rule_id": r.get("check_id", ""),
            })

        findings["cwe_ids"] = sorted(cwes)
        findings["severity"] = max_sev
        findings["locations"] = locations
        return findings
