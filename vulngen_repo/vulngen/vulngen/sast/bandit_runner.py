"""
vulngen/sast/bandit_runner.py
------------------------------
Bandit runner — Python-only SAST tool.

Paper: Table V — Bandit contributes to Python VR detection.

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from loguru import logger

from vulngen.sast.ensemble import empty_findings


SEVERITY_MAP = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH"}

BANDIT_CWE_MAP = {
    "B105": "CWE-259", "B106": "CWE-259", "B107": "CWE-259",
    "B108": "CWE-200", "B301": "CWE-502", "B303": "CWE-327",
    "B307": "CWE-78",  "B311": "CWE-338", "B324": "CWE-327",
    "B501": "CWE-295", "B601": "CWE-78",  "B602": "CWE-78",
    "B603": "CWE-78",  "B608": "CWE-89",  "B506": "CWE-611",
}


class BanditRunner:
    """Runs Bandit on Python code snippets and returns normalised findings."""

    TOOL = "bandit"

    def run(self, code: str, language: str) -> dict:
        if language != "python":
            return empty_findings(self.TOOL)

        with tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)

        try:
            result = subprocess.run(
                ["bandit", "-f", "json", "-q", str(tmp_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            raw = result.stdout
            return self._parse(raw)
        except FileNotFoundError:
            logger.warning("Bandit not found. Install with: pip install bandit")
            return empty_findings(self.TOOL)
        except subprocess.TimeoutExpired:
            logger.warning("Bandit timed out")
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
        cwes = set()
        locations = []
        max_sev = ""

        for issue in results:
            test_id = issue.get("test_id", "")
            cwe = BANDIT_CWE_MAP.get(test_id)
            if cwe:
                cwes.add(cwe)
            sev = issue.get("issue_severity", "").upper()
            if sev and (not max_sev or sev > max_sev):
                max_sev = sev
            locations.append({
                "line": issue.get("line_number"),
                "message": issue.get("issue_text", ""),
                "test_id": test_id,
            })

        findings["cwe_ids"] = sorted(cwes)
        findings["severity"] = SEVERITY_MAP.get(max_sev, "")
        findings["locations"] = locations
        return findings
