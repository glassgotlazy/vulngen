"""
vulngen/sast/codeql_runner.py
------------------------------
CodeQL runner — multi-language static analysis.

Queries used: codeql/python-queries, codeql/cpp-queries,
              codeql/javascript-queries, codeql/java-queries
              (security-and-quality suite)

Requires CodeQL CLI installed and on PATH.
Download: https://github.com/github/codeql-action/releases

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import csv
import io
import re
import subprocess
import tempfile
from pathlib import Path

from loguru import logger

from vulngen.sast.ensemble import empty_findings


CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)

LANGUAGE_MAP = {
    "python":     "python",
    "cpp":        "cpp",
    "javascript": "javascript",
    "java":       "java",
}

EXT_MAP = {
    "python": ".py",
    "cpp": ".cpp",
    "javascript": ".js",
    "java": ".java",
}

SEVERITY_MAP = {
    "error":   "HIGH",
    "warning": "MEDIUM",
    "note":    "LOW",
}

QUERY_SUITE = "security-and-quality"


class CodeQLRunner:
    """
    Runs CodeQL database create → analyse → SARIF export pipeline
    on a single code snippet in a temp directory.
    """

    TOOL = "codeql"

    def run(self, code: str, language: str) -> dict:
        ql_lang = LANGUAGE_MAP.get(language)
        ext = EXT_MAP.get(language)
        if not ql_lang or not ext:
            return empty_findings(self.TOOL)

        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = Path(tmpdir) / "src"
            src_dir.mkdir()
            (src_dir / f"target{ext}").write_text(code, encoding="utf-8")

            db_dir = Path(tmpdir) / "db"
            results_file = Path(tmpdir) / "results.sarif"

            try:
                # Step 1: Create DB
                subprocess.run(
                    [
                        "codeql", "database", "create",
                        str(db_dir),
                        f"--language={ql_lang}",
                        f"--source-root={src_dir}",
                        "--overwrite",
                    ],
                    capture_output=True, timeout=120, check=True,
                )
                # Step 2: Analyse
                subprocess.run(
                    [
                        "codeql", "database", "analyze",
                        str(db_dir),
                        f"{ql_lang}-{QUERY_SUITE}.qls",
                        "--format=sarif-latest",
                        f"--output={results_file}",
                    ],
                    capture_output=True, timeout=300, check=True,
                )
                raw = results_file.read_text(encoding="utf-8") if results_file.exists() else ""
                return self._parse_sarif(raw)

            except FileNotFoundError:
                logger.warning(
                    "CodeQL CLI not found. Download from "
                    "https://github.com/github/codeql-action/releases"
                )
                return empty_findings(self.TOOL)
            except subprocess.CalledProcessError as exc:
                logger.warning(f"CodeQL failed: {exc.stderr[:200] if exc.stderr else ''}")
                return empty_findings(self.TOOL)
            except subprocess.TimeoutExpired:
                logger.warning("CodeQL timed out")
                return empty_findings(self.TOOL)

    def _parse_sarif(self, sarif_text: str) -> dict:
        import json
        findings = empty_findings(self.TOOL)
        findings["raw_output"] = sarif_text[:500]

        try:
            data = json.loads(sarif_text)
        except json.JSONDecodeError:
            return findings

        cwes: set = set()
        locations = []
        max_sev = ""

        for run in data.get("runs", []):
            # Build rule-id → CWE map from rules
            rule_cwes: dict = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rule_id = rule.get("id", "")
                tags = rule.get("properties", {}).get("tags", [])
                for tag in tags:
                    for m in CWE_PATTERN.finditer(str(tag)):
                        rule_cwes.setdefault(rule_id, set()).add(f"CWE-{m.group(1)}")

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                for cwe in rule_cwes.get(rule_id, set()):
                    cwes.add(cwe)

                sev_raw = result.get("level", "").lower()
                sev = SEVERITY_MAP.get(sev_raw, "")
                if sev and (not max_sev or sev > max_sev):
                    max_sev = sev

                locs = result.get("locations", [])
                for loc in locs:
                    region = (
                        loc.get("physicalLocation", {})
                        .get("region", {})
                    )
                    locations.append({
                        "line": region.get("startLine"),
                        "col": region.get("startColumn"),
                        "message": result.get("message", {}).get("text", "")[:200],
                        "rule_id": rule_id,
                    })

        findings["cwe_ids"] = sorted(cwes)
        findings["severity"] = max_sev
        findings["locations"] = locations
        return findings
