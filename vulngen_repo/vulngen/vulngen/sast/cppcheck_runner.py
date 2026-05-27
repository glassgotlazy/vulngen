"""
vulngen/sast/cppcheck_runner.py
--------------------------------
Cppcheck runner — C/C++ static analysis.

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from loguru import logger

from vulngen.sast.ensemble import empty_findings


CWE_PATTERN = re.compile(r"CWE-(\d+)|cwe=(\d+)", re.IGNORECASE)

SEVERITY_MAP = {
    "error":       "HIGH",
    "warning":     "MEDIUM",
    "portability": "LOW",
    "performance": "LOW",
    "style":       "LOW",
    "information": "LOW",
}


class CppcheckRunner:
    """Runs Cppcheck on C/C++ code and returns normalised findings."""

    TOOL = "cppcheck"

    def run(self, code: str, language: str) -> dict:
        if language != "cpp":
            return empty_findings(self.TOOL)

        with tempfile.NamedTemporaryFile(
            suffix=".cpp", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(code)
            tmp_path = Path(tmp.name)

        try:
            result = subprocess.run(
                [
                    "cppcheck",
                    "--enable=warning,security,portability",
                    "--std=c++17",
                    "--addon=cert",
                    "--template={file}:{line}:{severity}:{id}:{message}",
                    "--suppress=missingIncludeSystem",
                    str(tmp_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Cppcheck writes to stderr
            return self._parse(result.stderr)

        except FileNotFoundError:
            logger.warning("cppcheck not found. Install with: sudo apt install cppcheck")
            return empty_findings(self.TOOL)
        except subprocess.TimeoutExpired:
            logger.warning("cppcheck timed out")
            return empty_findings(self.TOOL)
        finally:
            tmp_path.unlink(missing_ok=True)

    def _parse(self, stderr: str) -> dict:
        findings = empty_findings(self.TOOL)
        findings["raw_output"] = stderr

        cwes: set = set()
        locations = []
        max_sev_rank = 0

        for line in stderr.splitlines():
            parts = line.split(":", 5)
            if len(parts) < 5:
                continue
            _, line_no, sev_raw, rule_id, message = (
                parts[0], parts[1], parts[2], parts[3],
                parts[4] if len(parts) > 4 else ""
            )
            sev_raw = sev_raw.strip().lower()
            sev = SEVERITY_MAP.get(sev_raw, "")
            sev_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(sev, 0)
            if sev_rank > max_sev_rank:
                max_sev_rank = sev_rank

            # Extract CWE from rule_id or message
            for m in CWE_PATTERN.finditer(f"{rule_id} {message}"):
                num = m.group(1) or m.group(2)
                cwes.add(f"CWE-{num}")

            # Map known Cppcheck IDs to CWEs
            cwe = _CPPCHECK_CWE.get(rule_id.strip())
            if cwe:
                cwes.add(cwe)

            locations.append({
                "line": line_no.strip(),
                "message": message.strip()[:200],
                "rule_id": rule_id.strip(),
                "severity": sev,
            })

        sev_name = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(max_sev_rank, "")
        findings["cwe_ids"] = sorted(cwes)
        findings["severity"] = sev_name
        findings["locations"] = locations
        return findings


# Known Cppcheck rule IDs → CWE
_CPPCHECK_CWE = {
    "bufferAccessOutOfBounds":    "CWE-125",
    "outOfBounds":                "CWE-125",
    "outOfBoundsWrite":           "CWE-787",
    "nullPointer":                "CWE-476",
    "uninitvar":                  "CWE-457",
    "doubleFree":                 "CWE-415",
    "memleak":                    "CWE-401",
    "resourceLeak":               "CWE-404",
    "useAfterFree":               "CWE-416",
    "integerOverflow":            "CWE-190",
    "signedIntegerOverflow":      "CWE-190",
    "bufferOverrun":              "CWE-120",
    "strncat":                    "CWE-120",
    "strncatUsage":               "CWE-120",
    "sprintfOverlappingData":     "CWE-120",
    "racecondition":              "CWE-362",
    "copyBufferWithoutCheck":     "CWE-120",
}
