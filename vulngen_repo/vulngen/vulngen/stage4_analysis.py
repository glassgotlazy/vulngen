"""
vulngen/stage4_analysis.py
--------------------------
Stage 4 — SAST ensemble + dynamic analysis.

Ensemble (Section IV-A, Table V):
  Bandit          — Python
  Semgrep         — Python, JavaScript, Java, C/C++
  CodeQL          — Python, JavaScript, Java, C/C++
  Cppcheck        — C/C++
  SpotBugs/FindSecBugs — Java

Majority voting: flag as vulnerable when ≥ 2 tools agree.
Measured FPR = 8.3%, κ = 0.81 (Section IV-E).

Dynamic analysis:
  AFL++           — C/C++ fuzzing
  AddressSanitizer— C/C++ memory errors

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import subprocess
import tempfile
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from loguru import logger

from vulngen.sast.bandit_runner import BanditRunner
from vulngen.sast.semgrep_runner import SemgrepRunner
from vulngen.sast.codeql_runner import CodeQLRunner
from vulngen.sast.cppcheck_runner import CppcheckRunner


# ---------------------------------------------------------------------------
# CWE patterns for quick extraction from tool output
# ---------------------------------------------------------------------------

CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# SAST Ensemble
# ---------------------------------------------------------------------------

class SASTEnsemble:
    """
    Runs multiple SAST tools and applies majority-vote aggregation.

    Findings structure (per tool):
      {
        "tool": str,
        "cwe_ids": List[str],
        "severity": str,          # LOW / MEDIUM / HIGH / CRITICAL
        "locations": List[dict],
        "raw_output": str,
      }
    """

    LANGUAGE_TOOLS = {
        "python":     ["bandit", "semgrep", "codeql"],
        "cpp":        ["cppcheck", "semgrep", "codeql"],
        "javascript": ["semgrep", "codeql"],
        "java":       ["spotbugs", "semgrep", "codeql"],
    }

    def __init__(self, tools: Optional[List[str]] = None):
        self.tools = tools or ["bandit", "semgrep", "codeql", "cppcheck", "spotbugs"]
        self._runners = {
            "bandit":   BanditRunner(),
            "semgrep":  SemgrepRunner(),
            "codeql":   CodeQLRunner(),
            "cppcheck": CppcheckRunner(),
            "spotbugs": None,   # SpotBugs requires compiled .class files — see sast/
        }

    def analyse(self, code: str, language: str) -> List[dict]:
        """Run all applicable tools on *code* and return per-tool findings."""
        applicable = [
            t for t in self.LANGUAGE_TOOLS.get(language, [])
            if t in self.tools
        ]
        findings = []
        for tool_name in applicable:
            runner = self._runners.get(tool_name)
            if runner is None:
                continue
            try:
                result = runner.run(code=code, language=language)
                findings.append(result)
            except Exception as exc:
                logger.warning(f"SAST tool {tool_name} failed: {exc}")
        return findings

    def majority_vote(self, findings: List[dict], threshold: int = 2) -> bool:
        """
        Return True if ≥ *threshold* tools reported at least one finding.
        Paper uses threshold = 2 (majority of 3 tools).
        """
        flagged = sum(1 for f in findings if f.get("cwe_ids"))
        return flagged >= threshold

    def extract_cwes(self, findings: List[dict]) -> List[str]:
        """Union of all CWE IDs reported across tools, deduplicated."""
        cwes: set = set()
        for f in findings:
            cwes.update(f.get("cwe_ids", []))
        return sorted(cwes)

    @staticmethod
    def write_temp_file(code: str, language: str) -> Path:
        """Write code to a temp file with the correct extension."""
        ext_map = {
            "python": ".py",
            "cpp": ".cpp",
            "javascript": ".js",
            "java": ".java",
        }
        ext = ext_map.get(language, ".txt")
        tmp = tempfile.NamedTemporaryFile(
            suffix=ext, mode="w", delete=False, encoding="utf-8"
        )
        tmp.write(code)
        tmp.flush()
        return Path(tmp.name)


# ---------------------------------------------------------------------------
# Dynamic Analyser (AFL++ + AddressSanitizer)
# ---------------------------------------------------------------------------

class DynamicAnalyser:
    """
    Wraps AFL++ for fuzz testing of C/C++ and Python snippets.

    Requirements:
      - afl-fuzz installed and on PATH
      - clang with AddressSanitizer support
      - Only runs on C/C++ and Python (Section IV-A)
    """

    FUZZ_TIMEOUT_S = 30   # Time limit per snippet in the paper's setup

    def fuzz(self, code: str, language: str) -> dict:
        if language == "cpp":
            return self._fuzz_cpp(code)
        elif language == "python":
            return self._fuzz_python(code)
        return {}

    def _fuzz_cpp(self, code: str) -> dict:
        """Compile with ASan and fuzz with AFL++."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "target.cpp"
            src.write_text(code)
            binary = Path(tmpdir) / "target"
            # Compile with AddressSanitizer
            compile_cmd = [
                "clang++", "-fsanitize=address,undefined",
                "-o", str(binary), str(src)
            ]
            compile_result = subprocess.run(
                compile_cmd, capture_output=True, text=True, timeout=30
            )
            if compile_result.returncode != 0:
                return {
                    "status": "compile_error",
                    "stderr": compile_result.stderr[:500],
                }
            # Run AFL++
            corpus = Path(tmpdir) / "corpus"
            corpus.mkdir()
            (corpus / "seed").write_bytes(b"AAAA")
            fuzz_out = Path(tmpdir) / "findings"
            fuzz_cmd = [
                "afl-fuzz",
                "-i", str(corpus),
                "-o", str(fuzz_out),
                "-t", "1000",     # 1s per test case
                "--",
                str(binary), "@@",
            ]
            try:
                subprocess.run(
                    fuzz_cmd,
                    capture_output=True,
                    timeout=self.FUZZ_TIMEOUT_S,
                )
            except subprocess.TimeoutExpired:
                pass
            crashes = list((fuzz_out / "default" / "crashes").glob("id:*")) if fuzz_out.exists() else []
            return {
                "status": "complete",
                "crashes_found": len(crashes),
                "vulnerable": len(crashes) > 0,
            }

    def _fuzz_python(self, code: str) -> dict:
        """Basic Python input fuzzing using subprocess."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "target.py"
            harness = (
                "import sys\n"
                + code
                + "\n\nif __name__ == '__main__':\n"
                "    data = sys.stdin.read()\n"
                "    try:\n"
                "        result = locals().get('main', lambda x: None)(data)\n"
                "    except Exception as e:\n"
                "        print(f'ERROR: {e}', file=sys.stderr)\n"
            )
            src.write_text(harness)
            payloads = [
                b"' OR '1'='1",         # SQL injection
                b"../../../etc/passwd",  # Path traversal
                b"A" * 10000,           # Buffer-like
                b"<script>alert(1)</script>",  # XSS
                b"$(id)",               # Command injection
            ]
            errors = []
            for payload in payloads:
                try:
                    result = subprocess.run(
                        ["python3", str(src)],
                        input=payload,
                        capture_output=True,
                        timeout=5,
                    )
                    if result.returncode != 0:
                        errors.append(result.stderr.decode(errors="replace")[:200])
                except subprocess.TimeoutExpired:
                    errors.append("TIMEOUT")
            return {
                "status": "complete",
                "payloads_tested": len(payloads),
                "errors": errors,
                "vulnerable": bool(errors),
            }
