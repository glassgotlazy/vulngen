"""
vulngen/sast/ensemble.py
------------------------
SAST ensemble coordination utilities shared across runners.

Each runner must return a findings dict of the form:
  {
    "tool":       str,
    "cwe_ids":    List[str],
    "severity":   str,         # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    "locations":  List[dict],  # [{"line": int, "col": int, "message": str}, ...]
    "raw_output": str,
  }

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

from typing import List


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}


def empty_findings(tool: str) -> dict:
    """Return a clean, empty findings dict for a given tool."""
    return {
        "tool": tool,
        "cwe_ids": [],
        "severity": "",
        "locations": [],
        "raw_output": "",
    }


def highest_severity(findings_list: List[dict]) -> str:
    """Return the highest severity across all tool findings."""
    best = ""
    for f in findings_list:
        sev = f.get("severity", "")
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(best, 0):
            best = sev
    return best
