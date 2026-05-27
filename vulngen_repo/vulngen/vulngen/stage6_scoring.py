"""
vulngen/stage6_scoring.py
--------------------------
Stage 6 — CWE normalisation and CVSS v3.1 scoring.

CWE normalisation rules (Section IV-B):
  - Map vendor-specific rule IDs → canonical CWE IDs
  - Deduplicate findings that share the same root CWE
  - Exclude style/quality issues (not security defects)

CVSS v3.1 severity bands (paper Table IV):
  Critical  ≥ 9.0
  High      7.0 – 8.9
  Medium    4.0 – 6.9
  Low       0.1 – 3.9

Paper finding (Section V-A):
  34.2% of confirmed weaknesses are High or Critical.

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from loguru import logger

try:
    from cvss import CVSS3
    _CVSS_AVAILABLE = True
except ImportError:
    _CVSS_AVAILABLE = False


# ---------------------------------------------------------------------------
# CWE → CVSS v3.1 base-score lookup
# (representative scores from NVD; see paper Section IV-B)
# ---------------------------------------------------------------------------

CWE_CVSS_MAP: Dict[str, float] = {
    "CWE-89":  9.8,   # SQL Injection              — Critical
    "CWE-78":  9.8,   # OS Command Injection        — Critical
    "CWE-79":  6.1,   # XSS                         — Medium
    "CWE-22":  8.6,   # Path Traversal              — High
    "CWE-434": 9.8,   # Unrestricted File Upload    — Critical
    "CWE-94":  9.8,   # Code Injection              — Critical
    "CWE-502": 9.8,   # Deserialization             — Critical
    "CWE-611": 7.5,   # XXE                         — High
    "CWE-918": 8.6,   # SSRF                        — High
    "CWE-20":  7.5,   # Improper Input Validation   — High
    "CWE-190": 7.8,   # Integer Overflow            — High
    "CWE-125": 7.1,   # Out-of-Bounds Read          — High
    "CWE-787": 9.8,   # Out-of-Bounds Write         — Critical
    "CWE-416": 9.8,   # Use After Free              — Critical
    "CWE-476": 7.5,   # NULL Pointer Dereference    — High
    "CWE-362": 7.0,   # Race Condition (TOCTOU)     — High
    "CWE-330": 5.3,   # Insufficient Randomness     — Medium
    "CWE-331": 5.3,   # Insufficient Entropy        — Medium
    "CWE-338": 5.3,   # Weak PRNG                   — Medium
    "CWE-295": 7.4,   # Improper Cert Validation    — High
    "CWE-327": 7.4,   # Broken Crypto Algorithm     — High
    "CWE-321": 7.5,   # Hardcoded Crypto Key        — High
    "CWE-798": 9.8,   # Hardcoded Credentials       — Critical
    "CWE-259": 7.5,   # Hardcoded Password          — High
    "CWE-200": 5.3,   # Information Exposure        — Medium
    "CWE-209": 5.3,   # Error Message Info Leak     — Medium
    "CWE-532": 4.4,   # Sensitive Info in Log       — Medium
    "CWE-601": 6.1,   # Open Redirect               — Medium
    "CWE-352": 8.8,   # CSRF                        — High
    "CWE-400": 7.5,   # Resource Exhaustion         — High
    "CWE-770": 7.5,   # Uncontrolled Memory Alloc   — High
    "CWE-285": 8.6,   # Improper Authorisation      — High
    "CWE-306": 9.8,   # Missing Auth for Function   — Critical
    "CWE-732": 5.5,   # Incorrect Permission        — Medium
}

# Vendor rule prefix → CWE normalisation
VENDOR_TO_CWE: Dict[str, str] = {
    # Bandit
    "B105": "CWE-259",
    "B106": "CWE-259",
    "B107": "CWE-259",
    "B108": "CWE-200",
    "B301": "CWE-502",
    "B302": "CWE-502",
    "B303": "CWE-327",
    "B304": "CWE-327",
    "B305": "CWE-327",
    "B306": "CWE-330",
    "B307": "CWE-78",
    "B310": "CWE-601",
    "B311": "CWE-338",
    "B312": "CWE-330",
    "B313": "CWE-611",
    "B320": "CWE-295",
    "B322": "CWE-78",
    "B323": "CWE-295",
    "B324": "CWE-327",
    "B501": "CWE-295",
    "B502": "CWE-295",
    "B503": "CWE-295",
    "B506": "CWE-611",
    "B601": "CWE-78",
    "B602": "CWE-78",
    "B603": "CWE-78",
    "B604": "CWE-78",
    "B605": "CWE-78",
    "B608": "CWE-89",
    # Semgrep generic IDs
    "python.lang.security.sqli":   "CWE-89",
    "python.lang.security.os-cmd": "CWE-78",
    "javascript.lang.security.xss":"CWE-79",
    "c.lang.security.buffer":      "CWE-787",
}

CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)
SEVERITY_BANDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
]


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

class CWEScorer:
    """
    Normalises CWE IDs, deduplicates findings, and assigns CVSS v3.1 scores.

    >>> scorer = CWEScorer()
    >>> result = scorer.score({"cwe_ids": ["CWE-89", "B608"], "generated_code": "..."})
    """

    def score(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a generation record with normalised CWEs and CVSS scores.

        Parameters
        ----------
        record : dict
            Must contain at least 'cwe_ids' and optionally 'sast_findings'.

        Returns
        -------
        dict : original record + normalised_cwes, cvss_score, severity, severity_band
        """
        raw_cwes: List[str] = record.get("cwe_ids", [])
        normalised = self._normalise(raw_cwes)
        cvss_score = self._best_cvss(normalised)
        severity_band = self._band(cvss_score)

        return {
            **record,
            "normalised_cwes": normalised,
            "cvss_score": cvss_score,
            "severity": severity_band,
            "is_high_critical": cvss_score >= 7.0 if cvss_score else False,
        }

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _normalise(self, raw_ids: List[str]) -> List[str]:
        """Map vendor IDs → CWE-NNN, deduplicate, filter noise."""
        normalised: set = set()
        for raw in raw_ids:
            cwe = self._resolve(raw)
            if cwe:
                normalised.add(cwe)
        return sorted(normalised)

    def _resolve(self, raw: str) -> Optional[str]:
        """Resolve a raw finding ID to a canonical CWE-NNN string."""
        # Already CWE format
        m = CWE_PATTERN.search(raw)
        if m:
            return f"CWE-{m.group(1)}"
        # Vendor lookup
        stripped = raw.strip().upper()
        for prefix, cwe in VENDOR_TO_CWE.items():
            if stripped.startswith(prefix.upper()):
                return cwe
        logger.debug(f"Could not resolve ID to CWE: {raw!r}")
        return None

    # ------------------------------------------------------------------
    # CVSS scoring
    # ------------------------------------------------------------------

    def _best_cvss(self, cwes: List[str]) -> Optional[float]:
        """Return the highest CVSS base score across all CWE IDs."""
        scores = [CWE_CVSS_MAP[cwe] for cwe in cwes if cwe in CWE_CVSS_MAP]
        return round(max(scores), 1) if scores else None

    @staticmethod
    def _band(score: Optional[float]) -> str:
        if score is None:
            return "Unknown"
        for threshold, label in SEVERITY_BANDS:
            if score >= threshold:
                return label
        return "Informational"

    # ------------------------------------------------------------------
    # Corpus-level stats
    # ------------------------------------------------------------------

    @staticmethod
    def severity_distribution(records: List[Dict[str, Any]]) -> Dict[str, int]:
        from collections import Counter
        return dict(Counter(r.get("severity", "Unknown") for r in records))

    @staticmethod
    def cwe_frequency(records: List[Dict[str, Any]]) -> Dict[str, int]:
        from collections import Counter
        counts: Counter = Counter()
        for r in records:
            for cwe in r.get("normalised_cwes", []):
                counts[cwe] += 1
        return dict(counts.most_common(20))
