"""
vulngen/metrics/evaluation.py
------------------------------
Computes all metrics reported in the paper.

Metrics (Section V):
  VR    — Vulnerability Rate (FPR-corrected)
  SUT   — Secure Under Test rate
  ΔVR   — Absolute VR reduction vs baseline
  RRR   — Relative Risk Reduction
  Cohen's d — Effect size for prompt hardening
  95% CI  — Wilson score interval for proportions
  κ       — Cohen's Kappa for inter-rater agreement
  p-value — Two-sided z-test for VR comparisons

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy import stats


# ---------------------------------------------------------------------------
# Core rate functions
# ---------------------------------------------------------------------------

def vulnerability_rate(
    n_vulnerable: int,
    n_total: int,
    fpr: float = 0.083,
) -> float:
    """
    FPR-corrected Vulnerability Rate.

    VR_corrected = (raw_rate - FPR) / (1 - FPR)

    Paper uses FPR = 8.3% measured by expert adjudication (Section IV-E).
    """
    if n_total == 0:
        return 0.0
    raw = n_vulnerable / n_total
    corrected = (raw - fpr) / (1 - fpr)
    return max(0.0, round(corrected, 4))


def wilson_ci(n: int, k: int, z: float = 1.96) -> Tuple[float, float]:
    """
    Wilson score 95% confidence interval for a proportion k/n.

    Returns (lower, upper) as fractions.
    """
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z ** 2 / n
    centre = (p + z ** 2 / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z ** 2 / (4 * n ** 2)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def cohens_d(group_a: List[float], group_b: List[float]) -> float:
    """
    Cohen's d effect size (pooled SD).

    Interpretation: 0.2 = small, 0.5 = medium, 0.8+ = large.
    Paper reports d = 1.14 for Combined vs Baseline (Section V-B).
    """
    a, b = np.array(group_a), np.array(group_b)
    pooled_sd = math.sqrt((np.std(a, ddof=1) ** 2 + np.std(b, ddof=1) ** 2) / 2)
    if pooled_sd == 0:
        return 0.0
    return float((np.mean(a) - np.mean(b)) / pooled_sd)


def two_sample_z_test(
    n1: int, k1: int, n2: int, k2: int
) -> Tuple[float, float]:
    """
    Two-sided z-test comparing two proportions.

    Returns (z_stat, p_value).
    """
    p1 = k1 / n1 if n1 > 0 else 0
    p2 = k2 / n2 if n2 > 0 else 0
    p_pool = (k1 + k2) / (n1 + n2) if (n1 + n2) > 0 else 0
    denom = math.sqrt(p_pool * (1 - p_pool) * (1 / n1 + 1 / n2))
    if denom == 0:
        return 0.0, 1.0
    z = (p1 - p2) / denom
    p_val = 2 * (1 - stats.norm.cdf(abs(z)))
    return round(z, 4), round(p_val, 6)


def relative_risk_reduction(vr_treatment: float, vr_baseline: float) -> float:
    """RRR = (VR_baseline - VR_treatment) / VR_baseline"""
    if vr_baseline == 0:
        return 0.0
    return round((vr_baseline - vr_treatment) / vr_baseline, 4)


def cohens_kappa(agreed: int, n: int, p_e: float) -> float:
    """
    Cohen's Kappa: κ = (p_o - p_e) / (1 - p_e)

    Paper reports κ = 0.81 (substantial agreement).
    """
    p_o = agreed / n if n > 0 else 0
    if p_e == 1:
        return 0.0
    return round((p_o - p_e) / (1 - p_e), 4)


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

class MetricsCalculator:
    """
    Aggregates all paper metrics into a structured report dict.

    >>> calc = MetricsCalculator(fpr_correction=0.083)
    >>> report = calc.full_report(records, models=["gpt-4o"], languages=["python"])
    """

    def __init__(self, fpr_correction: float = 0.083):
        self.fpr = fpr_correction

    def full_report(
        self,
        records: List[dict],
        wild_records: Optional[List[dict]] = None,
        models: Optional[List[str]] = None,
        languages: Optional[List[str]] = None,
        conditions: Optional[List[str]] = None,
    ) -> dict:
        report: dict = {}
        report["corpus_summary"] = self._corpus_summary(records)
        report["per_model"] = self._per_model(records, models or [])
        report["per_language"] = self._per_language(records, languages or [])
        report["per_condition"] = self._per_condition(records, conditions or [])
        report["prompt_hardening"] = self._prompt_hardening_effects(records)
        report["cwe_distribution"] = self._cwe_distribution(records)
        report["severity_distribution"] = self._severity_distribution(records)
        if wild_records:
            report["real_world"] = self._real_world(wild_records)
        return report

    # ------------------------------------------------------------------
    # Sub-reports
    # ------------------------------------------------------------------

    def _corpus_summary(self, records: List[dict]) -> dict:
        n = len(records)
        k = sum(1 for r in records if r.get("is_vulnerable"))
        vr = vulnerability_rate(k, n, self.fpr)
        ci_lo, ci_hi = wilson_ci(n, k)
        return {
            "total_samples": n,
            "vulnerable": k,
            "vr": round(vr, 4),
            "vr_pct": f"{vr*100:.1f}%",
            "ci_95": (round(ci_lo, 4), round(ci_hi, 4)),
        }

    def _per_model(self, records: List[dict], models: List[str]) -> dict:
        result = {}
        for model in models:
            sub = [r for r in records if r.get("model") == model]
            if not sub:
                continue
            k = sum(1 for r in sub if r.get("is_vulnerable"))
            vr = vulnerability_rate(k, len(sub), self.fpr)
            ci = wilson_ci(len(sub), k)
            result[model] = {
                "n": len(sub),
                "vulnerable": k,
                "vr": round(vr, 4),
                "vr_pct": f"{vr*100:.1f}%",
                "ci_95": (round(ci[0], 4), round(ci[1], 4)),
            }
        return result

    def _per_language(self, records: List[dict], languages: List[str]) -> dict:
        result = {}
        for lang in languages:
            sub = [r for r in records if r.get("language") == lang]
            if not sub:
                continue
            k = sum(1 for r in sub if r.get("is_vulnerable"))
            vr = vulnerability_rate(k, len(sub), self.fpr)
            result[lang] = {
                "n": len(sub),
                "vulnerable": k,
                "vr": round(vr, 4),
                "vr_pct": f"{vr*100:.1f}%",
            }
        return result

    def _per_condition(self, records: List[dict], conditions: List[str]) -> dict:
        result = {}
        baseline_vr = None
        for cond in conditions:
            sub = [r for r in records if r.get("condition") == cond]
            if not sub:
                continue
            k = sum(1 for r in sub if r.get("is_vulnerable"))
            vr = vulnerability_rate(k, len(sub), self.fpr)
            if cond == "baseline":
                baseline_vr = vr
            rrr = (
                relative_risk_reduction(vr, baseline_vr)
                if baseline_vr and cond != "baseline"
                else None
            )
            result[cond] = {
                "n": len(sub),
                "vr": round(vr, 4),
                "vr_pct": f"{vr*100:.1f}%",
                "rrr": round(rrr, 4) if rrr is not None else None,
                "delta_vr": (
                    round(baseline_vr - vr, 4)
                    if baseline_vr and cond != "baseline"
                    else None
                ),
            }
        return result

    def _prompt_hardening_effects(self, records: List[dict]) -> dict:
        """Cohen's d for each hardening condition vs baseline."""
        baseline_vrs = [
            float(r.get("is_vulnerable", 0))
            for r in records
            if r.get("condition") == "baseline"
        ]
        effects = {}
        for cond in ["sp", "cb", "fse", "cost", "combined"]:
            treatment_vrs = [
                float(r.get("is_vulnerable", 0))
                for r in records
                if r.get("condition") == cond
            ]
            if treatment_vrs and baseline_vrs:
                d = cohens_d(baseline_vrs, treatment_vrs)
                magnitude = (
                    "large" if abs(d) >= 0.8
                    else "medium" if abs(d) >= 0.5
                    else "small"
                )
                effects[cond] = {
                    "cohens_d": round(d, 3),
                    "magnitude": magnitude,
                }
        return effects

    def _cwe_distribution(self, records: List[dict]) -> dict:
        from collections import Counter
        counts: Counter = Counter()
        for r in records:
            if r.get("is_vulnerable"):
                for cwe in r.get("normalised_cwes", r.get("cwe_ids", [])):
                    counts[cwe] += 1
        return dict(counts.most_common(15))

    def _severity_distribution(self, records: List[dict]) -> dict:
        from collections import Counter
        counts: Counter = Counter(
            r.get("severity", "Unknown")
            for r in records
            if r.get("is_vulnerable")
        )
        total = sum(counts.values())
        return {
            sev: {"count": cnt, "pct": f"{cnt/total*100:.1f}%"}
            for sev, cnt in counts.most_common()
        }

    def _real_world(self, wild_records: List[dict]) -> dict:
        by_tool = defaultdict(list)
        for r in wild_records:
            by_tool[r.get("source_tool", "unknown")].append(r)

        result = {}
        for tool, recs in by_tool.items():
            k = sum(1 for r in recs if r.get("is_vulnerable"))
            vr = vulnerability_rate(k, len(recs), self.fpr)
            result[tool] = {
                "n": len(recs),
                "vulnerable": k,
                "vr": round(vr, 4),
                "vr_pct": f"{vr*100:.1f}%",
            }
        return result
