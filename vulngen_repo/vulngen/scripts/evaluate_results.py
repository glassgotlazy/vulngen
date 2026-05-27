#!/usr/bin/env python3
"""
scripts/evaluate_results.py
----------------------------
Load a completed pipeline run and generate the full metrics report,
including tables and figures matching those in the paper.

Usage
-----
  python scripts/evaluate_results.py --results results/my_run/

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import click
import json
import matplotlib.pyplot as plt
import seaborn as sns
from rich.console import Console

from vulngen.metrics.evaluation import MetricsCalculator
from vulngen.utils.helpers import load_json, save_json

console = Console()
sns.set_theme(style="whitegrid", palette="muted")


@click.command()
@click.option("--results", required=True, help="Path to a completed pipeline run dir.")
@click.option("--fpr", default=0.083, show_default=True, help="FPR correction value.")
@click.option("--figures", is_flag=True, default=False, help="Generate matplotlib figures.")
def main(results, fpr, figures):
    """Generate metrics report from a completed VulnGen pipeline run."""

    run_dir = Path(results)
    scored_path = run_dir / "stage6_scored.json"
    wild_path   = run_dir / "stage5_wild.json"

    if not scored_path.exists():
        console.print(f"[red]Error:[/red] {scored_path} not found.")
        sys.exit(1)

    console.print(f"Loading results from [bold]{run_dir}[/bold]…")
    records = load_json(scored_path)
    wild = load_json(wild_path) if wild_path.exists() else None

    # Infer model/language/condition lists from data
    models     = sorted({r["model"]     for r in records if "model"     in r})
    languages  = sorted({r["language"]  for r in records if "language"  in r})
    conditions = sorted({r["condition"] for r in records if "condition" in r})

    calc = MetricsCalculator(fpr_correction=fpr)
    report = calc.full_report(
        records=records,
        wild_records=wild,
        models=models,
        languages=languages,
        conditions=conditions,
    )

    # Save report
    report_path = run_dir / "metrics_report.json"
    save_json(report_path, report)
    console.print(f"[green]✓[/green] Report saved: {report_path}")

    # Print key stats
    s = report["corpus_summary"]
    console.print(
        f"\n[bold]Corpus[/bold]: {s['total_samples']} samples, "
        f"VR = [red bold]{s['vr_pct']}[/red bold] (95% CI: {s['ci_95']})"
    )

    # Figures
    if figures:
        _plot_vr_by_model(report, run_dir)
        _plot_hardening_effects(report, run_dir)
        _plot_cwe_distribution(report, run_dir)
        console.print(f"[green]✓[/green] Figures saved to {run_dir}/figures/")


# ---------------------------------------------------------------------------
# Figure generators (matching paper Figs 1–5)
# ---------------------------------------------------------------------------

def _plot_vr_by_model(report: dict, run_dir: Path) -> None:
    fig_dir = run_dir / "figures"
    fig_dir.mkdir(exist_ok=True)

    per_model = report.get("per_model", {})
    if not per_model:
        return

    models = list(per_model.keys())
    vrs    = [per_model[m]["vr"] * 100 for m in models]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(models, vrs, color=sns.color_palette("Reds_r", len(models)))
    ax.set_xlabel("Vulnerability Rate (%)")
    ax.set_title("VulnGen — VR by Model (FPR-corrected)", fontsize=13, fontweight="bold")
    ax.bar_label(bars, fmt="%.1f%%", padding=3)
    ax.axvline(19.8, color="navy", linestyle="--", linewidth=1, label="GPT-4o baseline (19.8%)")
    ax.legend()
    plt.tight_layout()
    plt.savefig(fig_dir / "fig1_vr_by_model.pdf", dpi=300)
    plt.close()


def _plot_hardening_effects(report: dict, run_dir: Path) -> None:
    fig_dir = run_dir / "figures"
    fig_dir.mkdir(exist_ok=True)

    effects = report.get("prompt_hardening", {})
    if not effects:
        return

    conditions = list(effects.keys())
    ds         = [effects[c]["cohens_d"] for c in conditions]

    fig, ax = plt.subplots(figsize=(8, 4))
    colors  = ["#2ecc71" if d >= 0.8 else "#f39c12" if d >= 0.5 else "#3498db" for d in ds]
    ax.bar(conditions, ds, color=colors)
    ax.axhline(0.8, color="red", linestyle="--", linewidth=1, label="Large effect (d=0.8)")
    ax.axhline(0.5, color="orange", linestyle="--", linewidth=1, label="Medium effect (d=0.5)")
    ax.set_ylabel("Cohen's d")
    ax.set_title("Prompt Hardening Effect Sizes vs Baseline", fontsize=13, fontweight="bold")
    ax.legend()
    plt.tight_layout()
    plt.savefig(fig_dir / "fig2_prompt_hardening.pdf", dpi=300)
    plt.close()


def _plot_cwe_distribution(report: dict, run_dir: Path) -> None:
    fig_dir = run_dir / "figures"
    fig_dir.mkdir(exist_ok=True)

    cwe_dist = report.get("cwe_distribution", {})
    if not cwe_dist:
        return

    cwes   = list(cwe_dist.keys())[:12]
    counts = [cwe_dist[c] for c in cwes]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.barh(cwes[::-1], counts[::-1], color=sns.color_palette("Blues_r", len(cwes)))
    ax.set_xlabel("Frequency")
    ax.set_title("Top CWE Distribution in VulnGen Corpus", fontsize=13, fontweight="bold")
    plt.tight_layout()
    plt.savefig(fig_dir / "fig3_cwe_distribution.pdf", dpi=300)
    plt.close()


if __name__ == "__main__":
    main()
