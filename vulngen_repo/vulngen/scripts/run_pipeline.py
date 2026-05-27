#!/usr/bin/env python3
"""
scripts/run_pipeline.py
-----------------------
Command-line entry point for the VulnGen pipeline.

Usage
-----
  # Quick smoke-test (GPT-4o, Python only, 10 tasks)
  python scripts/run_pipeline.py --models gpt-4o --languages python --max-tasks 10

  # Full controlled study (paper replication)
  python scripts/run_pipeline.py \
      --models gpt-4o gpt-4 gpt-3.5-turbo codellama-34b codellama-7b starcoder-15b deepseek-coder-33b \
      --languages python cpp javascript java \
      --hardening baseline sp cb fse cost combined \
      --output results/paper_replication/

  # With real-world validation (requires GITHUB_TOKEN)
  python scripts/run_pipeline.py --models gpt-4o --real-world

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

import sys
from pathlib import Path

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import click
from rich.console import Console
from rich.table import Table

from vulngen.pipeline import PipelineConfig, VulnGenPipeline

console = Console()


@click.command()
@click.option(
    "--tasks-dir", default="securebench/tasks/", show_default=True,
    help="Path to SecureBench tasks directory.",
)
@click.option(
    "--models", multiple=True,
    default=["gpt-4o", "gpt-4", "gpt-3.5-turbo"],
    show_default=True,
    help="LLM(s) to evaluate.",
)
@click.option(
    "--languages", multiple=True,
    default=["python", "cpp", "javascript", "java"],
    show_default=True,
    help="Programming language(s).",
)
@click.option(
    "--hardening", multiple=True,
    default=["baseline", "sp", "cb", "fse", "cost", "combined"],
    show_default=True,
    help="Prompt hardening condition(s).",
)
@click.option(
    "--tiers", multiple=True, default=["S", "I", "C"],
    help="SecureBench tiers to include (S/I/C).",
)
@click.option(
    "--max-tasks", default=None, type=int,
    help="Limit number of tasks (useful for testing).",
)
@click.option(
    "--output", default="results/", show_default=True,
    help="Output directory.",
)
@click.option(
    "--no-fuzzing", is_flag=True, default=False,
    help="Skip AFL++ dynamic analysis.",
)
@click.option(
    "--real-world", is_flag=True, default=False,
    help="Run Stage 5 real-world validation (requires GITHUB_TOKEN).",
)
@click.option(
    "--seed", default=42, show_default=True,
    help="Random seed for reproducibility.",
)
def main(
    tasks_dir, models, languages, hardening, tiers,
    max_tasks, output, no_fuzzing, real_world, seed,
):
    """VulnGen — LLM Security Vulnerability Analysis Pipeline."""

    console.rule("[bold blue]VulnGen Pipeline[/bold blue]")
    console.print(f"  Models     : {list(models)}")
    console.print(f"  Languages  : {list(languages)}")
    console.print(f"  Hardening  : {list(hardening)}")
    console.print(f"  Tiers      : {list(tiers)}")
    console.print(f"  Max tasks  : {max_tasks or 'all'}")
    console.print(f"  Real-world : {real_world}")
    console.print()

    config = PipelineConfig(
        tasks_dir=Path(tasks_dir),
        output_dir=Path(output),
        tiers=list(tiers),
        max_tasks=max_tasks,
        hardening_conditions=list(hardening),
        models=list(models),
        languages=list(languages),
        run_fuzzing=not no_fuzzing,
        run_real_world=real_world,
        seed=seed,
    )

    pipeline = VulnGenPipeline(config)

    try:
        report = pipeline.run()
        _print_summary(report)
        console.print(
            f"\n[green]✓ Complete.[/green] Results saved to: [bold]{pipeline.output_dir}[/bold]"
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(1)


def _print_summary(report: dict) -> None:
    console.rule("[bold]Results Summary[/bold]")

    # Corpus summary
    s = report.get("corpus_summary", {})
    console.print(
        f"\nTotal samples : [bold]{s.get('total_samples', '—')}[/bold]\n"
        f"Vulnerable    : [red]{s.get('vulnerable', '—')}[/red]\n"
        f"VR (corrected): [red bold]{s.get('vr_pct', '—')}[/red bold]\n"
        f"95% CI        : {s.get('ci_95', '—')}\n"
    )

    # Per-model table
    per_model = report.get("per_model", {})
    if per_model:
        table = Table(title="Vulnerability Rate by Model")
        table.add_column("Model", style="cyan")
        table.add_column("N", justify="right")
        table.add_column("Vulnerable", justify="right", style="red")
        table.add_column("VR", justify="right", style="bold red")
        table.add_column("95% CI")
        for model, m in per_model.items():
            table.add_row(
                model,
                str(m["n"]),
                str(m["vulnerable"]),
                m["vr_pct"],
                str(m["ci_95"]),
            )
        console.print(table)

    # Prompt hardening effects
    effects = report.get("prompt_hardening", {})
    if effects:
        table2 = Table(title="Prompt Hardening — Cohen's d vs Baseline")
        table2.add_column("Condition", style="cyan")
        table2.add_column("Cohen's d", justify="right")
        table2.add_column("Magnitude")
        for cond, e in effects.items():
            table2.add_row(cond, str(e["cohens_d"]), e["magnitude"])
        console.print(table2)


if __name__ == "__main__":
    main()
