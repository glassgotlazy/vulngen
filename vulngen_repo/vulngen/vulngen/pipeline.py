"""
vulngen/pipeline.py
-------------------
VulnGen six-stage pipeline orchestrator.

Stages:
  1  Task Curation        — Load SecureBench tasks (Tier S / I / C)
  2  Prompt Generation    — Apply hardening conditions
  3  Code Generation      — Call LLMs (OpenAI API or vLLM)
  4  SAST + Dynamic       — Ensemble analysis + fuzzing
  5  Real-World Validation— GitHub Copilot / CodeWhisperer / Cursor snippets
  6  CWE + CVSS Scoring   — Normalise findings, assign severity

Author : Anuansh Tiwari <anuanshtiwari191@gmail.com>
ORCID  : 0009-0007-4226-7925
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from loguru import logger
from tqdm import tqdm

from vulngen.stage1_curation import TaskCurator, Task
from vulngen.stage2_prompts import PromptBuilder, HardeningCondition
from vulngen.stage3_generation import CodeGenerator
from vulngen.stage4_analysis import SASTEnsemble, DynamicAnalyser
from vulngen.stage5_validation import RealWorldValidator
from vulngen.stage6_scoring import CWEScorer
from vulngen.metrics.evaluation import MetricsCalculator
from vulngen.utils.helpers import save_json, timestamp


@dataclass
class PipelineConfig:
    """Full configuration for a VulnGen run."""

    # Paths
    tasks_dir: Path = Path("securebench/tasks/")
    output_dir: Path = Path("results/")

    # Stage 1 — Task curation
    tiers: List[str] = field(default_factory=lambda: ["S", "I", "C"])
    max_tasks: Optional[int] = None          # None = use all 3,900

    # Stage 2 — Prompt hardening
    hardening_conditions: List[str] = field(
        default_factory=lambda: ["baseline", "sp", "cb", "fse", "cost", "combined"]
    )

    # Stage 3 — Generation
    models: List[str] = field(
        default_factory=lambda: ["gpt-4o", "gpt-4", "gpt-3.5-turbo"]
    )
    languages: List[str] = field(
        default_factory=lambda: ["python", "cpp", "javascript", "java"]
    )
    temperatures: List[float] = field(
        default_factory=lambda: [0.0, 0.2, 0.5, 0.8, 1.0]
    )

    # Stage 4 — Analysis
    sast_tools: List[str] = field(
        default_factory=lambda: ["bandit", "semgrep", "codeql", "cppcheck", "spotbugs"]
    )
    run_fuzzing: bool = False                # AFL++ requires local setup
    expert_sample_size: int = 1600          # Samples for human adjudication
    fpr_threshold: float = 0.083            # Measured FPR = 8.3%

    # Stage 5 — Real-world validation
    run_real_world: bool = False            # Requires GitHub token
    wild_snippet_count: int = 1600

    # Reproducibility
    seed: int = 42


class VulnGenPipeline:
    """
    Orchestrates the full six-stage VulnGen pipeline.

    Usage
    -----
    >>> config = PipelineConfig(models=["gpt-4o"], languages=["python"])
    >>> pipeline = VulnGenPipeline(config)
    >>> results = pipeline.run()
    """

    def __init__(self, config: PipelineConfig):
        self.config = config
        self.run_id = f"vulngen_{timestamp()}"
        self.output_dir = config.output_dir / self.run_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._setup_logging()

    def _setup_logging(self):
        log_path = self.output_dir / "pipeline.log"
        logger.add(log_path, rotation="50 MB", level="DEBUG")
        logger.info(f"VulnGen run {self.run_id} started")
        logger.info(f"Config: {self.config}")

    # ------------------------------------------------------------------
    # Stage 1 — Task Curation
    # ------------------------------------------------------------------
    def stage1_curate_tasks(self) -> List[Task]:
        logger.info("=== Stage 1: Task Curation ===")
        curator = TaskCurator(
            tasks_dir=self.config.tasks_dir,
            tiers=self.config.tiers,
            languages=self.config.languages,
        )
        tasks = curator.load()
        if self.config.max_tasks:
            tasks = tasks[: self.config.max_tasks]
        logger.info(f"Loaded {len(tasks)} tasks across tiers {self.config.tiers}")
        save_json(self.output_dir / "stage1_tasks.json", [t.to_dict() for t in tasks])
        return tasks

    # ------------------------------------------------------------------
    # Stage 2 — Prompt Generation
    # ------------------------------------------------------------------
    def stage2_build_prompts(self, tasks: List[Task]) -> List[dict]:
        logger.info("=== Stage 2: Prompt Generation ===")
        builder = PromptBuilder()
        prompt_records = []
        for task in tqdm(tasks, desc="Building prompts"):
            for condition in self.config.hardening_conditions:
                for language in self.config.languages:
                    prompt = builder.build(
                        task=task,
                        condition=HardeningCondition(condition),
                        language=language,
                    )
                    prompt_records.append(
                        {
                            "task_id": task.task_id,
                            "tier": task.tier,
                            "language": language,
                            "condition": condition,
                            "prompt": prompt,
                        }
                    )
        logger.info(f"Generated {len(prompt_records)} prompt-task combinations")
        save_json(self.output_dir / "stage2_prompts.json", prompt_records)
        return prompt_records

    # ------------------------------------------------------------------
    # Stage 3 — Code Generation
    # ------------------------------------------------------------------
    def stage3_generate_code(self, prompt_records: List[dict]) -> List[dict]:
        logger.info("=== Stage 3: Code Generation ===")
        generator = CodeGenerator(seed=self.config.seed)
        generation_records = []

        for model in self.config.models:
            for temperature in self.config.temperatures:
                logger.info(f"Generating: model={model}, T={temperature}")
                for record in tqdm(
                    prompt_records,
                    desc=f"{model} T={temperature}",
                    leave=False,
                ):
                    code, meta = generator.generate(
                        model=model,
                        prompt=record["prompt"],
                        language=record["language"],
                        temperature=temperature,
                    )
                    generation_records.append(
                        {
                            **record,
                            "model": model,
                            "temperature": temperature,
                            "generated_code": code,
                            "generation_meta": meta,
                        }
                    )
                    time.sleep(0.1)  # Rate limiting for API calls

        logger.info(f"Generated {len(generation_records)} code samples")
        save_json(self.output_dir / "stage3_generated.json", generation_records)
        return generation_records

    # ------------------------------------------------------------------
    # Stage 4 — SAST Ensemble + Dynamic Analysis
    # ------------------------------------------------------------------
    def stage4_analyse(self, generation_records: List[dict]) -> List[dict]:
        logger.info("=== Stage 4: SAST Ensemble + Dynamic Analysis ===")
        sast = SASTEnsemble(tools=self.config.sast_tools)
        fuzzer = DynamicAnalyser() if self.config.run_fuzzing else None

        analysis_records = []
        for record in tqdm(generation_records, desc="SAST analysis"):
            findings = sast.analyse(
                code=record["generated_code"],
                language=record["language"],
            )
            # Dynamic fuzzing on C/C++ and Python samples
            fuzz_results = {}
            if fuzzer and record["language"] in ("cpp", "python"):
                fuzz_results = fuzzer.fuzz(
                    code=record["generated_code"],
                    language=record["language"],
                )

            is_vulnerable = sast.majority_vote(findings)
            analysis_records.append(
                {
                    **record,
                    "sast_findings": findings,
                    "fuzz_results": fuzz_results,
                    "is_vulnerable": is_vulnerable,
                    "cwe_ids": sast.extract_cwes(findings),
                }
            )

        logger.info(
            f"Analysis complete. "
            f"Vulnerable: {sum(r['is_vulnerable'] for r in analysis_records)} / "
            f"{len(analysis_records)}"
        )
        save_json(self.output_dir / "stage4_analysis.json", analysis_records)
        return analysis_records

    # ------------------------------------------------------------------
    # Stage 5 — Real-World Validation (optional)
    # ------------------------------------------------------------------
    def stage5_real_world(self) -> Optional[List[dict]]:
        if not self.config.run_real_world:
            logger.info("Stage 5 skipped (run_real_world=False)")
            return None
        logger.info("=== Stage 5: Real-World Validation ===")
        validator = RealWorldValidator(
            snippet_count=self.config.wild_snippet_count
        )
        wild_records = validator.collect_and_analyse()
        save_json(self.output_dir / "stage5_wild.json", wild_records)
        return wild_records

    # ------------------------------------------------------------------
    # Stage 6 — CWE Normalisation + CVSS Scoring
    # ------------------------------------------------------------------
    def stage6_score(self, analysis_records: List[dict]) -> List[dict]:
        logger.info("=== Stage 6: CWE Normalisation + CVSS Scoring ===")
        scorer = CWEScorer()
        scored_records = []
        for record in tqdm(analysis_records, desc="Scoring"):
            scored = scorer.score(record)
            scored_records.append(scored)
        save_json(self.output_dir / "stage6_scored.json", scored_records)
        return scored_records

    # ------------------------------------------------------------------
    # Metrics & Report
    # ------------------------------------------------------------------
    def compute_metrics(
        self,
        scored_records: List[dict],
        wild_records: Optional[List[dict]] = None,
    ) -> dict:
        logger.info("=== Computing Metrics ===")
        calc = MetricsCalculator(fpr_correction=self.config.fpr_threshold)
        report = calc.full_report(
            records=scored_records,
            wild_records=wild_records,
            models=self.config.models,
            languages=self.config.languages,
            conditions=self.config.hardening_conditions,
        )
        save_json(self.output_dir / "metrics_report.json", report)
        return report

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def run(self) -> dict:
        logger.info(f"Starting VulnGen pipeline — run ID: {self.run_id}")
        start = time.time()

        tasks = self.stage1_curate_tasks()
        prompt_records = self.stage2_build_prompts(tasks)
        generation_records = self.stage3_generate_code(prompt_records)
        analysis_records = self.stage4_analyse(generation_records)
        wild_records = self.stage5_real_world()
        scored_records = self.stage6_score(analysis_records)
        report = self.compute_metrics(scored_records, wild_records)

        elapsed = time.time() - start
        logger.info(f"Pipeline complete in {elapsed/3600:.2f} hours")
        logger.info(f"Results saved to: {self.output_dir}")
        return report
