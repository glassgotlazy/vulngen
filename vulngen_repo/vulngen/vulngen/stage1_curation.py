"""
vulngen/stage1_curation.py
--------------------------
Stage 1 — SecureBench task curation.

SecureBench contains 3,900 tasks drawn from:
  OWASP Top 10, CWE Top 25, HumanEval, MBPP, SecurityEval, NVD

Each task belongs to one tier:
  Tier S — Explicitly Unsafe   (prompt directly requests insecure code)
  Tier I — Implicitly Unsafe   (prompt is benign; vulnerability is latent)
  Tier C — Security-Critical   (prompt requires correct security handling)

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Task:
    """A single SecureBench evaluation task."""

    task_id: str
    tier: str                        # "S", "I", or "C"
    language: str                    # "python", "cpp", "javascript", "java"
    description: str                 # Natural-language task description
    function_signature: str          # Target function signature
    cwe_ids: List[str]               # Associated CWE IDs
    source: str                      # Origin dataset (owasp, cwe25, humaneval, …)
    secure_examples: List[str] = field(default_factory=list)   # For FSE prompts
    ground_truth_vulnerable: Optional[bool] = None             # For Tier S tasks

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "tier": self.tier,
            "language": self.language,
            "description": self.description,
            "function_signature": self.function_signature,
            "cwe_ids": self.cwe_ids,
            "source": self.source,
            "secure_examples": self.secure_examples,
            "ground_truth_vulnerable": self.ground_truth_vulnerable,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Task":
        return cls(**data)


# ---------------------------------------------------------------------------
# Curator
# ---------------------------------------------------------------------------

class TaskCurator:
    """
    Loads and filters SecureBench tasks from the tasks/ directory.

    Directory layout expected:
        tasks/
          tier_s/  *.json
          tier_i/  *.json
          tier_c/  *.json

    Each JSON file is a list of Task dicts for one source dataset.
    """

    TIER_MAP = {"S": "tier_s", "I": "tier_i", "C": "tier_c"}
    SUPPORTED_LANGUAGES = {"python", "cpp", "javascript", "java"}

    def __init__(
        self,
        tasks_dir: Path,
        tiers: List[str] = ("S", "I", "C"),
        languages: Optional[List[str]] = None,
    ):
        self.tasks_dir = Path(tasks_dir)
        self.tiers = [t.upper() for t in tiers]
        self.languages = (
            [l.lower() for l in languages]
            if languages
            else list(self.SUPPORTED_LANGUAGES)
        )
        self._validate()

    def _validate(self):
        for tier in self.tiers:
            if tier not in self.TIER_MAP:
                raise ValueError(f"Unknown tier '{tier}'. Must be S, I, or C.")
        for lang in self.languages:
            if lang not in self.SUPPORTED_LANGUAGES:
                raise ValueError(f"Unsupported language '{lang}'.")

    def load(self) -> List[Task]:
        """Load all tasks matching the configured tiers and languages."""
        tasks: List[Task] = []
        for tier in self.tiers:
            tier_dir = self.tasks_dir / self.TIER_MAP[tier]
            if not tier_dir.exists():
                raise FileNotFoundError(
                    f"Tier directory not found: {tier_dir}\n"
                    f"Run scripts/build_securebench.py to generate tasks."
                )
            for json_file in sorted(tier_dir.glob("*.json")):
                with open(json_file) as f:
                    raw = json.load(f)
                for item in raw:
                    task = Task.from_dict(item)
                    if task.language in self.languages:
                        tasks.append(task)

        if not tasks:
            raise RuntimeError(
                "No tasks loaded. Check your tasks_dir and tier/language filters."
            )
        return tasks

    def stats(self, tasks: List[Task]) -> dict:
        """Return breakdown of loaded tasks by tier, language, and CWE."""
        from collections import Counter
        return {
            "total": len(tasks),
            "by_tier": dict(Counter(t.tier for t in tasks)),
            "by_language": dict(Counter(t.language for t in tasks)),
            "by_source": dict(Counter(t.source for t in tasks)),
            "unique_cwes": list({cwe for t in tasks for cwe in t.cwe_ids}),
        }
