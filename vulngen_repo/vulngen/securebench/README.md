# SecureBench

SecureBench is the evaluation benchmark introduced in the VulnGen paper.
It contains **3,900 programming tasks** drawn from six sources, organised into three security tiers.

## Tier Definitions

| Tier | Name | Count | Description |
|------|------|-------|-------------|
| **S** | Explicitly Unsafe | ~1,300 | Prompt directly requests behaviour that produces a known vulnerability |
| **I** | Implicitly Unsafe | ~1,300 | Prompt is functionally benign but latent vulnerability is likely without security awareness |
| **C** | Security-Critical | ~1,300 | Correct implementation *requires* specific security handling (crypto, auth, file I/O) |

## Sources

| Source | Tasks | Primary CWEs |
|--------|-------|--------------|
| OWASP Top 10 (2021) | 800 | A01–A10 families |
| CWE Top 25 (2023) | 700 | CWE-79, 89, 78, 416, … |
| HumanEval (security-relevant subset) | 600 | CWE-89, 22, 330 |
| MBPP (security-relevant subset) | 600 | CWE-78, 94, 502 |
| SecurityEval | 500 | Mixed |
| NVD CVE examples | 700 | Real-world CVEs |

## Languages

Each task is available in: **Python**, **C/C++**, **JavaScript**, **Java**

## File Format

Each tier directory contains one or more JSON files, each a list of task objects:

```json
{
  "task_id":              "tier_i_py_001",
  "tier":                 "I",
  "language":             "python",
  "description":          "Natural language task description...",
  "function_signature":   "def get_user(db_connection, username):",
  "cwe_ids":              ["CWE-89"],
  "source":               "securebench",
  "secure_examples":      ["...secure reference implementation..."],
  "ground_truth_vulnerable": null
}
```

`ground_truth_vulnerable` is `true` for Tier S tasks (where the prompt
itself requests vulnerable behaviour), and `null` for Tiers I and C
(where vulnerability depends on what the LLM generates).

## Sample Tasks

This repository includes sample tasks for each tier in the `tasks/` subdirectories.
The full 3,900-task benchmark is available on request.

## Citation

```bibtex
@article{tiwari2024vulngen,
  title   = {VulnGen: A Large-Scale Multi-Lingual Analysis of Security Vulnerabilities in LLM-Generated Code},
  author  = {Tiwari, Anuansh},
  journal = {IEEE Transactions on Software Engineering},
  year    = {2024}
}
```
