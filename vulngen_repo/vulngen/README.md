# VulnGen: Security Vulnerabilities in LLM-Generated Code

> **VulnGen: A Large-Scale Multi-Lingual Analysis of Security Vulnerabilities in LLM-Generated Code**
>
> Anuansh Tiwari — Department of Computer Science and Engineering, Amity University Lucknow, India
> anuanshtiwari191@gmail.com | ORCID: 0009-0007-4226-7925

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![IEEE TSE](https://img.shields.io/badge/Venue-IEEE%20TSE-red.svg)]()

---

## Overview

VulnGen is an automated **six-stage security assessment pipeline** for detecting and analysing security vulnerabilities in LLM-generated code. Across **79,632 controlled code artefacts** spanning Python, C/C++, JavaScript, and Java from seven LLMs, the study finds **35.2% of generated functions contain at least one security-relevant defect**, with 34.2% of confirmed weaknesses at High or Critical CVSS severity.

Key findings:
- Even GPT-4o produces vulnerable code in **1 in 5 generated functions** (19.8% VR)
- Combined prompt hardening achieves **87% of fine-tuning security benefit at zero training cost**
- Pipeline FPR = **8.3%**, inter-rater agreement κ = **0.81**
- Real-world validation: **31.7–33.1% VR** across Copilot, CodeWhisperer, and Cursor (1,600 snippets)

---

## Repository Structure

```
vulngen/
├── vulngen/                   # Core pipeline package
│   ├── pipeline.py            # Main 6-stage orchestrator
│   ├── stage1_curation.py     # SecureBench task curation
│   ├── stage2_prompts.py      # Prompt hardening templates
│   ├── stage3_generation.py   # LLM code generation
│   ├── stage4_analysis.py     # SAST ensemble + dynamic analysis
│   ├── stage5_validation.py   # Real-world GitHub validation
│   ├── stage6_scoring.py      # CWE normalisation + CVSS scoring
│   ├── sast/                  # SAST tool runners
│   │   ├── ensemble.py        # Majority-voting ensemble
│   │   ├── bandit_runner.py   # Python — Bandit
│   │   ├── semgrep_runner.py  # Multi-language — Semgrep
│   │   ├── codeql_runner.py   # Multi-language — CodeQL
│   │   └── cppcheck_runner.py # C/C++ — Cppcheck
│   ├── models/
│   │   └── llm_client.py      # OpenAI API + vLLM local models
│   ├── metrics/
│   │   └── evaluation.py      # VR, SUT, Cohen's d, 95% CI
│   └── utils/
│       └── helpers.py         # Shared utilities
├── securebench/               # SecureBench dataset (3,900 tasks)
│   └── tasks/
│       ├── tier_s/            # Tier S — Explicitly Unsafe
│       ├── tier_i/            # Tier I — Implicitly Unsafe
│       └── tier_c/            # Tier C — Security-Critical
├── scripts/
│   ├── run_pipeline.py        # End-to-end pipeline runner
│   ├── evaluate_results.py    # Metrics and report generation
│   └── reproduce_paper.sh     # Full paper reproduction script
├── examples/
│   ├── sql_injection_demo.py  # CWE-89 worked example (Section VI)
│   └── prompt_templates.py    # All prompt templates (Appendix A)
├── docker/
│   └── Dockerfile             # Containerised environment
├── results/                   # Output directory (gitignored)
├── requirements.txt
└── setup.py
```

---

## Quick Start

### 1. Install dependencies

```bash
git clone https://github.com/glassgotlazy/vulngen.git
cd vulngen
pip install -r requirements.txt
```

### 2. Set API keys

```bash
export OPENAI_API_KEY="your-key-here"
```

### 3. Run the full pipeline on a small sample

```bash
python scripts/run_pipeline.py \
    --tasks securebench/tasks/ \
    --models gpt-4o gpt-4 \
    --languages python javascript \
    --hardening baseline sp cb fse combined \
    --output results/my_run/
```

### 4. Evaluate and generate report

```bash
python scripts/evaluate_results.py --results results/my_run/
```

---

## Pipeline Stages

| Stage | Description |
|-------|-------------|
| **1 — Task Curation** | Loads SecureBench tasks (Tier S/I/C) from OWASP Top 10, CWE Top 25, HumanEval, MBPP, SecurityEval, NVD |
| **2 — Prompt Generation** | Applies hardening conditions: Baseline, SP, CB, FSE, CoST, Combined (SP+CB+FSE) |
| **3 — Code Generation** | Calls OpenAI API or vLLM (local) at T=0 and stochastic T∈{0.2–1.0} |
| **4 — SAST + Dynamic** | Runs Bandit / Semgrep / CodeQL / Cppcheck / SpotBugs ensemble with majority voting; AFL++ fuzzing |
| **5 — Real-World Validation** | Evaluates GitHub Copilot, CodeWhisperer, Cursor snippets from public repos |
| **6 — CWE + CVSS Scoring** | Normalises CWE IDs, assigns CVSS v3.1 scores, produces final vulnerability report |

---

## Prompt Hardening Techniques (Appendix A)

| Technique | Description | Cohen's d vs Baseline |
|-----------|-------------|----------------------|
| Baseline | No hardening | 0.00 (ref) |
| Security Persona (SP) | Expert role framing | 0.42 (small) |
| Constraint-Based (CB) | Forbidden patterns + required practices | 0.71 (medium) |
| Few-Shot Exemplars (FSE) | 2–3 annotated secure examples | 0.56 (medium) |
| CoST | Security risk enumeration before coding | 0.51 (medium) |
| **Combined (SP+CB+FSE)** | **All three combined** | **1.14 (large)** |

See `examples/prompt_templates.py` for verbatim templates.

---

## Models Evaluated

| Model | Params | Access | Weighted Avg VR |
|-------|--------|--------|-----------------|
| GPT-4o | Undisclosed | OpenAI API | 19.8% |
| GPT-4 | Undisclosed | OpenAI API | 24.2% |
| GPT-3.5-turbo | Undisclosed | OpenAI API | 31.8% |
| DeepSeek-Coder-33B | 33B | Open weights | 34.1% |
| CodeLlama-34B | 34B | Open weights | 36.7% |
| StarCoder-15B | 15.5B | Open weights | 39.8% |
| CodeLlama-7B | 7B | Open weights | 43.9% |

---

## Citation

If you use VulnGen or SecureBench in your research, please cite:

```bibtex
@article{tiwari2024vulngen,
  title   = {VulnGen: A Large-Scale Multi-Lingual Analysis of Security Vulnerabilities in LLM-Generated Code},
  author  = {Tiwari, Anuansh},
  journal = {IEEE Transactions on Software Engineering},
  year    = {2024},
  note    = {Under Review}
}
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
