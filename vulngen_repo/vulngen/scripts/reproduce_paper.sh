#!/usr/bin/env bash
# scripts/reproduce_paper.sh
# ---------------------------
# Reproduces the main results of the VulnGen paper.
# Requires: OpenAI API key, ~72h compute, 4× A100 80GB for open-weight models.
#
# Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>

set -euo pipefail

echo "======================================"
echo " VulnGen — Full Paper Reproduction"
echo "======================================"
echo ""

# ---------- Prerequisites check ----------
check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "WARNING: $1 not found — some stages may be skipped."
    fi
}

check_cmd bandit
check_cmd semgrep
check_cmd codeql
check_cmd cppcheck
check_cmd python3

if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "ERROR: OPENAI_API_KEY not set."
    exit 1
fi

# ---------- Controlled study (Stages 1–4, 6) ----------
echo "[1/3] Running controlled study (all 7 models, 4 languages, 6 conditions)…"
python scripts/run_pipeline.py \
    --models gpt-4o gpt-4 gpt-3.5-turbo \
             codellama-34b codellama-7b starcoder-15b deepseek-coder-33b \
    --languages python cpp javascript java \
    --hardening baseline sp cb fse cost combined \
    --tiers S I C \
    --output results/paper_full/ \
    --seed 42

# ---------- Real-world validation (Stage 5) ----------
if [ -n "${GITHUB_TOKEN:-}" ]; then
    echo "[2/3] Running real-world validation (1,600 snippets)…"
    python scripts/run_pipeline.py \
        --models gpt-4o \
        --languages python cpp javascript java \
        --hardening baseline \
        --max-tasks 1 \
        --real-world \
        --output results/paper_full/ \
        --seed 42
else
    echo "[2/3] GITHUB_TOKEN not set — skipping real-world validation."
fi

# ---------- Evaluation & figures ----------
echo "[3/3] Computing metrics and generating figures…"
python scripts/evaluate_results.py \
    --results results/paper_full/ \
    --figures

echo ""
echo "======================================"
echo " Reproduction complete."
echo " Results: results/paper_full/"
echo "======================================"
