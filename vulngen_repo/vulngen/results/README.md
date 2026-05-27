# Results

Pipeline output is saved here. Each run creates a timestamped subdirectory:

```
results/
  vulngen_20241201_143022/
    stage1_tasks.json
    stage2_prompts.json
    stage3_generated.json
    stage4_analysis.json
    stage5_wild.json        (if --real-world was set)
    stage6_scored.json
    metrics_report.json
    pipeline.log
    figures/
      fig1_vr_by_model.pdf
      fig2_prompt_hardening.pdf
      fig3_cwe_distribution.pdf
```

This directory is gitignored — do not commit results.
