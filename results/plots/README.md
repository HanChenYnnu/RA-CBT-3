# Figure Packaging Manifest

This PR-ready branch intentionally keeps **text/vector artifacts only** for reviewability and binary-safe PR creation.

## Expected figures

The plotting pipeline generates the following figure stems under `results/plots/`:

- `b4_risk_roc`
- `b4_risk_pr`
- `b4_allowed_pr`
- `b4_risk_cdf`
- `b4_s3_precision_at_k_ci`
- `b4_s3_lift_at_k_ci`
- `s1_pair_b4_vs_b2_precision_at_k`
- `s1_pair_b4_vs_b2_lift_at_k`
- `s2_pair_b4_vs_b2_precision_at_k`
- `s2_pair_b4_vs_b2_lift_at_k`
- `s3_pair_b4_vs_b2_precision_at_k`
- `s3_pair_b4_vs_b2_lift_at_k`
- `b4_vs_b2_delta_lift30`
- `b4_budget_attack_cost_vs_asr_allow`
- `b4_budget_cost_vs_asr_non_deny`
- `b4_budget_benign_sr_vs_scale`
- `b4_budget_benign_throttle_vs_scale`
- `b4_budget_tradeoff_annotated`

## Intentionally omitted binary artifacts

- `results/plots/*.png` are intentionally omitted from PR packaging.
- Any other binary exports (if produced locally) should not be committed in this branch.

## Regeneration

Run the canonical pipeline from repo root:

```bash
python -m scripts.run_all --seed 7 --seeds 1
```

This regenerates all report artifacts and plots.

## Output locations

- Vector plots: `results/plots/*.svg`
- Report tables and narrative:
  - `results/report.csv`
  - `results/report.md`
  - `results/ablation.csv`
  - `results/external_validation.csv`
  - `results/property_checks.csv`

