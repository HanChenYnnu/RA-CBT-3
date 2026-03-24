# 1. Frozen Evaluation Protocol
- Strategy chosen: **STRATEGY B — re-run both baseline and current method under one frozen shared pipeline**.
- Frozen protocol run id: **shared-pipeline:15311eb65f927bd60f18065e74753ff791e4b999:seeds=1:seed_start=7**.
- Frozen stack (shared for before and after):
  - metric code: `experiments/metrics.py`
  - slice definitions: `scripts/run_all.py` LOSO groups + `experiments/scenario_contract.py`
  - served/non-deny definition + served filtering: `experiments/metrics.py`
  - mixed-load construction: `experiments/scenarios.py` S4 scenarios
  - primary operating point: `S4_mixedload_sweep_x1.00`
  - seed policy: `python -m scripts.run_all --seed 7 --seeds 1`
  - aggregation and report generation: `experiments/metrics.py` + `experiments/report.py`

# 2. Baseline Selection
- Single before baseline: **B2 from the same rerun protocol**.
- Single after run: **B4 from the same rerun protocol**.
- Why this is defensible: it removes historical mixed-source lookups and computes all compared metrics from one synchronized rerun using one code stack.

# 3. Apples-to-Apples Rerun Results
| metric_name | before (B2) | after (B4) |
|---|---:|---:|
| S4 PR-AUC | 0.5190 | 0.9638 |
| S4 Lift@100 | 1.1000 | 2.7202 |
| scale=1.00 SR_benign | 0.1733 | 0.2100 |
| scale=1.00 ASR_non_deny_attack | 0.2267 | 0.1900 |

# 4. Comparability Verification
- same metric code: **true**
- same slice definitions: **true**
- same operating point: **true**
- same seed policy: **true**
- same aggregation logic: **true**
- same non-deny definition: **true**
- same served-traffic filtering: **true**
- same mixed-load construction: **true**
- Sample-count review:
  - S4_pair n_non_deny before=9000 (attack=4500, benign=4500), after=7116 (attack=2616, benign=4500).
  - scale=1.00 mixed-load n_non_deny before=1800 (attack=900, benign=900), after=1434 (attack=534, benign=900).
  - scale=1.00 mixed-load denominators attack before/after=900/900, benign before/after=900/900.
  - Interpretation: denominator differences reflect B2 vs B4 behavior under the same protocol, not evaluation drift.

# 5. Final Verdict
**VALID APPLES-TO-APPLES**

# 6. Residual Risks
- Numeric outcomes can change if future commits modify the frozen stack; rerun under a new stack would require a new apples-to-apples audit.
- This validation is for the explicit B2->B4 comparison path only; any historical mixed-source comparison remains deprecated.
