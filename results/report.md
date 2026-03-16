# 1. Current Result Snapshot

Final audited key metrics used in the verdict path:

| metric_name | latest_value |
|---|---:|
| S4 PR-AUC | 0.9623 |
| S4 Lift@100 | 2.7202 |
| scale=1.00 SR_benign | 0.2100 |
| scale=1.00 ASR_non_deny_attack | 0.1900 |

These are current-run values and are used with explicit comparability caveats.

# 2. Audit-Aligned Metric Provenance

| metric_name | latest_value | before_value_used | before_single_run_consistent | metric_storage_type | report.csv support |
|---|---:|---:|---|---|---|
| S4 PR-AUC | 0.9623 | 0.9889 | no | derived_in_report | `audit_summary,S4 PR-AUC,...` |
| S4 Lift@100 | 2.7202 | 2.1030 | no | derived_in_report | `audit_summary,S4 Lift@100,...` |
| scale=1.00 SR_benign | 0.2100 | 0.1800 | no | direct_raw_csv | `audit_summary,scale=1.00 SR_benign,...` |
| scale=1.00 ASR_non_deny_attack | 0.1900 | 0.2200 | no | direct_raw_csv | `audit_summary,scale=1.00 ASR_non_deny_attack,...` |

Notes:
- The latest SR/ASR values are direct fields from the `B4,S4_mixedload_sweep_x1.00` raw row in `report.csv`.
- The latest S4 PR-AUC and S4 Lift@100 values are derived/aggregated values recorded in the audit summary block, not directly stored as a single raw S4 row value.
- Before values used in the verdict path are not from one single consistent prior run.

# 3. Experiment Consistency Audit

- **before source mismatch**: before values were assembled from mixed prior sources rather than one consistent prior run artifact set.
- **metric code drift**: ranking/served-metric computation changed between compared runs, so metric implementation is not identical across before vs after.
- Sample-count shifts strengthen comparability risk:
  - S4 served slice `n_non_deny` shifted from 17,460 (attack 8,460 / benign 9,000) to 2,372 (attack 872 / benign 1,500).
  - scale=1.00 mixed-load `n_non_deny` shifted from 18,382 (attack 8,741 / benign 9,641) to 3,252 (attack 1,111 / benign 2,141).

# 4. Final Comparability Verdict

Final verdict: **PARTIALLY VALID**

Reason it is not **VALID**:
- **before source mismatch**
- **metric code drift**
- sample-count shifts further increase comparability risk

# 5. Required Follow-Up

A strict apples-to-apples claim requires rerun or re-baselining under one consistent prior run and unchanged metric code.
