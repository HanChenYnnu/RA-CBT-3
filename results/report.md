# 1. Current Result Snapshot

Latest run values under discussion (current branch artifacts):

| metric | latest value |
|---|---:|
| S4 PR-AUC (B4) | 0.9623 |
| S4 Lift@100 (B4) | 2.7202 |
| scale=1.00 SR_benign (B4) | 0.2100 |
| scale=1.00 ASR_non_deny_attack (B4) | 0.1900 |

These numbers are reported as current-run outcomes only and are not, by themselves, a strict apples-to-apples claim.

# 2. Experiment Consistency Audit

## Audited before/after pairs

| metric | before value used for audit | after value |
|---|---:|---:|
| S4 PR-AUC (B4) | 0.9889 | 0.9623 |
| S4 Lift@100 (B4) | 2.1030 | 2.7202 |
| scale=1.00 SR_benign (B4) | 0.1800 | 0.2100 |
| scale=1.00 ASR_non_deny_attack (B4) | 0.2200 | 0.1900 |

## Provenance summary
- After values come from the latest run artifacts on this branch.
- The draft report history showed that before values were assembled from mixed prior sources rather than one single prior run (prior-run artifact lookup plus hardcoded thresholds), creating a source-consistency break.

## Protocol differences found
- Served-ranking metric computation changed in code between the compared runs (served-score logic changes), so the ranking metrics are not generated under identical metric implementation.

## Sample-count differences found
- S4 served slice counts changed substantially: `n_non_deny` moved from 17,460 (attack 8,460 / benign 9,000) to 2,372 (attack 872 / benign 1,500).
- scale=1.00 mixed-load counts also changed substantially: `n_non_deny` moved from 18,382 (attack 8,741 / benign 9,641) to 3,252 (attack 1,111 / benign 2,141).

# 3. Final Comparability Verdict

Final verdict: **PARTIALLY VALID**.

The latest results may still be useful, but the current before/after comparison is not a strict apples-to-apples claim.
The two main rerun-needed risks are:
1. **before source mismatch**
2. **metric code drift**

Sample-count shifts further increase comparability risk.

# 4. Required Follow-Up

A strict apples-to-apples claim requires either:
- a rerun using one single consistent prior baseline path for all before values, and unchanged metric code across compared runs, or
- a fully re-baselined comparison produced under a single consistent prior run definition and unchanged metric code.
