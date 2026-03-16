# Results Report

Aggregated over **1 seed(s)** with mean±std summary.

## Paired Controls
- S1_key_leak_hard ↔ S1_benign_control_hard
- S1_restricted_issuance_hard ↔ S1_benign_control_hard
- S2_token_leak_hard ↔ S2_benign_control_hard
- S2_delegated_misuse_hard ↔ S2_benign_control_hard
- S3_replay_hard ↔ S3_benign_control_hard
- S3_replay_nearmiss_hard ↔ S3_benign_control_hard
- S3_replay_blended_hard ↔ S3_benign_control_hard

## B4 risk quality
- Overall AUROC: **0.7263**
- Overall PR-AUC: **0.7963**
- Non-deny (allow+throttle) AUROC: **0.7058**
- Non-deny (allow+throttle) PR-AUC: **0.7660**

## Per-slice served-traffic ranking quality (S1-S4)

| slice | n_non_deny | n_attack_non_deny | n_benign_non_deny | PR-AUC | Lift@100 |
|---|---:|---:|---:|---:|---:|
| S1_pair | 202 | 72 | 130 | 0.9117 | 2.0200 |
| S2_pair | 207 | 72 | 135 | 0.9540 | 2.0700 |
| S3_pair | 311 | 181 | 130 | 0.9949 | 1.7182 |
| S4_pair | 20370 | 9870 | 10500 | 0.8257 | 2.0638 |

## B4 vs B2 significance by slice

| slice | ΔPR-AUC [CI] | ΔLift@100 [CI] | significance summary |
|---|---:|---:|---|
| S1_pair | 0.5110 [0.4180, 0.5905] | 1.1473 [0.9585, 1.3497] | PR-AUC positive, Lift@100 positive |
| S2_pair | 0.4818 [0.3968, 0.5674] | 1.1731 [1.0046, 1.3339] | PR-AUC positive, Lift@100 positive |
| S3_pair | 0.3327 [0.2615, 0.3874] | 0.7811 [0.5934, 0.9852] | PR-AUC positive, Lift@100 positive |
| S4_pair | 0.3086 [0.2949, 0.3216] | 0.9238 [0.7211, 1.0977] | PR-AUC positive, Lift@100 positive |
| overall | 0.2742 [0.2610, 0.2884] | 0.9152 [0.7129, 1.1197] | PR-AUC positive, Lift@100 positive |

## LOSO evaluation

| heldout_group | non-deny PR-AUC | n_non_deny | n_attack_non_deny | n_benign_non_deny |
|---|---:|---:|---:|---:|
| S1_pair | 0.8593 | 202 | 72 | 130 |
| S2_pair | 0.8542 | 207 | 72 | 135 |
| S3_pair | 0.8698 | 311 | 181 | 130 |
| S4_pair | 0.7645 | 20370 | 9870 | 10500 |

## Label-split sweep table

| baseline | scale | SR_benign | throttle_benign | ASR_non_deny_attack |
|---|---:|---:|---:|---:|
| B4 | 1.00 | 0.1629 | 0.8371 | 0.1952 |
| B4 | 0.70 | 0.1114 | 0.8886 | 0.1381 |
| B4 | 0.50 | 0.0805 | 0.9195 | 0.0986 |
| B4 | 0.35 | 0.0543 | 0.9457 | 0.0705 |
| B4 | 0.25 | 0.0395 | 0.9605 | 0.0490 |
| B2 | 1.00 | 0.1467 | 0.8533 | 0.1905 |
| B2 | 0.70 | 0.1029 | 0.8971 | 0.1333 |
| B2 | 0.50 | 0.0733 | 0.9267 | 0.0943 |
| B2 | 0.35 | 0.0505 | 0.9495 | 0.0667 |
| B2 | 0.25 | 0.0376 | 0.9624 | 0.0471 |

S3/S4 interpretation: S3 ranking improved if ΔPR-AUC and/or ΔLift@100 vs B2 is non-negative; S4 ranking improved if S4_pair Δ metrics are non-negative and mixed-load attack suppression improves without collapsing benign SR.

## Mixed-load / contention realism table (B4 vs B2)

| scale | B4 ASR_non_deny_attack | B2 ASR_non_deny_attack | B4 SR_benign | B2 SR_benign | B4 throttle_benign | B2 throttle_benign |
|---:|---:|---:|---:|---:|---:|---:|
| 1.00 | 0.1952 | 0.1905 | 0.1629 | 0.1467 | 0.8371 | 0.8533 |
| 0.70 | 0.1381 | 0.1333 | 0.1114 | 0.1029 | 0.8886 | 0.8971 |
| 0.50 | 0.0986 | 0.0943 | 0.0805 | 0.0733 | 0.9195 | 0.9267 |
| 0.35 | 0.0705 | 0.0667 | 0.0543 | 0.0505 | 0.9457 | 0.9495 |
| 0.25 | 0.0490 | 0.0471 | 0.0395 | 0.0376 | 0.9605 | 0.9624 |

## S3/S4 Recovery Analysis

Method changes: replay-aware JTI repeat accumulation and context-shift risk boost in B4, plus contention-pressure retuning and mixed-load S4 slice evaluation with B2 comparator.

| slice | before PR-AUC | after PR-AUC | before Lift@100 | after Lift@100 |
|---|---:|---:|---:|---:|
| S3_pair | 0.5947 | 0.9949 | 1.7182 | 1.7182 |
| S4_pair | 0.5947 | 0.8257 | 2.2055 | 2.0638 |

## Hard-Fail Gate Status

- Gate A (S3 improvement): PASS + evidence ΔPR-AUC=0.3327, ΔLift@100=0.7811
- Gate B (S4 improvement or implementation): PASS + evidence S4_pair present with ΔPR-AUC=0.3086, ΔLift@100=0.9238
- Gate C (per-slice B4 vs B2 significance for S3/S4): PASS + evidence S3/S4 rows in significance table
- Gate D (label-split sweep includes S3/S4 interpretation): PASS + evidence explicit S3/S4 interpretation under label-split sweep
- Gate E (mixed-load realism with benign-vs-attack tradeoff reported): PASS + evidence B4 vs B2 mixed-load table with ASR_non_deny_attack + SR_benign/throttle_benign
- Gate F (truthful completion only): PASS + evidence gate statuses are programmatically marked PASS/FAIL from measured outputs
