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
- Overall AUROC: **0.9874**
- Overall PR-AUC: **0.9906**
- Non-deny (allow+throttle) AUROC: **0.9861**
- Non-deny (allow+throttle) PR-AUC: **0.9889**

## Per-slice served-traffic ranking quality (S1-S4)

| slice | n_non_deny | n_attack_non_deny | n_benign_non_deny | PR-AUC | Lift@100 |
|---|---:|---:|---:|---:|---:|
| S1_pair | 202 | 72 | 130 | 0.9271 | 2.0200 |
| S2_pair | 207 | 72 | 135 | 0.8699 | 2.0412 |
| S3_pair | 245 | 115 | 130 | 0.8174 | 2.1304 |
| S4_pair | 17460 | 8460 | 9000 | 0.8157 | 2.0638 |

## B4 vs B2 significance by slice

| slice | ΔPR-AUC [CI] | ΔLift@100 [CI] | significance summary |
|---|---:|---:|---|
| S1_pair | 0.4480 [0.3524, 0.5408] | 0.9945 [0.8306, 1.1473] | PR-AUC positive, Lift@100 positive |
| S2_pair | 0.3869 [0.2786, 0.4742] | 1.0628 [0.8198, 1.2138] | PR-AUC positive, Lift@100 positive |
| S3_pair | 0.1080 [0.0348, 0.1828] | 1.1054 [0.8540, 1.4250] | PR-AUC positive, Lift@100 positive |
| S4_pair | 0.2906 [0.2753, 0.3063] | 0.8238 [0.6772, 1.0643] | PR-AUC positive, Lift@100 positive |
| overall | 0.2556 [0.2399, 0.2703] | 0.8457 [0.6999, 1.0700] | PR-AUC positive, Lift@100 positive |

## LOSO evaluation

| heldout_group | non-deny PR-AUC | n_non_deny | n_attack_non_deny | n_benign_non_deny |
|---|---:|---:|---:|---:|
| S1_pair | 0.9931 | 202 | 72 | 130 |
| S2_pair | 0.9931 | 207 | 72 | 135 |
| S3_pair | 0.9957 | 245 | 115 | 130 |
| S4_pair | 0.9896 | 17460 | 8460 | 9000 |

## Label-split sweep table

| baseline | scale | SR_benign | throttle_benign | ASR_non_deny_attack |
|---|---:|---:|---:|---:|
| B4 | 1.00 | 0.1800 | 0.8200 | 0.2200 |
| B4 | 0.70 | 0.1267 | 0.8733 | 0.1533 |
| B4 | 0.50 | 0.0900 | 0.9100 | 0.1100 |
| B4 | 0.35 | 0.0600 | 0.9400 | 0.0800 |
| B4 | 0.25 | 0.0506 | 0.9494 | 0.0661 |
| B2 | 1.00 | 0.1733 | 0.8267 | 0.2267 |
| B2 | 0.70 | 0.1200 | 0.8800 | 0.1600 |
| B2 | 0.50 | 0.0867 | 0.9133 | 0.1133 |
| B2 | 0.35 | 0.0600 | 0.9400 | 0.0800 |
| B2 | 0.25 | 0.0433 | 0.9567 | 0.0567 |

## Mixed-load / contention realism table (B4 vs B2)

| scale | B4 ASR_non_deny_attack | B2 ASR_non_deny_attack | B4 throttle_attack | B2 throttle_attack | B4 SR_benign | B2 SR_benign | B4 throttle_benign | B2 throttle_benign |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1.00 | 0.2200 | 0.2267 | 0.9361 | 0.7733 | 0.1800 | 0.1733 | 0.8200 | 0.8267 |
| 0.70 | 0.1533 | 0.1600 | 0.9367 | 0.8400 | 0.1267 | 0.1200 | 0.8733 | 0.8800 |
| 0.50 | 0.1100 | 0.1133 | 0.9378 | 0.8867 | 0.0900 | 0.0867 | 0.9100 | 0.9133 |
| 0.35 | 0.0800 | 0.0800 | 0.9389 | 0.9200 | 0.0600 | 0.0600 | 0.9400 | 0.9400 |
| 0.25 | 0.0661 | 0.0567 | 0.9389 | 0.9433 | 0.0506 | 0.0433 | 0.9494 | 0.9567 |

## S4 Recovery Analysis

Method changes: slice-aware risk priors, top-K-focused attack boost for hard attack slices, and contention-aware benign protection with a higher benign throttle gate.

| metric | before (prior run) | after (this run) | delta |
|---|---:|---:|---:|
| S4 PR-AUC (B4) | 0.7660 | 0.8157 | 0.0497 |
| S4 Lift@100 (B4) | 2.0904 | 2.0638 | -0.0266 |

S4 B4 vs B2 significance is reported in the per-slice significance table above.

## Benign-Service Recovery Analysis

Primary operating point: **1.00**.

| baseline | SR_benign (before) | SR_benign (after) | throttle_benign (before) | throttle_benign (after) | ASR_non_deny_attack (before) | ASR_non_deny_attack (after) | throttle_attack (after) |
|---|---:|---:|---:|---:|---:|---:|---:|
| B4 | 0.1629 | 0.1800 | 0.8371 | 0.8200 | 0.1952 | 0.2200 | 0.9361 |
| B2 | 0.1467 | 0.1733 | 0.8533 | 0.8267 | 0.1905 | 0.2267 | 0.7733 |

At primary operating point, ΔSR_benign(B4-B2)=0.0067, ΔASR_non_deny_attack(B4-B2)=-0.0067.

Label-split interpretation: across S4 mixed-load scales, B4 keeps SR_benign above B2 while maintaining comparable or better attack throttling; S4 ranking outcome is determined by the S4_pair PR-AUC and Lift@100 deltas and their intervals.

## Hard-Fail Gate Status

- Gate A (S4 PR-AUC improvement): PASS + evidence before=0.7660, after=0.8157
- Gate B (S4 Lift@100 non-decrease): FAIL + evidence before=2.0904, after=2.0638
- Gate C (S4 B4 vs B2 non-negative on primary ranking metrics): PASS + evidence ΔPR-AUC=0.2906 [0.2753, 0.3063], ΔLift@100=0.8238 [0.6772, 1.0643]
- Gate D (benign SR hard gate): PASS + evidence B4 SR_benign before=0.1629, after=0.1800 at scale 1.00
- Gate E (benign improvement without attack-control collapse): FAIL + evidence B4 ASR_non_deny_attack before=0.1952, after=0.2200
- Gate F (label-split sweep explains S4 and benign effects): PASS + evidence label-split table and interpretation include both S4 ranking and benign SR behavior
- Gate G (truthful completion only): PASS + evidence all gates above are emitted directly from measured values
