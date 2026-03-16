# Results Report

Aggregated over **3 seed(s)** with mean±std summary.

## Paired Controls
- S1_key_leak_hard ↔ S1_benign_control_hard
- S1_restricted_issuance_hard ↔ S1_benign_control_hard
- S2_token_leak_hard ↔ S2_benign_control_hard
- S2_delegated_misuse_hard ↔ S2_benign_control_hard
- S3_replay_hard ↔ S3_benign_control_hard
- S3_replay_nearmiss_hard ↔ S3_benign_control_hard
- S3_replay_blended_hard ↔ S3_benign_control_hard

## B4 risk quality
- Overall AUROC: **0.5779**
- Overall PR-AUC: **0.6992**
- Non-deny (allow+throttle) AUROC: **0.5006**
- Non-deny (allow+throttle) PR-AUC: **0.5947**

## Served-traffic ranking quality

| slice | n_non_deny | n_attack_non_deny | n_benign_non_deny | base_attack_rate_non_deny | P@30 | lift@30 |
|---|---:|---:|---:|---:|---:|---:|
| S1_pair | 546 | 216 | 330 | 0.3956 | 1.0000 | 2.5278 |
| S2_pair | 538 | 208 | 330 | 0.3866 | 1.0000 | 2.5865 |
| S3_pair | 933 | 543 | 390 | 0.5820 | 1.0000 | 1.7182 |
| overall | 11504 | 5216 | 6288 | 0.4534 | 1.0000 | 2.2055 |

## Bootstrap served-traffic ranking (B4)

### S1_pair
- counts: n_non_deny=546, n_attack_non_deny=216, n_benign_non_deny=330

| K | P@K (95% CI) | lift@K (95% CI) |
|---:|---:|---:|
| 10 | 1.0000 [1.0000, 1.0000] | 2.5278 [2.2941, 2.9514] |
| 30 | 1.0000 [1.0000, 1.0000] | 2.5278 [2.2941, 2.9514] |
| 100 | 1.0000 [1.0000, 1.0000] | 2.5278 [2.2941, 2.9514] |
| 200 | 1.0000 [0.9100, 1.0000] | 2.5278 [2.2941, 2.7163] |
- non-deny PR-AUC: **0.9277** [0.9034, 0.9527]
- base attack rate non-deny: **0.3956** [0.3388, 0.4359]

### S2_pair
- counts: n_non_deny=538, n_attack_non_deny=208, n_benign_non_deny=330

| K | P@K (95% CI) | lift@K (95% CI) |
|---:|---:|---:|
| 10 | 1.0000 [1.0000, 1.0000] | 2.5865 [2.3090, 2.8617] |
| 30 | 1.0000 [1.0000, 1.0000] | 2.5865 [2.3090, 2.8617] |
| 100 | 1.0000 [1.0000, 1.0000] | 2.5865 [2.3090, 2.8617] |
| 200 | 1.0000 [0.9400, 1.0000] | 2.5865 [2.3090, 2.6900] |
- non-deny PR-AUC: **0.9062** [0.8793, 0.9313]
- base attack rate non-deny: **0.3866** [0.3494, 0.4331]

### S3_pair
- counts: n_non_deny=933, n_attack_non_deny=543, n_benign_non_deny=390

| K | P@K (95% CI) | lift@K (95% CI) |
|---:|---:|---:|
| 10 | 1.0000 [1.0000, 1.0000] | 1.7182 [1.6254, 1.8012] |
| 30 | 1.0000 [1.0000, 1.0000] | 1.7182 [1.6254, 1.8012] |
| 100 | 1.0000 [0.9400, 1.0000] | 1.7182 [1.6031, 1.7839] |
| 200 | 0.7900 [0.7250, 0.8600] | 1.3574 [1.2494, 1.4657] |
- non-deny PR-AUC: **0.6381** [0.5985, 0.6679]
- base attack rate non-deny: **0.5820** [0.5552, 0.6152]

## B4 vs B2 served-traffic comparison

| slice | B4 P@30 [CI] | B2 P@30 [CI] | ΔPR-AUC [CI] | ΔLift@30 [CI] | ΔLift@100 [CI] |
|---|---:|---:|---:|---:|---:|
| S1_pair | 1.0000 [1.0000, 1.0000] | 0.3667 [0.2333, 0.5667] | 0.4230 [0.3624, 0.4786] | 1.7944 [1.3781, 2.2115] | 1.4278 [1.1585, 1.7922] |
| S2_pair | 1.0000 [1.0000, 1.0000] | 0.5333 [0.3333, 0.7333] | 0.3440 [0.2859, 0.4041] | 1.6019 [1.2018, 2.0568] | 1.5896 [1.2720, 1.8891] |
| S3_pair | 1.0000 [1.0000, 1.0000] | 0.7000 [0.5333, 0.8333] | -0.0253 [-0.0751, 0.0264] | 0.6932 [0.4619, 0.9747] | 0.7518 [0.5772, 0.8962] |
| overall | 1.0000 [1.0000, 1.0000] | 0.0667 [0.0000, 0.1667] | 0.2042 [0.1707, 0.2316] | 1.3608 [0.9873, 1.6585] | 1.1824 [0.9798, 1.3680] |

## LOSO evaluation

| heldout_group | non-deny PR-AUC | n_non_deny | n_attack_non_deny | n_benign_non_deny |
|---|---:|---:|---:|---:|
| S1_pair | 0.9277 | 546 | 216 | 330 |
| S2_pair | 0.9062 | 538 | 208 | 330 |
| S3_pair | 0.6381 | 933 | 543 | 390 |

## Mixed-load contention sweep

Label-split metrics are reported under shared queue/budget pressure so benign and attack traffic contend for the same limiter state.

### Attack panel

| scale | ASR_allow_attack | ASR_non_deny_attack | cost_attack | throttle_attack | p95_attack |
|---:|---:|---:|---:|---:|---:|
| 1.00 | 0.0611 | 0.1722 | 839.33 | 0.8700 | 3.814 |
| 0.70 | 0.0411 | 0.1211 | 588.67 | 0.8900 | 4.336 |
| 0.50 | 0.0311 | 0.0844 | 413.00 | 0.9000 | 4.166 |
| 0.35 | 0.0222 | 0.0589 | 289.00 | 0.9089 | 3.810 |
| 0.25 | 0.0167 | 0.0433 | 211.67 | 0.9144 | 3.724 |

### Benign panel

| scale | SR_benign | FRR_benign | throttle_benign | p95_benign |
|---:|---:|---:|---:|---:|
| 1.00 | 0.1444 | 0.0000 | 0.8556 | 3.594 |
| 0.70 | 0.1011 | 0.0000 | 0.8989 | 3.923 |
| 0.50 | 0.0733 | 0.0000 | 0.9267 | 3.951 |
| 0.35 | 0.0500 | 0.0000 | 0.9500 | 3.655 |
| 0.25 | 0.0356 | 0.0000 | 0.9644 | 3.645 |

## Metric definitions
- SR (success_rate): 2xx + reason=ok over all requests.
- ASR_allow: decision=allow and 2xx + reason=ok over all requests.
- ASR_non_deny: decision in {allow, throttle} and 2xx + reason=ok over all requests.
