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
- Overall AUROC: **0.4577**
- Overall PR-AUC: **0.6566**
- Non-deny (allow+throttle) AUROC: **0.4265**
- Non-deny (allow+throttle) PR-AUC: **0.6203**

## Served-traffic ranking quality

| slice | n_non_deny | n_attack_non_deny | n_benign_non_deny | base_attack_rate_non_deny | P@30 | lift@30 |
|---|---:|---:|---:|---:|---:|---:|
| S1_pair | 546 | 216 | 330 | 0.3956 | 1.0000 | 2.5278 |
| S2_pair | 538 | 208 | 330 | 0.3866 | 1.0000 | 2.5865 |
| S3_pair | 933 | 543 | 390 | 0.5820 | 1.0000 | 1.7182 |
| overall | 95504 | 45716 | 49788 | 0.4787 | 1.0000 | 2.0891 |

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
| S1_pair | 1.0000 [1.0000, 1.0000] | 0.4000 [0.2667, 0.6667] | 0.4447 [0.3878, 0.4967] | 1.7278 [1.2012, 2.1124] | 1.5878 [1.2869, 1.9220] |
| S2_pair | 1.0000 [1.0000, 1.0000] | 0.6667 [0.5333, 0.8000] | 0.3746 [0.3144, 0.4249] | 1.3558 [0.9575, 1.8446] | 1.6081 [1.2630, 1.9214] |
| S3_pair | 1.0000 [1.0000, 1.0000] | 0.7000 [0.5667, 0.9000] | -0.0386 [-0.0934, 0.0117] | 0.6932 [0.3881, 0.9414] | 0.6932 [0.5347, 0.8447] |
| overall | 1.0000 [1.0000, 1.0000] | 0.0000 [0.0000, 0.0000] | 0.2183 [0.1830, 0.2464] | 1.4166 [1.0242, 1.7162] | 1.2660 [1.0615, 1.4481] |

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
| 1.00 | 0.0691 | 0.1760 | 9249.00 | 0.8620 | 19.003 |
| 0.70 | 0.0443 | 0.1207 | 6301.33 | 0.8868 | 17.744 |
| 0.50 | 0.0331 | 0.0842 | 4426.00 | 0.8980 | 16.782 |
| 0.35 | 0.0236 | 0.0587 | 3089.33 | 0.9075 | 3.831 |
| 0.25 | 0.0184 | 0.0444 | 2326.33 | 0.9127 | 3.738 |

### Benign panel

| scale | SR_benign | FRR_benign | throttle_benign | p95_benign |
|---:|---:|---:|---:|---:|
| 1.00 | 0.1474 | 0.0000 | 0.8526 | 16.685 |
| 0.70 | 0.1007 | 0.0000 | 0.8993 | 15.726 |
| 0.50 | 0.0729 | 0.0000 | 0.9271 | 10.688 |
| 0.35 | 0.0498 | 0.0000 | 0.9502 | 3.671 |
| 0.25 | 0.0365 | 0.0000 | 0.9635 | 3.622 |

## Metric definitions
- SR (success_rate): 2xx + reason=ok over all requests.
- ASR_allow: decision=allow and 2xx + reason=ok over all requests.
- ASR_non_deny: decision in {allow, throttle} and 2xx + reason=ok over all requests.
