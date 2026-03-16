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
- Overall AUROC: **0.5362**
- Overall PR-AUC: **0.7128**
- Non-deny (allow+throttle) AUROC: **0.4955**
- Non-deny (allow+throttle) PR-AUC: **0.6695**

## Served-traffic ranking quality

| slice | n_non_deny | n_attack_non_deny | n_benign_non_deny | base_attack_rate_non_deny | P@30 | lift@30 |
|---|---:|---:|---:|---:|---:|---:|
| S1_pair | 606 | 216 | 390 | 0.3564 | 1.0000 | 2.8056 |
| S2_pair | 613 | 208 | 405 | 0.3393 | 1.0000 | 2.9471 |
| S3_pair | 933 | 543 | 390 | 0.5820 | 1.0000 | 1.7182 |
| overall | 55089 | 26166 | 28923 | 0.4750 | 1.0000 | 2.1054 |

## Bootstrap served-traffic ranking (B4)

### S1_pair
- counts: n_non_deny=606, n_attack_non_deny=216, n_benign_non_deny=390

| K | P@K (95% CI) | lift@K (95% CI) |
|---:|---:|---:|
| 10 | 1.0000 [1.0000, 1.0000] | 2.8056 [2.5787, 3.1237] |
| 30 | 1.0000 [1.0000, 1.0000] | 2.8056 [2.5787, 3.1237] |
| 100 | 1.0000 [1.0000, 1.0000] | 2.8056 [2.5787, 3.1237] |
| 200 | 0.9450 [0.8800, 1.0000] | 2.6513 [2.5364, 2.8035] |
- non-deny PR-AUC: **0.9338** [0.9161, 0.9532]
- base attack rate non-deny: **0.3564** [0.3201, 0.3878]

### S2_pair
- counts: n_non_deny=613, n_attack_non_deny=208, n_benign_non_deny=405

| K | P@K (95% CI) | lift@K (95% CI) |
|---:|---:|---:|
| 10 | 1.0000 [1.0000, 1.0000] | 2.9471 [2.6309, 3.3497] |
| 30 | 1.0000 [1.0000, 1.0000] | 2.9471 [2.6309, 3.3497] |
| 100 | 1.0000 [1.0000, 1.0000] | 2.9471 [2.6309, 3.3497] |
| 200 | 0.9300 [0.8300, 1.0000] | 2.7408 [2.6073, 2.8494] |
- non-deny PR-AUC: **0.9301** [0.9083, 0.9506]
- base attack rate non-deny: **0.3393** [0.2985, 0.3801]

### S3_pair
- counts: n_non_deny=933, n_attack_non_deny=543, n_benign_non_deny=390

| K | P@K (95% CI) | lift@K (95% CI) |
|---:|---:|---:|
| 10 | 1.0000 [1.0000, 1.0000] | 1.7182 [1.6455, 1.8330] |
| 30 | 1.0000 [0.8667, 1.0000] | 1.7182 [1.4354, 1.8330] |
| 100 | 0.5600 [0.4300, 0.6700] | 0.9622 [0.7570, 1.1449] |
| 200 | 0.3200 [0.2400, 0.4050] | 0.5498 [0.4290, 0.6855] |
- non-deny PR-AUC: **0.4763** [0.4366, 0.5106]
- base attack rate non-deny: **0.5820** [0.5456, 0.6077]

## B4 vs B2 significance

| slice | B4 P@30 [CI] | B2 P@30 [CI] | ΔPR-AUC [CI] | ΔLift@30 [CI] | ΔLift@100 [CI] |
|---|---:|---:|---:|---:|---:|
| S1_pair | 1.0000 [1.0000, 1.0000] | 0.3667 [0.2333, 0.5333] | 0.5012 [0.4522, 0.5524] | 2.0056 [1.6018, 2.5610] | 1.8674 [1.5397, 2.2567] |
| S2_pair | 1.0000 [1.0000, 1.0000] | 0.5667 [0.3667, 0.7000] | 0.4367 [0.3759, 0.4863] | 1.7920 [1.2866, 2.2662] | 1.9279 [1.5762, 2.3140] |
| S3_pair | 1.0000 [0.8667, 1.0000] | 0.6667 [0.5000, 0.8000] | -0.2009 [-0.2547, -0.1487] | 0.7420 [0.4504, 1.0144] | -0.0481 [-0.3071, 0.2038] |
| overall | 1.0000 [1.0000, 1.0000] | 0.0000 [0.0000, 0.0000] | 0.1001 [0.0618, 0.1342] | 1.5802 [1.2646, 1.9203] | 1.4864 [1.2410, 1.6867] |

## LOSO evaluation

| heldout_group | non-deny PR-AUC | n_non_deny | n_attack_non_deny | n_benign_non_deny |
|---|---:|---:|---:|---:|
| S1_pair | 0.8970 | 606 | 216 | 390 |
| S2_pair | 0.8438 | 613 | 208 | 405 |
| S3_pair | 0.6381 | 933 | 543 | 390 |

## Mixed-load contention sweep

Label-split metrics are reported under shared queue/budget pressure so benign and attack traffic contend for the same limiter state.

### Attack panel

| scale | ASR_allow_attack | ASR_non_deny_attack | cost_attack | throttle_attack | p95_attack |
|---:|---:|---:|---:|---:|---:|
| 1.00 | 0.0509 | 0.1741 | 5007.67 | 0.8802 | 3.964 |
| 0.70 | 0.0319 | 0.1220 | 3483.67 | 0.8993 | 4.088 |
| 0.50 | 0.0246 | 0.0854 | 2459.67 | 0.9065 | 3.958 |
| 0.35 | 0.0174 | 0.0633 | 1817.67 | 0.9137 | 3.853 |
| 0.25 | 0.0148 | 0.0446 | 1292.67 | 0.9163 | 3.786 |

### Benign panel

| scale | SR_benign | FRR_benign | throttle_benign | p95_benign |
|---:|---:|---:|---:|---:|
| 1.00 | 0.1463 | 0.0000 | 0.8537 | 3.657 |
| 0.70 | 0.1030 | 0.0000 | 0.8970 | 3.727 |
| 0.50 | 0.0733 | 0.0000 | 0.9267 | 3.730 |
| 0.35 | 0.0528 | 0.0000 | 0.9472 | 3.683 |
| 0.25 | 0.0385 | 0.0000 | 0.9615 | 3.686 |

## Hard fail gates status
- Served-traffic count sufficiency: **PASS**
- Served-traffic anti-saturation and Lift@100 constraints: **PASS**
- B4 vs B2 significance (Lift@100 / PR-AUC CIs): **PASS**
- MIN_CLASS_NON_DENY strict N/A behavior: **PASS**
- Mixed-load contention sweep realism gates: **PASS**

## Metric definitions
- SR (success_rate): 2xx + reason=ok over all requests.
- ASR_allow: decision=allow and 2xx + reason=ok over all requests.
- ASR_non_deny: decision in {allow, throttle} and 2xx + reason=ok over all requests.
