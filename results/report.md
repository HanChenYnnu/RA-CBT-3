# Results Report

Aggregated over **3 seed(s)** with mean±std summary.

## Paired Controls
- S1_key_leak_hard ↔ S1_benign_control_hard
- S2_token_leak_hard ↔ S2_benign_control_hard
- S3_replay_hard ↔ S3_benign_control_hard
- S3_replay_nearmiss_hard ↔ S3_benign_control_hard

## B4 risk quality
- Overall AUROC: **0.9219**
- Overall PR-AUC: **0.9433**
- Non-deny (allow+throttle) AUROC: **0.7258**
- Non-deny (allow+throttle) PR-AUC: **0.6784**

## Served-traffic ranking quality

| slice | n_non_deny | n_attack_non_deny | n_benign_non_deny | base_attack_rate_non_deny | P@30 | lift@30 |
|---|---:|---:|---:|---:|---:|---:|
| S1_pair | 126 | 6 | 120 | 0.0476 | N/A | N/A |
| S2_pair | 240 | 0 | 240 | 0.0000 | N/A | N/A |
| S3_pair | 963 | 303 | 660 | 0.3146 | 1.0000 | 3.1782 |
| overall | 8703 | 1683 | 7020 | 0.1934 | 1.0000 | 5.1711 |

## Bootstrap (B4 S3_pair)

| K | P@K (95% CI) | lift@K (95% CI) |
|---:|---:|---:|
| 10 | 1.0000 [1.0000, 1.0000] | 3.1782 [2.9006, 3.4891] |
| 30 | 1.0000 [1.0000, 1.0000] | 3.1782 [2.9006, 3.4891] |
| 100 | 1.0000 [1.0000, 1.0000] | 3.1782 [2.9006, 3.4891] |
| 200 | 0.9900 [0.8700, 1.0000] | 3.1464 [2.8576, 3.3007] |
- non-deny PR-AUC: **0.7765** [0.7344, 0.8142]
- base attack rate non-deny: **0.3146** [0.2866, 0.3448]
- K=200 valid: **yes**

## LOSO evaluation

| heldout_group | non-deny PR-AUC | n_non_deny | n_attack_non_deny | n_benign_non_deny |
|---|---:|---:|---:|---:|
| S1_pair | N/A | 126 | 6 | 120 |
| S2_pair | N/A | 240 | 0 | 240 |
| S3_pair | 0.7765 | 963 | 303 | 660 |

## Budget sweep (label-split)

### Attack panel

| scale | ASR_allow_attack | ASR_non_deny_attack | cost_attack | throttle_attack | p95_attack |
|---:|---:|---:|---:|---:|---:|
| 1.00 | 0.1829 | 0.5417 | 1073.33 | 0.3588 | 21.310 |
| 0.70 | 0.1829 | 0.5417 | 899.67 | 0.3588 | 21.351 |
| 0.50 | 0.1829 | 0.5417 | 783.33 | 0.3588 | 20.802 |
| 0.35 | 0.1736 | 0.5417 | 729.00 | 0.3681 | 20.789 |
| 0.25 | 0.1736 | 0.5417 | 707.67 | 0.3681 | 20.878 |

### Benign panel

| scale | SR_benign | FRR_benign | throttle_benign | p95_benign |
|---:|---:|---:|---:|---:|
| 1.00 | 1.0000 | 0.0000 | 0.0000 | 19.308 |
| 0.70 | 1.0000 | 0.0000 | 0.0000 | 19.132 |
| 0.50 | 1.0000 | 0.0000 | 0.0000 | 19.066 |
| 0.35 | 1.0000 | 0.0000 | 0.0000 | 18.885 |
| 0.25 | 1.0000 | 0.0000 | 0.0000 | 18.907 |

## Metric definitions
- SR (success_rate): 2xx + reason=ok over all requests.
- ASR_allow: decision=allow and 2xx + reason=ok over all requests.
- ASR_non_deny: decision in {allow, throttle} and 2xx + reason=ok over all requests.
