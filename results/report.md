# Defensibility report

## Bootstrap
Scenario: B4 / S3_pair

- n_non_deny: 1743
- n_attack_non_deny: 483
- n_benign_non_deny: 1260
- non-deny PR-AUC (95% CI): 0.960 [0.947, 0.970]
- non-deny base attack rate (95% CI): 0.277 [0.256, 0.298]

### K=200 coverage
- n_non_deny = 1743; Precision@200 = 1.000 [0.995, 1.000]

### S3_pair K metrics (mean [95% CI])
| Metric | Precision@K | Lift@K |
|---|---:|---:|
| K=10 | 1.000 [1.000, 1.000] | 3.614 [3.358, 3.908] |
| K=30 | 1.000 [1.000, 1.000] | 3.614 [3.358, 3.908] |
| K=100 | 1.000 [1.000, 1.000] | 3.614 [3.358, 3.908] |
| K=200 | 1.000 [0.995, 1.000] | 3.613 [3.358, 3.897] |

## Budget sweep (label-split)

### Benign panel
| scale | SR_benign | FRR_benign | throttle_benign | p95_benign |
|---:|---:|---:|---:|---:|
| 1.00 | 0.989 | 0.011 | 0.002 | 185.5 |
| 0.95 | 0.988 | 0.012 | 0.005 | 184.3 |
| 0.90 | 0.987 | 0.013 | 0.006 | 183.0 |
| 0.85 | 0.987 | 0.013 | 0.005 | 184.6 |
| 0.80 | 0.986 | 0.014 | 0.006 | 184.9 |

### Attack panel
| scale | ASR_allow_attack | ASR_non_deny_attack | cost_attack | throttle_attack | p95_attack |
|---:|---:|---:|---:|---:|---:|
| 1.00 | 0.250 | 0.280 | 0.746 | 0.068 | 217.9 |
| 0.95 | 0.238 | 0.268 | 0.721 | 0.083 | 215.1 |
| 0.90 | 0.229 | 0.259 | 0.705 | 0.087 | 217.1 |
| 0.85 | 0.224 | 0.254 | 0.680 | 0.094 | 216.4 |
| 0.80 | 0.214 | 0.244 | 0.659 | 0.102 | 216.1 |
