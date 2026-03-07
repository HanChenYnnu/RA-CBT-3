# Evaluation Report

## Served-traffic ranking quality

### B4 non-deny Precision@K and lift
| scenario | p@10 | p@30 | p@50 | lift@30 | base_attack_rate_non_deny |
|---|---:|---:|---:|---:|---:|
| S1_pair | 1.0000 | 1.0000 | 1.0000 | 7.7059 | 0.1298 |
| S2_pair | 1.0000 | 0.7000 | 0.4200 | 11.8667 | 0.0590 |
| S3_pair | 1.0000 | 1.0000 | 0.9200 | 8.4130 | 0.1189 |
| overall | 1.0000 | 1.0000 | 1.0000 | 9.6271 | 0.1039 |

### B2 contrast
| scenario | p@30 | lift@30 |
|---|---:|---:|
| S1_pair | 1.0000 | 4.3465 |
| S2_pair | 1.0000 | 5.1325 |
| S3_pair | 1.0000 | 5.0119 |
| overall | 1.0000 | 4.7985 |

## Budget sweep

### Cost-conditioned Pareto sweep (B4)
| scale | cost | ASR_allow | ASR_non_deny | throttle_rate |
|---:|---:|---:|---:|---:|
| 1.00 | 2800.0000 | 0.4700 | 0.5500 | 0.1200 |
| 0.70 | 1979.6000 | 0.6050 | 0.6850 | 0.2550 |
| 0.50 | 1400.0000 | 0.6950 | 0.7750 | 0.3450 |
| 0.35 | 980.0000 | 0.7625 | 0.8425 | 0.4125 |
| 0.25 | 700.0000 | 0.8075 | 0.8875 | 0.4575 |
