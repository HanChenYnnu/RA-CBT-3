# Results Report

Generated 10 baseline/scenario metric rows from deterministic synthetic events.

| baseline | scenario | attack_success_rate | cost_leakage_tokens | p50_ms | p95_ms |
|---|---:|---:|---:|---:|---:|
| B0 | S4_burst | 1.0000 | 855 | 30.0 | 35.0 |
| B1 | S1_key_leak | 1.0000 | 47 | 25.0 | 25.0 |
| B1 | S6_drift | 1.0000 | 56 | 27.0 | 27.0 |
| B2 | S2_token_leak | 1.0000 | 201 | 28.0 | 29.0 |
| B2 | S3_replay | 1.0000 | 63 | 33.0 | 33.0 |
| B3 | S2_token_leak | 0.5000 | 23 | 24.0 | 26.0 |
| B3 | S3_replay | 0.5000 | 38 | 31.0 | 32.0 |
| B4 | S2_token_leak | 0.0000 | 0 | 26.0 | 27.0 |
| B4 | S3_replay | 0.5000 | 38 | 34.0 | 35.0 |
| B4 | S4_burst | 0.5000 | 45 | 36.0 | 37.0 |
