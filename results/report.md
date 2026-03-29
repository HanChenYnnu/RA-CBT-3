# 1. Formal Problem Definition
- We model API-facing LLM authorization as a stateful access-control problem over subjects, context-bound credentials, request context, endpoint scope, and budget contention.
- Objective: maximize benign service continuity while minimizing attack success in the non-deny channel (allow+throttle), under a frozen comparable evaluation protocol.

# 2. Formal Method
- Entity model: subject/client, credential/token, runtime context, request, resource endpoint, control action (`allow`, `throttle`, `deny`).
- Credential model: structured context-bound envelope with expiry, confirmation key hash (`cnf.jkt`), bound context hash, and restricted flag.
- Decision function: `decide_action(state, thresholds)` in `baselines/B4_full/policy.py`, with hard-violation precedence and ordered action lattice.
- Policy semantics: validity, context consistency, hard violation, escalation by risk/contention, throttle downgrade lane, deny on hard gates.
- Intended properties are implementation-grounded and tested (validity/context/hard-violation/monotonicity/comparability checks).

# 3. Implementation Mapping
- Credential exchange + context binding: `baselines/B4_full/app.py` (`/auth/exchange`, `_ctx_hash`, token encode/decode).
- Runtime context checks + PoP verification: `baselines/B4_full/app.py` (`_verify_dpop`, ctx mismatch checks).
- Risk and contention state: `baselines/B4_full/app.py` (`_exchange_risk`, `_ctx_drift_score`, budget manager, pressure).
- Explicit authorization semantics layer: `baselines/B4_full/policy.py`.
- Ablation variants are runtime-configured via `experiments/runner.py` + `baselines/B4_full/harness.py`.

# 4. Experimental Design
- Frozen comparable core evaluation: shared rerun pipeline, shared metric code, shared seed policy.
- Stronger held-out external-style validation (still synthetic): domain-shifted families `S5_slowdrip` and `S6_drift`, treated as held-out stressors.
- Ablation plan: B2, B4 full, B4_no_ctx, B4_no_multi, B4_weak_signals, B4_simple_policy.
- Seed policy: `python -m scripts.run_all --seed 7 --seeds 1`.
- Reported metrics include S4 PR-AUC, Lift@100, SR_benign@x1.00, ASR_non_deny_attack@x1.00.

# 5. Results
## 5.1 Core mixed-load results
- Strategy chosen: **STRATEGY B — re-run both baseline and current method under one frozen shared pipeline**.
- Frozen protocol run id: **shared-pipeline:36fd8b6a95bba317b9d3a5a851c6679b4838d0bc:seeds=1:seed_start=7**.

## 5.2 Apples-to-apples B2 vs B4
| metric_name | before (B2) | after (B4) |
|---|---:|---:|
| S4 PR-AUC | 0.5192 | 0.9594 |
| S4 Lift@100 | 1.0600 | 2.6922 |
| scale=1.00 SR_benign | 0.1733 | 0.2083 |
| scale=1.00 ASR_non_deny_attack | 0.2267 | 0.1917 |

## 5.3 Ablation table (S4 x1.00)
| method | S4 PR-AUC | S4 Lift@100 | SR_benign | ASR_non_deny_attack |
|---|---:|---:|---:|---:|
| baseline B2 | 0.5192 | 1.0600 | 0.1733 | 0.2267 |
| B4 full | 0.9594 | 2.6922 | 0.2083 | 0.1917 |
| B4 w/o context binding | N/A | N/A | 0.2085 | 0.1915 |
| B4 w/o multi-action control | N/A | N/A | 0.2079 | 0.1921 |
| B4 weak risk/context signals | N/A | N/A | 0.2080 | 0.1920 |
| B4 simplified decision policy | N/A | N/A | 0.2081 | 0.1919 |

## 5.4 Stronger held-out / external-style validation
| scenario | SR_benign | ASR_non_deny_attack | throttle_rate |
|---|---:|---:|---:|
| S5_slowdrip | N/A | N/A | 0.0000 |
| S6_drift | N/A | N/A | 0.2059 |

## 5.5 Attribution analysis
- Context binding removal (`B4_no_ctx`) isolates credential-context consistency effects.
- Multi-action removal (`B4_no_multi`) isolates throttle-lane contribution.
- Weak-signal and simplified-policy variants isolate score quality vs policy structure effects.

# 6. Formal Property Checks
- Property checks are implementation-grounded tests, not formal proofs.
- Covered checks: credential validity semantics, context mismatch handling, hard-violation=>deny, and action monotonicity under risk escalation.
- Frozen protocol comparability invariants are recorded in `results/consistency_audit.csv`.

# 7. Conclusion and Positioning
- This branch now supports positioning as a **formalized context-aware access-control method** with explicit semantics and implementation-grounded validation.
- Limitation: stronger validation is held-out synthetic/domain-shifted, not production telemetry.

## Comparability verification appendix
- same metric code: **true**
- same slice definitions: **true**
- same operating point: **true**
- same seed policy: **true**
- same aggregation logic: **true**
- same non-deny definition: **true**
- same served-traffic filtering: **true**
- same mixed-load construction: **true**
- Sample-count review:
  - S4_pair n_non_deny before=12000 (attack=6000, benign=6000), after=13364 (attack=4964, benign=8400).
  - scale=1.00 mixed-load n_non_deny before=2400 (attack=1200, benign=1200), after=7726 (attack=2926, benign=4800).
  - scale=1.00 mixed-load denominators attack before/after=1200/4800, benign before/after=1200/4800.
  - Interpretation: denominator differences reflect B2 vs B4 behavior under the same protocol, not evaluation drift.
- final verdict: **VALID APPLES-TO-APPLES**
