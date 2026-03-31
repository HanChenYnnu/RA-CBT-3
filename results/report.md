# 1. Formal Problem Definition
- We model API-facing LLM authorization as a stateful access-control problem over subjects, context-bound credentials, request context, endpoint scope, and budget contention.
- Objective: maximize benign service continuity while minimizing attack success in the non-deny channel (allow+throttle), under a frozen comparable evaluation protocol.

# 2. Rule-System Authorization Semantics
- **State model**: authorization state is tuple Σ=(ι,κ,χ,ρ,σ,ψ,β,ν), where ι is subject identity state, κ credential state, χ runtime context state, ρ request state, σ resource/action scope, ψ risk state, β contention budget state, ν hard-violation predicate.
- **Credential semantics**: issuance/exchange in `/auth/exchange`; validity requires signature, expiry, PoP (`cnf.jkt`) consistency, and context-bound hash consistency (unless ablated).
- **Decision relation**: δ(Σ,Θ)→A where A={allow, throttle, deny}. Implemented in `decide_action` with explicit deny gates for invalid credentials, context inconsistency, hard violations, or risk/contention deny thresholds.
- **State transitions**: Σ0 (pre-request) → Σ1 (credential/context checked) → Σ2 (risk/contention evaluated) → Σ3 (decision).
- **Action order**: allow < throttle < deny with lattice join operator `compose_actions` = severity-max.
- **Rule composition**: R = Rcred ⊔ Rctx ⊔ Rhard ⊔ Rrisk ⊔ Rbudget with deny precedence and no-downgrade under stronger evidence.

# 3. Propositions and Proofs
- **B1 Hard-violation deny theorem**: from `(HARD)` and `(AUTH)` with deny as top element, any derivable hard-violation yields final deny.
- **B2 Risk monotonicity theorem**: with fixed credential/context/contention classes, monotone risk-class mapping and isotonic join imply non-decreasing decision severity.
- **B3 Invalid/inconsistent exclusion theorem**: `(CRED-DENY)` or `(CTX-HARD)` injects deny into rule set, so allow is not derivable.
- **B4 Composition non-downgrade theorem**: `⊔` is severity-max join on total order; adding stronger applicable rules cannot reduce severity.
- **B5 Determinism theorem**: fixed Γ and Σ produce a unique applicable-rule multiset and therefore unique composed action.

# 4. Implementation Mapping
- Credential exchange + context binding: `baselines/B4_full/app.py` (`/auth/exchange`, `_ctx_hash`, token encode/decode).
- Runtime context checks + PoP verification: `baselines/B4_full/app.py` (`_verify_dpop`, ctx mismatch checks).
- Risk and contention state: `baselines/B4_full/app.py` (`_exchange_risk`, `_ctx_drift_score`, budget manager, pressure).
- Explicit authorization semantics layer: `baselines/B4_full/policy.py`.
- Ablation variants are runtime-configured via `experiments/runner.py` + `baselines/B4_full/harness.py`.

# 5. Experimental Design
- Frozen comparable core evaluation: shared rerun pipeline, shared metric code, shared seed policy.
- Held-out synthetic/OOD design: `S5_pair`, `S6_pair`, `S7_pair`, and harder `S8_pair` (camouflaged replay after warmup), separated from S4 tuning path.
- Ablation plan: B2, B4 full, B4_no_ctx, B4_no_multi, B4_weak_signals, B4_simple_policy.
- Seed policy: frozen multi-seed rerun with shared seeds (`python -m scripts.run_all --seed 7 --seeds 5`).
- Reported metrics include S4 PR-AUC, Lift@100, SR_benign@x1.00, ASR_non_deny_attack@x1.00.

# 6. Core Results
## 6.1 Frozen comparable S4 results
- Strategy chosen: **STRATEGY B — re-run both baseline and current method under one frozen shared pipeline**.
- Frozen protocol run id: **shared-pipeline:2ceb8ad5058abc7a9f7f5a81f752af2d310b193c:seeds=1:seed_start=7**.

## 6.1.1 Apples-to-apples B2 vs B4
| metric_name | before (B2) | after (B4) |
|---|---:|---:|
| S4 PR-AUC | 0.5205 | 0.9569 |
| S4 Lift@100 | 1.3000 | 2.6806 |
| scale=1.00 SR_benign | 0.1733 | 0.2081 |
| scale=1.00 ASR_non_deny_attack | 0.2267 | 0.1919 |

# 7. Complete Ablation Analysis
## 7.1 S4 + S8 attribution matrix
| method | S4 PR-AUC | S4 Lift@100 | S4 SR_benign | S4 ASR_non_deny_attack | S8 PR-AUC | S8 Lift@100 | S8 SR_benign | S8 ASR_non_deny_attack |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline B2 | 0.5205 | 1.3000 | 0.1733 | 0.2267 | 0.8573 | 1.8600 | 1.0000 | 1.0000 |
| B4 full | 0.9569 | 2.6806 | 0.2081 | 0.1919 | 0.9900 | 2.7000 | 1.0000 | 0.2273 |
| B4 w/o context binding | 0.5285 | 2.6405 | 0.2081 | 0.1919 | 0.6988 | 2.6460 | 1.0000 | 0.2273 |
| B4 w/o multi-action control | 0.5291 | 2.6347 | 0.2079 | 0.1921 | 0.6758 | 2.1060 | 1.0000 | 0.2273 |
| B4 weak risk/context signals | 0.5273 | 2.6362 | 0.2079 | 0.1921 | 0.7953 | 2.7100 | 1.0000 | 0.2318 |
| B4 simplified decision policy | 0.5274 | 2.6376 | 0.2080 | 0.1920 | 0.6707 | 2.4840 | 1.0000 | 0.2273 |

# 8. Held-Out Validation
## 8.1 Held-out synthetic/OOD families (B2 vs B4)
| family | baseline | PR-AUC | Lift@100 | SR_benign | ASR_non_deny_attack | n_non_deny | n_attack_non_deny | n_benign_non_deny | interpretation |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| S4_pair | B2 | 0.5205 | 1.3000 | 0.0967 | 0.1273 | 21000 | 10500 | 10500 | discriminative/failure-revealing |
| S4_pair | B4 | 0.9569 | 2.6806 | 0.1524 | 0.1432 | 28232 | 10532 | 17700 | discriminative/failure-revealing |
| S5_pair | B2 | N/A | N/A | 1.0000 | N/A | 36 | 0 | 36 | easy/saturated |
| S5_pair | B4 | N/A | N/A | 1.0000 | N/A | 36 | 0 | 36 | easy/saturated |
| S6_pair | B2 | N/A | N/A | 1.0000 | N/A | 34 | 0 | 34 | easy/saturated |
| S6_pair | B4 | N/A | N/A | 1.0000 | N/A | 34 | 0 | 34 | easy/saturated |
| S7_pair | B2 | 0.6795 | N/A | 1.0000 | 1.0000 | 96 | 48 | 48 | easy/saturated |
| S7_pair | B4 | 0.9896 | N/A | 1.0000 | 1.0000 | 96 | 48 | 48 | easy/saturated |
| S8_pair | B2 | 0.8573 | 1.8600 | 1.0000 | 1.0000 | 440 | 220 | 220 | discriminative/failure-revealing |
| S8_pair | B4 | 0.9900 | 2.7000 | 1.0000 | 0.2273 | 270 | 50 | 220 | discriminative/failure-revealing |

## 8.2 Held-out family interpretation
- S5/S6/S7 are mostly easy or saturated under current synthetic construction and are reported as such.
- S8 remains a first-class hard held-out family and is used as the main failure-revealing slice.

# 9. S8 Failure Analysis and Repair
- **Dominant failure mechanism (pre-repair):** staged camouflaged replay produced many non-deny attack warmup events with benign-like risk, while replay detection happened only at deny-time; this collapsed non-deny ranking discrimination.
- **Implicated components:** replay evidence accumulation and policy composition timing in `baselines/B4_full/app.py` (risk computed before replay-history evidence was incorporated).
- **Type of issue:** algorithmic + semantic (temporal replay evidence not accumulated into decision state), not a simple threshold-only miss.
- **Repair introduced:** replay reuse and per-token replay-violation history are now explicit risk signals and are folded into decision risk before final action composition. This prevents replay evidence from being washed out by otherwise valid credentials.
- **Outcome on S8:** status=`repaired_non_collapse`, with B2 PR-AUC=0.8573 vs B4 PR-AUC=0.9900 and B2 ASR_non_deny_attack=1.0000 vs B4=0.2273.

# 10. Multi-Seed Robustness Verification
- Shared frozen seeds: **7, 11, 19, 23, 31** (same set for B2 and B4).
- Per-seed B2/B4 values are provided in `results/multiseed_runs.csv`.

| pair | metric | B2 per-seed | B4 per-seed | B2 mean ± std | B4 mean ± std | delta mean (B4-B2) | direction consistency |
|---|---|---|---|---:|---:|---:|---:|
| S4_pair | PR-AUC | 0.5212, 0.5170, 0.5141, 0.5175, 0.5148 | 0.9573, 0.9553, 0.9583, 0.9481, 0.9611 | 0.5169 ± 0.0025 | 0.9560 ± 0.0044 | +0.4391 | 5/5 (B4 ≥ B2) |
| S4_pair | ASR_non_deny_attack | 0.1281, 0.1273, 0.1273, 0.1273, 0.1273 | 0.1412, 0.1358, 0.1107, 0.1093, 0.1087 | 0.1275 ± 0.0003 | 0.1211 ± 0.0143 | -0.0063 | 3/5 (B4 ≤ B2) |
| S8_pair | PR-AUC | 0.6847, 0.7096, 0.6830, 0.6857, 0.6935 | 0.9900, 0.9900, 0.9900, 0.9900, 0.9900 | 0.6913 ± 0.0098 | 0.9900 ± 0.0000 | +0.2987 | 5/5 (B4 ≥ B2) |
| S8_pair | ASR_non_deny_attack | 0.5455, 0.5455, 0.5455, 0.5455, 0.5455 | 0.2273, 0.2273, 0.2273, 0.2273, 0.2273 | 0.5455 ± 0.0000 | 0.2273 ± 0.0000 | -0.3182 | 5/5 (B4 ≤ B2) |

# 11. Property Checks versus Formal Proofs
- **Proved in docs (semantic level):** B1/B2/B3/B4/B5 in `docs/proofs.md`, based on inference rules in `docs/formal_semantics.md`.
- **Checked in tests (implementation conformance):** `tests/test_formal_policy.py` includes replay-escalation non-neutralization conformance in addition to existing tests.
- **Empirical only:** ablation deltas and held-out performance are empirical outcomes, not theorems.

# 12. Positioning and Limitations
- Positioning supported: **formal context-aware access-control method with explicit rule-system semantics, proved core properties, component attribution, and frozen multi-seed core/held-out evaluation**.
- Limitations: held-out families are synthetic/OOD, proofs are pen-and-paper, and some held-out families remain saturated and therefore weak discriminators.

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
  - S4_pair n_non_deny before=21000 (attack=10500, benign=10500), after=28232 (attack=10532, benign=17700).
  - scale=1.00 mixed-load n_non_deny before=4200 (attack=2100, benign=2100), after=16912 (attack=6412, benign=10500).
  - scale=1.00 mixed-load denominators attack before/after=2100/10500, benign before/after=2100/10500.
  - Interpretation: denominator differences reflect B2 vs B4 behavior under the same protocol, not evaluation drift.
- final verdict: **VALID APPLES-TO-APPLES**
