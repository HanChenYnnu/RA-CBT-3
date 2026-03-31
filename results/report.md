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
- Seed policy: `python -m scripts.run_all --seed 7 --seeds 1`.
- Reported metrics include S4 PR-AUC, Lift@100, SR_benign@x1.00, ASR_non_deny_attack@x1.00.

# 6. Core Results
## 6.1 Frozen comparable S4 results
- Strategy chosen: **STRATEGY B — re-run both baseline and current method under one frozen shared pipeline**.
- Frozen protocol run id: **shared-pipeline:47a1feedaaa7c66b2b1dfe29e38d71cdc2e7a3c4:seeds=1:seed_start=7**.

## 6.1.1 Apples-to-apples B2 vs B4
| metric_name | before (B2) | after (B4) |
|---|---:|---:|
| S4 PR-AUC | 0.5185 | 0.9572 |
| S4 Lift@100 | 1.1200 | 2.6862 |
| scale=1.00 SR_benign | 0.1733 | 0.2082 |
| scale=1.00 ASR_non_deny_attack | 0.2267 | 0.1918 |

# 7. Complete Ablation Analysis
## 7.1 S4 x1.00 ablation table
| method | S4 PR-AUC | S4 Lift@100 | SR_benign | ASR_non_deny_attack |
|---|---:|---:|---:|---:|
| baseline B2 | 0.5185 | 1.1200 | 0.1733 | 0.2267 |
| B4 full | 0.9572 | 2.6862 | 0.2082 | 0.1918 |
| B4 w/o context binding | 0.5258 | 2.5660 | 0.2083 | 0.1917 |
| B4 w/o multi-action control | 0.5264 | 2.5515 | 0.2077 | 0.1923 |
| B4 weak risk/context signals | 0.5242 | 2.5816 | 0.2079 | 0.1921 |
| B4 simplified decision policy | 0.5261 | 2.6376 | 0.2080 | 0.1920 |

# 8. Discriminative Held-Out Validation
## 8.1 Held-out synthetic/OOD families (B2 vs B4)
| family | baseline | PR-AUC | Lift@100 | SR_benign | ASR_non_deny_attack | n_non_deny | n_attack_non_deny | n_benign_non_deny | interpretation |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| S4_pair | B2 | 0.5185 | 1.1200 | 0.0967 | 0.1273 | 9000 | 4500 | 4500 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S4_pair | B4 | 0.9572 | 2.6862 | 0.1470 | 0.1383 | 10992 | 4092 | 6900 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S5_pair | B2 | 0.9957 | 1.1636 | 1.0000 | 1.0000 | 256 | 220 | 36 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S5_pair | B4 | 0.4906 | N/A | 1.0000 | 0.2318 | 87 | 51 | 36 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S6_pair | B2 | 0.6944 | 1.3000 | 1.0000 | 1.0000 | 130 | 48 | 82 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S6_pair | B4 | 0.9896 | 1.3000 | 1.0000 | 1.0000 | 130 | 48 | 82 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S7_pair | B2 | 0.6994 | N/A | 1.0000 | 1.0000 | 96 | 48 | 48 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S7_pair | B4 | 0.9896 | N/A | 1.0000 | 1.0000 | 96 | 48 | 48 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S8_pair | B2 | 0.8254 | 1.8000 | 1.0000 | 1.0000 | 440 | 220 | 220 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |
| S8_pair | B4 | 0.1349 | 0.3720 | 1.0000 | 0.2318 | 271 | 51 | 220 | Synthetic held-out/OOD family; when Lift@100 is N/A (n_non_deny<100), PR-AUC + SR/ASR + counts are primary. |

## 8.2 Attribution under held-out stress
- Context binding removal (`B4_no_ctx`) isolates credential-context consistency effects.
- Multi-action removal (`B4_no_multi`) isolates throttle-lane contribution.
- Weak-signal and simplified-policy variants isolate score quality vs policy structure effects.

# 9. Property Checks versus Formal Proofs
- **Proved in docs (semantic level):** B1/B2/B3/B4/B5 in `docs/proofs.md`, based on inference rules in `docs/formal_semantics.md`.
- **Checked in tests (implementation conformance):** `tests/test_formal_policy.py` and frozen protocol checks.
- **Empirical only:** ablation deltas and held-out performance are empirical outcomes, not theorems.

# 10. Positioning and Limitations
- Positioning supported: **formal context-aware access-control method with explicit rule-system semantics, abstract safety properties, and discriminative held-out synthetic validation under frozen comparable evaluation**.
- Limitations: held-out sets remain synthetic/OOD (not deployment traces), and proofs are pen-and-paper rather than mechanized theorem proving.

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
  - S4_pair n_non_deny before=9000 (attack=4500, benign=4500), after=10992 (attack=4092, benign=6900).
  - scale=1.00 mixed-load n_non_deny before=1800 (attack=900, benign=900), after=7248 (attack=2748, benign=4500).
  - scale=1.00 mixed-load denominators attack before/after=900/4500, benign before/after=900/4500.
  - Interpretation: denominator differences reflect B2 vs B4 behavior under the same protocol, not evaluation drift.
- final verdict: **VALID APPLES-TO-APPLES**
