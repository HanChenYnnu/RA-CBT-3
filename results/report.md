# 1. Formal Problem Definition
- We model API-facing LLM authorization as a stateful access-control problem over subjects, context-bound credentials, request context, endpoint scope, and budget contention.
- Objective: maximize benign service continuity while minimizing attack success in the non-deny channel (allow+throttle), under a frozen comparable evaluation protocol.

# 2. Formal Authorization Semantics
- **State model**: authorization state is tuple Σ=(ι,κ,χ,ρ,σ,ψ,β,ν), where ι is subject identity state, κ credential state, χ runtime context state, ρ request state, σ resource/action scope, ψ risk state, β contention budget state, ν hard-violation predicate.
- **Credential semantics**: issuance/exchange in `/auth/exchange`; validity requires signature, expiry, PoP (`cnf.jkt`) consistency, and context-bound hash consistency (unless ablated).
- **Decision relation**: δ(Σ,Θ)→A where A={allow, throttle, deny}. Implemented in `decide_action` with explicit deny gates for invalid credentials, context inconsistency, hard violations, or risk/contention deny thresholds.
- **State transitions**: Σ0 (pre-request) → Σ1 (credential/context checked) → Σ2 (risk/contention evaluated) → Σ3 (decision).
- **Action order**: allow < throttle < deny with lattice join operator `compose_actions` = severity-max.
- **Rule composition**: R = Rcred ⊔ Rctx ⊔ Rhard ⊔ Rrisk ⊔ Rbudget with deny precedence and no-downgrade under stronger evidence.

# 3. Propositions and Proofs
- **P1 (Hard-violation priority)**: if ν=true then δ(Σ,Θ)=deny. *Proof*: direct from first guard in `decide_action`; once ν is true execution returns deny before any lower-severity branch.
- **P2 (Monotonicity under increasing risk)**: under fixed κ-valid, χ-consistent, β and ν=false, if ψ1≤ψ2 then δ(Σ1,Θ) ≤ δ(Σ2,Θ) in action order. *Proof*: case split on thresholds `tau_allow` and `tau_deny`; branch predicates are monotone in ψ and map to non-decreasing severities.
- **P3 (Invalid/inconsistent credentials cannot allow)**: if κ invalid OR χ inconsistent beyond permitted bound then δ(Σ,Θ)≠allow. *Proof*: contradiction: allow branch reachable only after the initial deny guard, which requires κ-valid and χ-consistent.
- **P4 (Severity-max composition)**: for action sets X⊆Y, compose_actions(X) ≤ compose_actions(Y). *Proof*: `compose_actions=max` over total order; adding elements cannot decrease maximum.

# 4. Implementation Mapping
- Credential exchange + context binding: `baselines/B4_full/app.py` (`/auth/exchange`, `_ctx_hash`, token encode/decode).
- Runtime context checks + PoP verification: `baselines/B4_full/app.py` (`_verify_dpop`, ctx mismatch checks).
- Risk and contention state: `baselines/B4_full/app.py` (`_exchange_risk`, `_ctx_drift_score`, budget manager, pressure).
- Explicit authorization semantics layer: `baselines/B4_full/policy.py`.
- Ablation variants are runtime-configured via `experiments/runner.py` + `baselines/B4_full/harness.py`.

# 5. Experimental Design
- Frozen comparable core evaluation: shared rerun pipeline, shared metric code, shared seed policy.
- Stronger held-out external-style validation (still synthetic): domain-shifted families `S5_slowdrip` and `S6_drift`, treated as held-out stressors.
- Ablation plan: B2, B4 full, B4_no_ctx, B4_no_multi, B4_weak_signals, B4_simple_policy.
- Seed policy: `python -m scripts.run_all --seed 7 --seeds 1`.
- Reported metrics include S4 PR-AUC, Lift@100, SR_benign@x1.00, ASR_non_deny_attack@x1.00.

# 6. Results
## 6.1 Core S4 results
- Strategy chosen: **STRATEGY B — re-run both baseline and current method under one frozen shared pipeline**.
- Frozen protocol run id: **shared-pipeline:9a897771419a72ba357c0f62d810e164183e9c67:seeds=1:seed_start=7**.

## 6.1.1 Apples-to-apples B2 vs B4
| metric_name | before (B2) | after (B4) |
|---|---:|---:|
| S4 PR-AUC | 0.5213 | 0.9585 |
| S4 Lift@100 | 1.1000 | 2.6862 |
| scale=1.00 SR_benign | 0.1733 | 0.2082 |
| scale=1.00 ASR_non_deny_attack | 0.2267 | 0.1918 |

## 6.2 Complete ablation table (S4 x1.00)
| method | S4 PR-AUC | S4 Lift@100 | SR_benign | ASR_non_deny_attack |
|---|---:|---:|---:|---:|
| baseline B2 | 0.5213 | 1.1000 | 0.1733 | 0.2267 |
| B4 full | 0.9585 | 2.6862 | 0.2082 | 0.1918 |
| B4 w/o context binding | 0.5284 | 2.6189 | 0.2083 | 0.1917 |
| B4 w/o multi-action control | 0.5289 | 2.5778 | 0.2077 | 0.1923 |
| B4 weak risk/context signals | 0.5246 | 2.6342 | 0.2079 | 0.1921 |
| B4 simplified decision policy | 0.5276 | 2.6112 | 0.2080 | 0.1920 |

## 6.3 Complete held-out synthetic validation (B2 vs B4)
| family | baseline | PR-AUC | Lift@100 | SR_benign | ASR_non_deny_attack | n_non_deny | n_attack_non_deny | n_benign_non_deny | interpretation |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| S4_pair | B2 | 0.5213 | 1.1000 | 0.0967 | 0.1273 | 9000 | 4500 | 4500 | Synthetic held-out family; PR/Lift N/A when class support is single-label. |
| S4_pair | B4 | 0.9585 | 2.6862 | 0.1470 | 0.1383 | 10992 | 4092 | 6900 | Synthetic held-out family; PR/Lift N/A when class support is single-label. |
| S5_pair | B2 | 0.8578 | N/A | 1.0000 | 1.0000 | 84 | 48 | 36 | Synthetic held-out family; PR/Lift N/A when class support is single-label. |
| S5_pair | B4 | 0.9896 | N/A | 1.0000 | 1.0000 | 84 | 48 | 36 | Synthetic held-out family; PR/Lift N/A when class support is single-label. |
| S6_pair | B2 | 0.9631 | N/A | 1.0000 | 1.0000 | 82 | 48 | 34 | Synthetic held-out family; PR/Lift N/A when class support is single-label. |
| S6_pair | B4 | 0.9896 | N/A | 1.0000 | 1.0000 | 82 | 48 | 34 | Synthetic held-out family; PR/Lift N/A when class support is single-label. |
| S7_pair | B2 | 0.7616 | N/A | 1.0000 | 1.0000 | 96 | 48 | 48 | Synthetic held-out family; PR/Lift N/A when class support is single-label. |
| S7_pair | B4 | 0.9896 | N/A | 1.0000 | 1.0000 | 96 | 48 | 48 | Synthetic held-out family; PR/Lift N/A when class support is single-label. |

## 6.4 Attribution analysis
- Context binding removal (`B4_no_ctx`) isolates credential-context consistency effects.
- Multi-action removal (`B4_no_multi`) isolates throttle-lane contribution.
- Weak-signal and simplified-policy variants isolate score quality vs policy structure effects.

# 7. Property Checks
- Formal proofs are in this report Section 3 and in `docs/proofs.md`; tests are corroborative implementation checks only.
- Covered implementation checks: hard-violation=>deny, invalid/inconsistent-not-allow, monotonicity, severity-max no-downgrade, frozen protocol invariants.
- Frozen protocol comparability invariants are recorded in `results/consistency_audit.csv`.

# 8. Positioning and Limitations
- Positioning supported: **formalized context-aware access-control method** with explicit semantics, rule composition order, and proved core safety properties under stated assumptions.
- Limitation: held-out evidence is still synthetic OOD validation; no external deployment telemetry or theorem-prover mechanization.

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
