# 1. Problem Setting

This report summarizes paper-support evidence for **Context-Bound Credential and Rule-Composed Authorization (CBRCA)** in API-facing LLM access control. The target problem is security-availability control under mixed benign/adversarial load when static credentials and binary gates are insufficient.

# 2. Method Overview

CBRCA combines: (i) context-bound credentials, (ii) rule-composed `allow/throttle/deny` authorization, and (iii) frozen comparable evaluation against B2.

- Context binding uses PoP and runtime context checks.
- Authorization composition follows `allow < throttle < deny` with severity-max join.
- Replay evidence is explicitly accumulated across requests.

# 3. Formal Semantics

The formal model specifies state, judgments, inference rules, and transition/composition semantics for CBRCA (see `docs/formal_semantics.md`). It explicitly models credential validity, context classes, risk/contention classes, hard violations, and replay accumulation.

# 4. Formal Properties and Proofs

Core proved properties (see `docs/proofs.md`):

- hard-violation deny,
- risk monotonicity,
- invalid-credential/hard-context exclusion of allow,
- composition non-downgrade,
- determinism,
- replay evidence non-neutralization.

These are formal semantic claims, distinct from implementation tests.

# 5. Implementation Mapping

- Policy/action composition realization: `baselines/B4_full/policy.py`
- Credential lifecycle + runtime signals: `baselines/B4_full/app.py`
- Controlled ablation wiring: `experiments/runner.py`
- Canonical regeneration entrypoint: `python -m scripts.run_all --seed 7 --seeds 5`

# 6. Experimental Design

- Frozen comparable protocol with shared metric/slice/aggregation stack.
- Core slice: `S4_pair` (mixed-load discriminative slice).
- Attribution slices: S4 + S8 with complete ablation panel.
- Held-out synthetic/OOD slices: S5/S6/S7/S8.
- Multi-seed robustness: shared seeds `7, 11, 19, 23, 31` for B2 and B4.

# 7. Core S4 Results

| metric_name | B2 | B4 |
|---|---:|---:|
| S4 PR-AUC | 0.5205 | 0.9569 |
| S4 Lift@100 | 1.3000 | 2.6806 |
| scale=1.00 SR_benign | 0.1733 | 0.2081 |
| scale=1.00 ASR_non_deny_attack | 0.2267 | 0.1919 |

Interpretation: under frozen comparability, B4 improves ranking quality (PR-AUC/Lift@100), increases benign service at the chosen operating point, and reduces non-deny attack success.

# 8. S4/S8 Ablation and Attribution

| method | S4 PR-AUC | S4 Lift@100 | S4 SR_benign | S4 ASR_non_deny_attack | S8 PR-AUC | S8 Lift@100 | S8 SR_benign | S8 ASR_non_deny_attack |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline B2 | 0.5205 | 1.3000 | 0.1733 | 0.2267 | 0.8573 | 1.8600 | 1.0000 | 1.0000 |
| B4 full | 0.9569 | 2.6806 | 0.2081 | 0.1919 | 0.9900 | 2.7000 | 1.0000 | 0.2273 |
| B4 w/o context binding | 0.5285 | 2.6405 | 0.2081 | 0.1919 | 0.6988 | 2.6460 | 1.0000 | 0.2273 |
| B4 w/o multi-action control | 0.5291 | 2.6347 | 0.2079 | 0.1921 | 0.6758 | 2.1060 | 1.0000 | 0.2273 |
| B4 weak risk/context signals | 0.5273 | 2.6362 | 0.2079 | 0.1921 | 0.7953 | 2.7100 | 1.0000 | 0.2318 |
| B4 simplified decision policy | 0.5274 | 2.6376 | 0.2080 | 0.1920 | 0.6707 | 2.4840 | 1.0000 | 0.2273 |

Attribution summary: S4 and especially S8 behavior indicates that context binding and explicit multi-action/replay-aware composition are both necessary to recover hard-slice discrimination.

# 9. Held-Out Validation

Held-out synthetic/OOD families (`S5_pair`, `S6_pair`, `S7_pair`, `S8_pair`) are reported separately from S4. S8 is the principal hard held-out slice and remains failure-revealing; B4 materially reduces S8 non-deny attack success relative to B2.

# 10. Multi-Seed Robustness

Shared-seed summary (B2 vs B4):

- `S4_pair` PR-AUC: `0.5169 ± 0.0025` vs `0.9560 ± 0.0044`
- `S8_pair` PR-AUC: `0.6913 ± 0.0098` vs `0.9900 ± 0.0000`
- `S8_pair` ASR_non_deny_attack: `0.5455 ± 0.0000` vs `0.2273 ± 0.0000`

Per-seed values are in `results/multiseed_runs.csv`.

# 11. Limitations

- Evidence is from deterministic synthetic/OOD scenarios, not production deployment.
- Formal proofs are over the explicit CBRCA semantic model only.
- Some held-out families (S5/S6/S7) are currently saturated and weakly discriminative.

# 12. Conclusion

CBRCA provides an implementation-grounded formal method for context-aware authorization in API-facing LLM services, with explicit semantics, proved core properties, and frozen comparable evidence including S4/S8 attribution and held-out robustness.

**Positioning used throughout this repository:** CBRCA is an implementation-grounded formal method for context-aware authorization in API-facing LLM services, with explicit semantics and proved core properties under its stated model, plus frozen comparable evaluation. It is **not** claimed as a fully general access-control theory, real-world deployment validation, or proof outside the explicit semantic model.
