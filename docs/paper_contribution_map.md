# Paper Contribution-to-Evidence Map

| Contribution claim | Repository artifact(s) | Evidence type | Paper location |
|---|---|---|---|
| Formal context-aware access-control method (CBRCA) for API-facing LLM services | `docs/method_overview.md`, `README.md` | Method specification + positioning narrative | Sec. 1, Sec. 3, Sec. 4 |
| Explicit rule-system authorization semantics | `docs/formal_semantics.md` | Formal definitions (state, judgments, rules, composition) | Sec. 4 |
| Proved core safety properties under stated model | `docs/proofs.md` | Formal proof sketches (B1–B6) | Sec. 5 |
| Implementation-grounded realization of the formal method | `baselines/B4_full/policy.py`, `baselines/B4_full/app.py` | Code-level realization mapping | Sec. 6 |
| Frozen comparable core evaluation (B2 vs B4) | `scripts/run_all.py`, `results/report.md`, `results/report.csv`, `results/apples_to_apples_runs.csv` | Reproducible empirical comparison | Sec. 7, Sec. 8 |
| S4 core performance improvement evidence | `results/report.md`, `results/report.csv` | Empirical metrics table (PR-AUC, Lift@100, SR_benign, ASR_non_deny_attack) | Sec. 8 |
| S4/S8 complete ablation and attribution | `results/ablation.csv`, `results/report.md` | Component attribution matrix | Sec. 9.1 |
| Held-out robustness under synthetic/OOD families | `results/external_validation.csv`, `results/report.md` | Held-out family outcomes (S5/S6/S7/S8) | Sec. 9.2 |
| Hard-slice S8 failure-revealing behavior and repair support | `results/s8_analysis.csv`, `results/report.md` | Failure analysis + post-repair outcome evidence | Sec. 9.3 |
| Multi-seed robustness with shared seeds | `results/multiseed_runs.csv`, `results/report.md` | Across-seed consistency summaries | Sec. 8.3 |
| Proof/test boundary is explicit | `docs/proofs.md`, `tests/test_formal_policy.py`, `results/report.md` | Methodological clarity (formal vs conformance) | Sec. 5, Sec. 6 |

## Positioning lock (for manuscript consistency)

CBRCA should be described as an implementation-grounded formal method with explicit semantics, proved core properties under the stated model, and frozen comparable evaluation. It must not be described as a fully general access-control theory or production-deployment validation.
