# Section Drafting Notes (CBRCA)

## 1. Introduction
- **Emphasize:** Concrete API-facing LLM authorization problem; mixed-load security/availability objective.
- **De-emphasize:** Broad theoretical framing.
- **Do not overclaim:** Universal solution or production validation.
- **Cite evidence:** `README.md`, `docs/method_overview.md`, `results/report.md`.

## 2. Related Work
- **Emphasize:** Practical contrast: explicit semantics + implementation mapping + frozen comparability.
- **De-emphasize:** Exhaustive survey breadth.
- **Do not overclaim:** Prior work invalidation.
- **Cite evidence:** `docs/formal_semantics.md`, `docs/proofs.md`.

## 3. Problem Definition
- **Emphasize:** System state, threat assumptions, target metrics and operating point.
- **De-emphasize:** Pipeline mechanics.
- **Do not overclaim:** Threat coverage beyond modeled scenarios.
- **Cite evidence:** `docs/formal_semantics.md`, `results/report.md`.

## 4. Formal Method
- **Emphasize:** Judgment forms, rule families, composition algebra, replay accumulation.
- **De-emphasize:** Implementation details not needed for formal understanding.
- **Do not overclaim:** Equivalence to all policy languages.
- **Cite evidence:** `docs/formal_semantics.md`.

## 5. Formal Properties
- **Emphasize:** Exact theorem statements and model-bounded scope.
- **De-emphasize:** Empirical results in proof section.
- **Do not overclaim:** Proof of external performance.
- **Cite evidence:** `docs/proofs.md`.

## 6. System Realization / Implementation Mapping
- **Emphasize:** Mapping from semantic constructs to modules/functions.
- **De-emphasize:** Non-essential engineering minutiae.
- **Do not overclaim:** Formal verification of the full codebase.
- **Cite evidence:** `baselines/B4_full/policy.py`, `baselines/B4_full/app.py`, `tests/test_formal_policy.py`.

## 7. Experimental Setup
- **Emphasize:** Frozen protocol, shared seeds, compared methods, slice roles.
- **De-emphasize:** Exploratory tuning narrative.
- **Do not overclaim:** Search-based optimization.
- **Cite evidence:** `scripts/run_all.py`, `results/report.csv`, `results/apples_to_apples_runs.csv`.

## 8. Results
- **Emphasize:** S4 core metrics and operating-point tradeoff under frozen comparison.
- **De-emphasize:** Secondary saturated slices in core result discussion.
- **Do not overclaim:** Broad generalization.
- **Cite evidence:** `results/report.md`, `results/report.csv`.

## 9. Ablation and Held-Out Validation
- **Emphasize:** S4/S8 attribution and hard-slice held-out behavior (S8).
- **De-emphasize:** Saturated-slice interpretation depth (S5/S6/S7).
- **Do not overclaim:** Real-world robustness.
- **Cite evidence:** `results/ablation.csv`, `results/external_validation.csv`, `results/s8_analysis.csv`, `results/report.md`.

## 10. Discussion / Limitations
- **Emphasize:** Model scope boundaries, synthetic/OOD limitation, proof/test boundary.
- **De-emphasize:** Forward-looking claims not yet evidenced.
- **Do not overclaim:** Deployment readiness proof.
- **Cite evidence:** `results/report.md`, `docs/proofs.md`.

## 11. Conclusion
- **Emphasize:** Exactly what is delivered: formal method, explicit semantics, core proofs, frozen comparative evidence.
- **De-emphasize:** Speculative future impact.
- **Do not overclaim:** Universality or complete external validity.
- **Cite evidence:** `docs/paper_contribution_map.md`, `results/report.md`.

## Global consistency lock

Use this identical positioning statement in manuscript-facing materials:

> CBRCA is an implementation-grounded formal method for context-aware authorization in API-facing LLM services, with explicit semantics and proved core properties under its stated model, plus frozen comparable evaluation. It is not claimed as a fully general access-control theory, real-world deployment validation, or proof outside the explicit semantic model.
