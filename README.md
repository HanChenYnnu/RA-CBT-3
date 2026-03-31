# RA-CBT-3

RA-CBT-3 is a publication-structured research artifact for **Context-Bound Credential and Rule-Composed Authorization (CBRCA)**: a formal context-aware access-control method for API-facing LLM services, with explicit authorization semantics, proved core safety properties, and implementation-grounded frozen evaluation.

## Problem statement

API-facing LLM services often rely on static or weakly scoped credentials and binary allow/deny gates. This creates two coupled risks: (i) replay/misuse across context shifts (device/network/time), and (ii) avoidable benign service loss under mixed benign/adversarial traffic.

## Method summary: CBRCA

CBRCA combines three components:

1. **Context-bound credentialing** (exchange-time and request-time context binding).
2. **Rule-composed multi-action authorization** with `allow < throttle < deny` and severity-max composition.
3. **Deterministic frozen evaluation protocol** for comparable B2 vs B4 analysis with S4/S8 attribution and held-out stress testing.

See method details in `docs/method_overview.md`.

## Formal contribution summary

CBRCA is formalized as explicit judgment and transition semantics with an action-composition algebra and replay-evidence accumulation rules. The repository includes core semantic proofs (hard-violation deny, monotonicity, invalid-credential exclusion, composition non-downgrade, determinism, replay non-neutralization) under the stated model.

- Formal semantics: `docs/formal_semantics.md`
- Proofs: `docs/proofs.md`

## Experiment summary

Under a frozen comparable protocol, the repository reports:

- Core mixed-load S4 comparison (B2 vs B4),
- Complete S4/S8 ablation and attribution,
- Held-out synthetic/OOD families (S5/S6/S7/S8),
- Multi-seed robustness with shared seeds.

Paper-facing report: `results/report.md`.

## Paper positioning (scope and non-scope)

**Positioning used throughout this repository:** CBRCA is an implementation-grounded formal method for context-aware authorization in API-facing LLM services, with explicit semantics and proved core properties under its stated model, plus frozen comparable evaluation. It is **not** claimed as a fully general access-control theory, real-world deployment validation, or proof outside the explicit semantic model.

## Reproduction entrypoint

Canonical deterministic entrypoint:

```bash
python -m scripts.run_all --seed 7 --seeds 5
```

Optional publish mode:

```bash
python -m scripts.run_all --seed 7 --seeds 5 --publish-results true
```

## Primary paper-support artifacts

- `docs/paper_outline.md`
- `docs/paper_contribution_map.md`
- `docs/paper_section_notes.md`
- `results/report.md`
- `results/report.csv`

## Developer checks

```bash
make setup
make lint
make test
make smoke
make all
```
