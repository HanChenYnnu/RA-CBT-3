# RA-CBT-3

RA-CBT-3 is a deterministic artifact for a **formalized context-aware access-control method** for API-mediated LLM services. It combines: (A) context-bound credentials, (B) explicit authorization semantics for multi-action control, and (C) a frozen comparable evaluation protocol with ablations and held-out synthetic stress validation.

## Problem statement

Static long-lived API keys can be replayed or misused across devices, network contexts, and time windows. A binary allow/deny gate also fails to preserve benign service quality under contention. The repository studies whether context binding and graded runtime control can reduce attack-side success while maintaining benign service in mixed-load conditions.

## Formal method contribution (implementation-grounded)

### A) Context-Bound Dynamic API Credential Mechanism
Implemented in baseline **B4** via short-lived exchanged tokens that bind to runtime context and proof-of-possession signals:
- token exchange with `cnf.jkt` and context hash,
- context checks over IP/ASN/country/UA/device fingerprint/time,
- drift and anomaly scoring used at exchange and request time.

### B) Explicit Authorization Semantics and Multi-Action Control
Implemented via `baselines/B4_full/policy.py` and integrated in B4 request handling:
- **allow** for low risk/pressure,
- **throttle** via tighter token precharge under intermediate risk/pressure,
- **deny** under high risk or hard policy violations.

The decision state explicitly includes credential validity, context consistency, hard-policy violations, risk score, and contention pressure.

### C) Unified Comparable Evaluation Protocol for Mixed-Load Scenarios
Implemented through the canonical pipeline entrypoint and frozen-stack reruns:
- same metrics/slices/non-deny definition/aggregation/report logic,
- same baseline-current pair (`B2` vs `B4`),
- same shared seed set,
- explicit mixed-load slice (`S4_pair`) and slice-aware reporting.

This protocol supports defensible interpretation of A and B; it is not a standalone replacement for control logic.

## What the experiments validate

The evaluation tests whether B4 (A+B) outperforms B2 under the frozen protocol (C), with emphasis on:
- **S4 PR-AUC** and **S4 Lift@100** (risk ranking quality under mixed load),
- **scale=1.00 SR_benign** (benign service rate),
- **scale=1.00 ASR_non_deny_attack** (attack success on non-denied traffic).

Ablation baselines are included:
- `B4_no_ctx`, `B4_no_multi`, `B4_weak_signals`, `B4_simple_policy`.

Held-out external-style validation (still synthetic) is reported for:
- `S5_slowdrip`, `S6_drift`.

## Primary research artifacts

- `results/report.md`: publication-oriented narrative (problem → method → experiments → results → conclusion).
- `results/report.csv`: machine-readable per-seed metrics, audit summaries, and narrative-aligned summary rows.
- `results/plots/*.svg`: supporting figures generated from the same frozen run.
- `scripts/run_all.py`: canonical deterministic entrypoint for regeneration.

> PR packaging note: binary plot exports (for example `results/plots/*.png`) are intentionally excluded in this PR-ready branch. Text/vector artifacts (`.md`, `.csv`, `.svg`) are preserved, and figures are reproducible locally via the canonical script. See `results/plots/README.md`.

## Reproducible rerun

From repo root:

```bash
python -m scripts.run_all --seed 7 --seeds 5
```

This regenerates report artifacts under `results/` using the canonical pipeline.

Optional auto-commit mode for generated results:

```bash
python -m scripts.run_all --seed 7 --seeds 5 --publish-results true
```

## Developer checks

```bash
make setup
make lint
make test
make smoke
make all
```
