# Formal Properties and Proof Sketches for CBRCA

These are semantic proofs over `docs/formal_semantics.md` for **Context-Bound Credential and Rule-Composed Authorization (CBRCA)**.

## Proof scope

All claims are within the explicit CBRCA semantic model. They are not claims about arbitrary access-control systems.

## B1. Hard-violation deny

**Statement.** If `Γ ⊢ Σ ⇒ R_hard : deny`, then final authorization is `Γ ⊢ Σ ⇓ deny`.

**Proof sketch.** Final action is severity-max over applicable rule outputs. Since `deny` is top, result is `deny`.

## B2. Monotonicity under risk escalation

**Statement.** With other classes fixed, increasing risk from `ψ1` to `ψ2` (`ψ1 ≤ ψ2`) cannot decrease decision severity.

**Proof sketch.** Risk class mapping is monotone (`low→mid→high`), and composition is isotone under severity-max.

## B3. Invalid credential or hard mismatch excludes allow

**Statement.** If credential is invalid or context class is `hard`, final action cannot be `allow`.

**Proof sketch.** Either condition injects a deny-producing rule, and deny dominates composition.

## B4. Composition non-downgrade

**Statement.** For applicable action sets `X ⊆ Y`, `⨆X ≤ ⨆Y` under `allow < throttle < deny`.

**Proof sketch.** Severity-max over a superset cannot be smaller.

## B5. Determinism

**Statement.** For fixed `Γ` and `Σ`, derived final action is unique.

**Proof sketch.** Applicable rule outputs are fixed predicates over fixed inputs; severity-max is unique.

## B6. Replay evidence non-neutralization

**Statement.** Adding replay evidence from `(REPLAY-ACCUM)` or `(REPLAY-HARD)` cannot make the action less severe.

**Proof sketch.** Replay adds `throttle` or `deny` to the action set; by B4, composition cannot downgrade.

## Proofs vs tests

- **Proofs (this file):** semantic guarantees under the formal model.
- **Tests (`tests/test_formal_policy.py` and related):** implementation conformance checks for selected instances.

Tests support fidelity of realization; they do not replace the proofs.

## Paper positioning (scope and non-scope)

**Positioning used throughout this repository:** CBRCA is an implementation-grounded formal method for context-aware authorization in API-facing LLM services, with explicit semantics and proved core properties under its stated model, plus frozen comparable evaluation. It is **not** claimed as a fully general access-control theory, real-world deployment validation, or proof outside the explicit semantic model.
