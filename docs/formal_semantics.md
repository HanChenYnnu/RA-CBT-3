# Formal Semantics for CBRCA

This document specifies the abstract authorization semantics for **Context-Bound Credential and Rule-Composed Authorization (CBRCA)**.

## 1. Scope of the formal model

The model specifies judgments, inference rules, and action composition for CBRCA under an API-facing LLM service setting. It does not claim universality beyond this explicit model.

## 2. Sorts and state

Let:

- subject `u ∈ U`
- credential `κ ∈ K`
- runtime context `χ ∈ X`
- request `ρ ∈ R`
- scope `σ ∈ S`
- risk score `ψ ∈ [0,1]`
- contention score `β ∈ [0,1]`
- hard-violation predicate `ν ∈ {false,true}`

Authorization state:

`Σ = ⟨u, κ, χ, ρ, σ, ψ, β, ν⟩`

Environment:

`Γ = ⟨τ_a, τ_d, β_t, β_d, ε, scope_map, revoked⟩`

with `τ_a < τ_d` and `β_t < β_d`.

Action lattice:

`A = {allow, throttle, deny}` with `allow < throttle < deny`.

## 3. Judgments

- `Γ ⊢ cred_valid(κ,t)`
- `Γ ⊢ ctx_class(κ,χ) = m`, where `m ∈ {exact, bounded, hard}`
- `Γ ⊢ risk_class(ψ) = r`, where `r ∈ {low, mid, high}`
- `Γ ⊢ cont_class(β) = c`, where `c ∈ {low, mid, high}`
- `Γ ⊢ Σ ⇒ R_i : a_i`
- `Γ ⊢ Σ ⇓ a`

## 4. Credential and scope rules

- Invalid/expired/revoked credentials derive deny.
- Scope violation derives deny.
- Restricted credentials may induce throttle floor.

## 5. Context and replay rules

Let `d(κ,χ)` be mismatch distance:

- `d=0` → `exact`
- `0<d≤ε` → `bounded`
- `d>ε` → `hard`

Escalation:

- `bounded` mismatch can derive `throttle`
- `hard` mismatch derives `deny`

Replay accumulation:

- `(REPLAY-ACCUM)` derives `throttle`
- `(REPLAY-HARD)` derives `deny`

These rules encode temporal persistence: replay evidence remains active for later decisions.

## 6. Risk and contention rules

Risk and contention are each threshold-classified into `{low, mid, high}` and mapped to actions:

- mid → `throttle`
- high → `deny`

## 7. Composition and authorization

Composition operator is severity-max join:

`a ⊔ b = max_{<}{a,b}` with identity `allow`.

If applicable action multiset is `X`, final action is:

`act(Σ) = ⨆ X`.

Hence adding stronger applicable evidence cannot make the final action less severe.

## 8. Abstract transition view

A guarded chain captures processing:

`check_cred → classify_ctx → classify_risk/cont → collect_rules → compose`.

Post-action updates (e.g., replay history/budget updates) feed subsequent states.

## 9. Implementation mapping

- Policy realization: `baselines/B4_full/policy.py`
- Runtime signal realization: `baselines/B4_full/app.py`

The formal document defines the model; implementation files instantiate one concrete realization.

## 10. Paper positioning (scope and non-scope)

**Positioning used throughout this repository:** CBRCA is an implementation-grounded formal method for context-aware authorization in API-facing LLM services, with explicit semantics and proved core properties under its stated model, plus frozen comparable evaluation. It is **not** claimed as a fully general access-control theory, real-world deployment validation, or proof outside the explicit semantic model.
