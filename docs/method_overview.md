# Method Overview: Context-Bound Credential and Rule-Composed Authorization (CBRCA)

CBRCA is a formal context-aware access-control method for API-facing LLM services. It couples context-bound credential lifecycle control with explicit rule-composed authorization.

## 1. Problem and objective

The target setting is API-facing inference traffic with mixed benign and adversarial requests. The objective is to reduce attack success on non-denied traffic while maintaining benign service continuity.

## 2. Method components

### 2.1 Context-bound credential mechanism

Credentials are short-lived and context-bound at exchange time, then re-checked at request time. Binding uses PoP (`cnf.jkt`) and context features (e.g., network/device/time signals).

### 2.2 Rule-composed authorization semantics

Authorization is derived from explicit rules over credential validity, context consistency, risk score, contention pressure, and hard violations.

Action set and order:

- `allow < throttle < deny`
- final decision = severity-max composition over applicable rule outputs.

### 2.3 Replay-aware temporal accumulation

Replay history is accumulated into decision state. Reuse/violation evidence can escalate from `throttle` to `deny` and cannot be neutralized by benign-looking context in later requests.

## 3. Formal/implementation split

- Abstract semantics and judgments: `docs/formal_semantics.md`
- Abstract proofs over the semantic model: `docs/proofs.md`
- Implementation realization: `baselines/B4_full/policy.py` and `baselines/B4_full/app.py`

Proofs are semantic statements under the explicit model. Tests are implementation conformance checks, not replacements for proofs.

## 4. Evaluation role

CBRCA is evaluated in a frozen comparable protocol (B2 vs B4), including S4 core, S4/S8 ablation/attribution, and held-out synthetic/OOD families with shared-seed robustness.

## 5. Paper positioning (scope and non-scope)

**Positioning used throughout this repository:** CBRCA is an implementation-grounded formal method for context-aware authorization in API-facing LLM services, with explicit semantics and proved core properties under its stated model, plus frozen comparable evaluation. It is **not** claimed as a fully general access-control theory, real-world deployment validation, or proof outside the explicit semantic model.

## 6. Canonical reproduction entrypoint

```bash
python -m scripts.run_all --seed 7 --seeds 5
```
