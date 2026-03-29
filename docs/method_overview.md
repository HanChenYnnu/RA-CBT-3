# Formal Method Overview

## Access-Control Object

This artifact defines a context-aware authorization object for API-facing LLM services:

- **Subject**: API client identity.
- **Credential**: short-lived exchanged token with confirmation key hash and bound context hash.
- **Runtime context**: IP/ASN/country/UA/device/time tuple.
- **Request**: model call carrying token, DPoP proof, and context headers.
- **Resource**: `/v1/chat/completions`.
- **Control action**: ordered lattice `allow < throttle < deny`.

## Authorization Semantics

The explicit decision function is implemented in `baselines/B4_full/policy.py` as:

`δ(state, thresholds) -> {allow, throttle, deny}`

where state includes:

- credential validity,
- context consistency,
- hard-policy violation,
- risk score,
- contention state,
- restricted-credential flag.

Hard violations and invalid/ inconsistent credentials are deny-precedence.

## Implementation Mapping

- Exchange/binding: `baselines/B4_full/app.py` (`/auth/exchange`, `_ctx_hash`, token encode/decode).
- PoP and replay checks: `baselines/B4_full/app.py` (`_verify_dpop`).
- Risk/context/contention signals: `baselines/B4_full/app.py`.
- Formal decision object: `baselines/B4_full/policy.py`.
- Ablation baselines: `experiments/runner.py` + `baselines/B4_full/harness.py`.

## Intended Properties (Validated by Tests)

- Invalid or expired credentials are never low-risk allow.
- Hard violation implies deny.
- Context inconsistency implies deny.
- Increasing risk does not yield more permissive action (bounded monotonicity).
- Frozen operating-point invariants are checked for report comparability.

These are implementation-grounded checks, not machine-checked proofs.

