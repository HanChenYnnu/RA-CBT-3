# 1. Problem Setting

API-facing LLM services are often protected by static key-style credentials or minimally scoped bearer tokens. In adversarial settings, these credentials can be replayed or delegated outside their intended context, especially when requests are generated from heterogeneous clients and network conditions. Under mixed-load contention, purely binary access control can also cause undesirable trade-offs: strict blocking degrades benign service, while permissive rules increase attack-side leakage.

This artifact evaluates a practical control framework that combines context-bound credentialing and risk-driven runtime decisions, and validates it under a frozen, comparable protocol.

# 2. Method

We evaluate baseline **B4** as a three-component method contribution.

## 2.1 Context-Bound Dynamic API Credential Mechanism

B4 replaces static authorization behavior with short-lived exchanged credentials that are bound to runtime context.

Implementation mapping:
- `/auth/exchange` issues a bounded token with `cnf.jkt` and a context hash.
- Request-time checks compare issuance-time and runtime context (IP/ASN/country/UA/device signals) and reject severe mismatch.
- Exchange-time profile anomaly scoring supports restricted issuance and high-risk denial thresholds.

Method role:
- constrains credential validity to context and time,
- reduces reuse utility of leaked/static credential material,
- feeds downstream risk signals used by runtime control.

## 2.2 Risk-Driven Multi-Action Control Strategy

B4 performs a risk-scored, pressure-aware multi-action decision rather than binary allow/deny.

Implementation mapping:
- risk score combines context drift, replay pressure, exchange anomaly, budget pressure, and scenario priors;
- decision space includes **allow**, **throttle**, and **deny**;
- throttle is implemented as token precharge tightening under contention/risk bands.

Method role:
- preserves a graded response under load,
- seeks to increase benign service rate without simply relaxing attack control,
- supports mixed-load stability when attack and benign traffic coexist.

## 2.3 Unified Comparable Evaluation Protocol for Mixed-Load Scenarios

The experiment pipeline enforces a frozen apples-to-apples setup for B2 vs B4.

Protocol mapping:
- same metric code, slice definition, operating point, seed policy, aggregation, and report generation;
- shared seed set: `[7, 11, 19, 23, 31]`;
- mixed-load analysis centered on S4 slices;
- single baseline/current path (`B2` → `B4`) to avoid post-hoc comparator changes.

Method role:
- provides defensibility for observed gains of Sections 2.1 and 2.2,
- reduces attribution ambiguity from pipeline drift.

# 3. Experimental Design

## 3.1 Compared systems

- **Baseline**: B2 (short-bearer style control under the same evaluation stack).
- **Current method**: B4 (context-bound credentialing + risk-driven multi-action runtime control).

## 3.2 Frozen-stack apples-to-apples constraints

The run enforces identical evaluation components across B2 and B4:
- metric computation,
- slice definitions,
- operating point,
- seed set and aggregation,
- report logic.

All comparability checks are marked valid in the audit outputs.

## 3.3 Slice focus and mixed-load setting

The key slice is **S4_pair**, a mixed-load setting containing scale sweeps (`x1.00`, `x0.70`, `x0.50`, `x0.35`, `x0.25`). This slice is used to evaluate security ranking and service behavior under contention.

## 3.4 Primary evaluation metrics

Four primary metrics are used:
1. **S4 PR-AUC**,
2. **S4 Lift@100**,
3. **scale=1.00 SR_benign**,
4. **scale=1.00 ASR_non_deny_attack**.

# 4. Results and Analysis

## 4.1 Multi-seed summary (B2 vs B4)

- **S4 PR-AUC**: B2 `0.5174 ± 0.0033`, B4 `0.9603 ± 0.0037`, delta `+0.4430`, 5/5 favorable, 95% CI `[0.4406, 0.4453]`.
- **S4 Lift@100**: B2 `1.0520 ± 0.0483`, B4 `2.6402 ± 0.0653`, delta `+1.5882`, 5/5 favorable, 95% CI `[1.5567, 1.6197]`.
- **scale=1.00 SR_benign**: B2 `0.1733 ± 0.0000`, B4 `0.2080 ± 0.0100`, delta `+0.0347`, 5/5 favorable, 95% CI `[0.0259, 0.0435]`.
- **scale=1.00 ASR_non_deny_attack**: B2 `0.2267 ± 0.0000`, B4 `0.1920 ± 0.0100`, delta `-0.0347`, 5/5 favorable, 95% CI `[-0.0435, -0.0259]`.

## 4.2 Interpretation through the method lens

1. **Component A effect (context-bound credentials)**: strong S4 ranking gains (PR-AUC, Lift@100) are consistent with improved discrimination of risky traffic under mixed context conditions.
2. **Component B effect (multi-action control)**: benign service improves at scale=1.00 while non-deny attack success decreases, indicating that graded throttle/deny control can improve availability-security balance rather than trading one metric for another.
3. **Component C effect (frozen comparability)**: strict parity of evaluation stack and seed policy increases confidence that improvements are method-driven rather than evaluation drift.

## 4.3 Scope and limitations

- Evidence is limited to the deterministic synthetic scenario set in this repository.
- Confidence intervals are normal-approximate and derived from five seeds.
- The artifact demonstrates empirical robustness under its fixed protocol, not formal security guarantees.

# 5. Conclusion

This work proposes and evaluates a practical three-part framework for API-facing LLM access control: (i) context-bound dynamic credentialing, (ii) risk-driven multi-action runtime control, and (iii) a frozen comparable evaluation protocol for mixed-load validation. Under a controlled B2-to-B4 comparison, the method shows consistent multi-seed gains in mixed-load ranking quality (S4 PR-AUC and Lift@100), improves benign service at scale=1.00, and reduces non-deny attack success.

The contribution is primarily a systems/control framework with rigorous comparative evaluation, rather than a new formal access-control theory. The current evidence supports effectiveness within the repository’s deterministic scenario model. A natural next step is external validation under broader traffic distributions and independent infrastructure conditions, while preserving the same comparability constraints.
