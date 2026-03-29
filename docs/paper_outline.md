# Paper Outline Draft (Aligned with Current Branch)

## Title candidates
1. Context-Bound Dynamic Credentials and Risk-Driven Multi-Action Control for API-Facing LLM Security
2. A Reproducible Mixed-Load Evaluation of Context-Bound Credential Control in LLM API Access
3. From Static Keys to Context-Bound Runtime Control: A Deterministic Evaluation Framework for LLM APIs

## Abstract skeleton
- **Background**: Static API-key style authorization is vulnerable to misuse and offers weak control granularity under mixed benign/adversarial load.
- **Objective**: Evaluate whether context-bound credentialing and risk-driven multi-action control improve security-availability balance.
- **Method**: B4 combines dynamic context-bound exchange tokens, risk-scored allow/throttle/deny decisions, and a frozen apples-to-apples protocol against B2.
- **Results**: Under shared seeds and fixed stack, B4 improves S4 PR-AUC and Lift@100, increases SR_benign at scale=1.00, and decreases ASR_non_deny_attack.
- **Conclusion**: The contribution is a systems/control framework with reproducible comparative evidence; external validation remains future work.

## Introduction logic
1. Practical weakness of static long-lived API credentials in LLM/API deployments.
2. Operational requirement to preserve benign service under mixed-load contention.
3. Gap: binary control and non-comparable evaluations obscure method attribution.
4. Proposed three-part framework (A/B/C) and its scoped claims.
5. Summary of empirical findings and limitations.

## Method section outline
### 3.1 System model and threat assumptions
- API request path with token exchange and request-time authorization checks.
- Adversarial behaviors represented by scenario slices.

### 3.2 Component A: Context-Bound Dynamic API Credential Mechanism
- Exchange token construction and binding fields.
- Context/profile mismatch handling.
- Intended risk reduction mechanism.

### 3.3 Component B: Risk-Driven Multi-Action Control Strategy
- Risk signal construction and calibration thresholds.
- Action space: allow/throttle/deny.
- Budget/queue pressure coupling and deterministic control behavior.

### 3.4 Component C: Unified Comparable Evaluation Protocol
- Frozen stack definition.
- Shared-seed, single-comparator rerun protocol.
- Slice-aware mixed-load reporting.

## Experiment section outline
### 4.1 Compared methods and implementation parity
- B2 baseline vs B4 current method.

### 4.2 Data generation and scenario coverage
- Deterministic scenario generator and mixed-load S4 emphasis.

### 4.3 Metrics
- S4 PR-AUC, S4 Lift@100, scale=1.00 SR_benign, scale=1.00 ASR_non_deny_attack.

### 4.4 Reproducibility controls
- Seed set, frozen code path, and report-generation parity checks.

### 4.5 Main results and interpretation
- Method-linked interpretation rather than leaderboard-only reporting.

## Conclusion outline
1. Restate three-part proposal and scoped contribution.
2. Summarize validated effects under frozen comparable evaluation.
3. Explicitly state limitations (synthetic deterministic environment, no formal proof).
4. Next steps: broader external traffic and infrastructure validation with unchanged comparability discipline.
