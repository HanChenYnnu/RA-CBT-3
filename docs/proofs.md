# Propositions and Proof Sketches

## P1. Hard-violation priority

**Statement.** If hard violation predicate \(\nu=true\), then \(\delta(\Sigma,\Theta)=\textsf{deny}\).

**Proof.** Direct. In `decide_action`, the first guard returns `deny` when `hard_violation` is true; no later branch is reachable. ∎

## P2. Monotonicity under increasing risk

**Statement.** Fix credential validity, context consistency class, contention, and hard-violation=false. For two states differing only in risk \(\psi_1\le\psi_2\), we have
\(\delta(\Sigma_1,\Theta) \le \delta(\Sigma_2,\Theta)\).

**Proof.** Case analysis on threshold regions:
1. \(\psi_2 < \tau_{allow}\): both states in allow/throttle region depending on other fixed guards, never stricter-to-weaker under higher risk.
2. \(\tau_{allow} \le \psi_2 < \tau_{deny}\): output at least throttle; increasing risk cannot move to allow because allow predicate requires risk below \(\tau_{allow}\).
3. \(\psi_2 \ge \tau_{deny}\): output deny.
Hence severity is monotone non-decreasing. ∎

## P3. Invalid or context-inconsistent credentials cannot allow

**Statement.** If credential invalid OR context inconsistent beyond allowed bound, decision is not allow.

**Proof by contradiction.** Assume decision is allow while invalid/inconsistent holds. Allow branch in `decide_action` is reachable only after initial guard
`if not credential_valid or not context_consistent ...: deny` evaluates false. Contradiction. Therefore allow is impossible. ∎

## P4. Severity-max composition no-downgrade

**Statement.** For action multisets \(X\subseteq Y\), `compose_actions(X) <= compose_actions(Y)`.

**Proof.** `compose_actions` is max over totally ordered action lattice. Adding elements to a set cannot decrease its maximum. ∎

Tests in `tests/test_formal_policy.py` corroborate implementation conformance; they are not substitutes for proofs.
