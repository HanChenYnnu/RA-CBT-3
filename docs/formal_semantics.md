# Formal Authorization Semantics

We define authorization as a guarded transition system over state tuple
\(\Sigma=(\iota,\kappa,\chi,\rho,\sigma,\psi,\beta,\nu)\):

- \(\iota\): subject/client identity state.
- \(\kappa\): credential state (issued token, expiry, PoP binding, invalidation flags).
- \(\chi\): runtime context state (IP/ASN/country/UA/device/time).
- \(\rho\): request state (request metadata and intent class).
- \(\sigma\): resource/action scope.
- \(\psi\): risk state in \([0,1]\).
- \(\beta\): contention/budget state in \([0,1]\).
- \(\nu\): hard-violation predicate.

Action set \(A=\{\textsf{allow},\textsf{throttle},\textsf{deny}\}\) with order:
\(\textsf{allow} < \textsf{throttle} < \textsf{deny}\).

## Credential semantics

Issuance transition \(\kappa_0 \xrightarrow{exchange} \kappa_1\) requires valid user key and produces
short-lived token with expiry `exp`, PoP key hash `cnf.jkt`, and context hash `ctx_hash`.

Validity predicate:
\[
Valid(\kappa, t) \iff SignatureOK \land t\le exp \land \neg Invalidated.
\]

Context consistency predicate:
\[
CtxOK(\kappa,\chi) \iff hash(\chi)=ctx\_hash \lor Drift(\chi)\le \epsilon.
\]

Restricted credential flag implies reduced scope and at least throttle severity.

## Decision semantics

Decision relation \(\delta(\Sigma,\Theta)\to A\) is implemented by `decide_action`.

- If `not credential_valid` or `not context_consistent` or `hard_violation`, return `deny`.
- Else if `risk_score >= tau_deny` or `contention >= contention_deny`, return `deny`.
- Else if `restricted_credential` or `risk_score >= tau_allow` or `contention >= contention_throttle`, return `throttle`.
- Else return `allow`.

## State-transition semantics

\[
\Sigma_0 \xrightarrow{verify\_credential/context} \Sigma_1
\xrightarrow{risk/contention\_eval} \Sigma_2
\xrightarrow{\delta} (a,\Sigma_3)
\]

with `a` in \(A\), and optional post-decision updates (budget precharge/refund, replay cache mutation).

## Rule algebra / composition

Let rule outputs be actions in \(A\). Composition uses severity-max join \(\sqcup\):
\[
R = R_{cred} \sqcup R_{ctx} \sqcup R_{hard} \sqcup R_{risk} \sqcup R_{budget}
\]
where \(x\sqcup y = \max(x,y)\) under the action order.

This gives deny precedence and no-downgrade under stronger violation evidence.
