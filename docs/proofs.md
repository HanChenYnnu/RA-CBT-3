# Abstract Semantic Proofs

Proofs below are over the rule system in `docs/formal_semantics.md`, not over source-order in code.

## Theorem B1 (Hard-violation deny)

**Statement.** If \(\Gamma \vdash \Sigma \Rightarrow R_{hard}:\mathsf{deny}\), then \(\Gamma \vdash \Sigma \Downarrow \mathsf{deny}\).

**Proof.** By rule `(AUTH)`, final action is \(a=\bigsqcup_i a_i\) over all applicable rules. Since one member is `deny` from `(HARD)`, and `deny` is top element of \((A,\preceq)\), \(a=\mathsf{deny}\). ∎

## Theorem B2 (Monotonicity under risk escalation)

**Statement.** Fix \(\kappa,t,\chi,\beta,\nu,\rho,\sigma\) and let \(\psi_1\le\psi_2\). Assume same credential-validity class and context class hold for both states. If
\(\Gamma\vdash\Sigma_1\Downarrow a_1\) and \(\Gamma\vdash\Sigma_2\Downarrow a_2\), then \(a_1\preceq a_2\).

**Proof.** From risk classification rules, \(\mathsf{risk\_class}(\psi)\) is monotone in \(\psi\): low→mid→high only. Corresponding applicable risk action is monotone (`allow` contribution for low, `throttle` for mid, `deny` for high). Other rule outputs are fixed by hypothesis (same credential/context/contention/hard classes). Let fixed multiset be \(F\); then
\(a_1 = (\bigsqcup F) \sqcup r_1\), \(a_2 = (\bigsqcup F) \sqcup r_2\), with \(r_1\preceq r_2\). By isotonicity of \(\sqcup\), \(a_1\preceq a_2\). ∎

## Theorem B3 (Invalid or hard-inconsistent credentials exclude allow)

**Statement.** If either (i) \(\Gamma\vdash\neg\mathsf{cred\_valid}(\kappa,t)\) or (ii) \(\Gamma\vdash\mathsf{ctx\_class}(\kappa,\chi)=\mathsf{hard}\), then \(\Gamma\vdash\Sigma\Downarrow a\Rightarrow a\neq\mathsf{allow}\).

**Proof.** Case (i): by `(CRED-DENY)` we derive an applicable `deny` action, so by `(AUTH)` composition contains top element and final action is deny. Case (ii): by `(CTX-HARD)` escalation rule we derive `deny`, again forcing final action deny by `(AUTH)`. In both cases allow is impossible. ∎

## Theorem B4 (Composition non-downgrade)

**Statement.** Let applicable action multisets satisfy \(X\subseteq Y\). Then \(\bigsqcup X \preceq \bigsqcup Y\).

**Proof.** Since \(\sqcup\) is max over total order \(\preceq\), \(\bigsqcup X\) is the greatest element of \(X\), while \(\bigsqcup Y\) is greatest in superset \(Y\). A superset cannot have a smaller maximum. ∎

## Theorem B5 (Determinism under fixed environment)

**Statement.** For fixed \(\Gamma\) and \(\Sigma\), if \(\Gamma\vdash\Sigma\Downarrow a\) and \(\Gamma\vdash\Sigma\Downarrow a'\), then \(a=a'\).

**Proof.** Rule applicability judgments are predicates over fixed \(\Gamma,\Sigma\), hence produce a unique multiset \(\mathcal R(\Sigma)\). `(AUTH)` defines result as \(\bigsqcup \mathcal R(\Sigma)\), unique because max over total order is unique. Therefore \(a=a'\). ∎

## Corollary (Deny precedence)

If any applicable rule yields deny, final action is deny. This follows directly from B4 with `deny` as top element and from B1/B3 instantiations.

---

Implementation tests in `tests/test_formal_policy.py` are **conformance checks** for selected theorem instances; they are not the proofs themselves.
