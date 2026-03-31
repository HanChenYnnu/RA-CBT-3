# Formal Authorization Semantics (Rule-System Model)

This document specifies the **abstract semantics** of the method.  
`baselines/B4_full/*` is one concrete implementation of this model.

## 1) Sorts, environments, and state

Let:

- Subjects \(u \in \mathcal U\)
- Credentials \(\kappa \in \mathcal K\)
- Runtime contexts \(\chi \in \mathcal X\)
- Requests \(\rho \in \mathcal R\)
- Resource scopes \(\sigma \in \mathcal S\)
- Risk scores \(\psi \in [0,1]\)
- Contention scores \(\beta \in [0,1]\)
- Actions \(A=\{\mathsf{allow},\mathsf{throttle},\mathsf{deny}\}\)

Action severity order:
\[
\mathsf{allow} \preceq \mathsf{throttle} \preceq \mathsf{deny}
\]

Authorization state:
\[
\Sigma = \langle u,\kappa,\chi,\rho,\sigma,\psi,\beta,\nu \rangle
\]
where \(\nu\) is hard-violation evidence.

Policy environment:
\[
\Gamma = \langle \tau_a, \tau_d, \beta_t, \beta_d, \epsilon, \mathsf{scope\_map}, \mathsf{revoked}\rangle
\]
with \(\tau_a < \tau_d\), \(\beta_t < \beta_d\), mismatch tolerance \(\epsilon\).

## 2) Judgment forms

We use the following judgments.

- Credential validity: \(\Gamma \vdash \mathsf{cred\_valid}(\kappa, t)\)
- Context class: \(\Gamma \vdash \mathsf{ctx\_class}(\kappa,\chi)=m\), where
  \(m \in \{\mathsf{exact},\mathsf{bounded},\mathsf{hard}\}\)
- Risk class: \(\Gamma \vdash \mathsf{risk\_class}(\psi)=r\), where
  \(r \in \{\mathsf{low},\mathsf{mid},\mathsf{high}\}\)
- Contention class: \(\Gamma \vdash \mathsf{cont\_class}(\beta)=c\), where
  \(c \in \{\mathsf{low},\mathsf{mid},\mathsf{high}\}\)
- Rule applicability: \(\Gamma \vdash \Sigma \Rightarrow R_i : a_i\)
- Authorization derivation (big-step): \(\Gamma \vdash \Sigma \Downarrow a\)
- Transition step: \(\Gamma \vdash \Sigma \xrightarrow{\ell} \Sigma'\)

## 3) Credential lifecycle semantics

### 3.1 Issuance/scoping

\[
\frac{\mathsf{authn}(u)\quad \mathsf{bind}(\chi)=h\quad t_0<t_{exp}}
     {\Gamma \vdash \langle u,\chi,t_0\rangle \xRightarrow{issue} \kappa=(u,t_{exp},h,\mathsf{scope},\mathsf{restricted})}
\quad (ISSUE)
\]

### 3.2 Validation / expiry / invalidation

\[
\frac{\mathsf{sig\_ok}(\kappa)\quad t\le t_{exp}(\kappa)\quad \kappa\notin\Gamma.\mathsf{revoked}}
     {\Gamma \vdash \mathsf{cred\_valid}(\kappa,t)}
\quad (CRED\text{-}VALID)
\]

\[
\frac{t>t_{exp}(\kappa)}{\Gamma \vdash \neg\mathsf{cred\_valid}(\kappa,t)}
\quad (CRED\text{-}EXPIRED)
\qquad
\frac{\kappa\in\Gamma.\mathsf{revoked}}{\Gamma \vdash \neg\mathsf{cred\_valid}(\kappa,t)}
\quad (CRED\text{-}REVOKED)
\]

### 3.3 Scope restriction

\[
\frac{\rho.\mathsf{op}\notin \mathsf{scope}(\kappa)}
     {\Gamma \vdash \Sigma \Rightarrow R_{scope}:\mathsf{deny}}
\quad (SCOPE\text{-}VIOL)
\]

Restricted credentials apply throttle floor:
\[
\frac{\mathsf{restricted}(\kappa)}{\Gamma \vdash \Sigma \Rightarrow R_{restrict}:\mathsf{throttle}}
\quad (RESTRICT\text{-}FLOOR)
\]

## 4) Context mismatch classes

Let \(d(\kappa,\chi)\) be mismatch distance (hash/feature drift score).

\[
\frac{d=0}{\Gamma \vdash \mathsf{ctx\_class}(\kappa,\chi)=\mathsf{exact}}\ (CTX\text{-}EXACT)
\quad
\frac{0<d\le\epsilon}{\Gamma \vdash \mathsf{ctx\_class}(\kappa,\chi)=\mathsf{bounded}}\ (CTX\text{-}BOUNDED)
\quad
\frac{d>\epsilon}{\Gamma \vdash \mathsf{ctx\_class}(\kappa,\chi)=\mathsf{hard}}\ (CTX\text{-}HARD)
\]

Escalation from mismatch:
\[
\frac{\Gamma \vdash \mathsf{ctx\_class}(\kappa,\chi)=\mathsf{bounded}}
     {\Gamma \vdash \Sigma \Rightarrow R_{ctx}:\mathsf{throttle}}
\quad
\frac{\Gamma \vdash \mathsf{ctx\_class}(\kappa,\chi)=\mathsf{hard}}
     {\Gamma \vdash \Sigma \Rightarrow R_{ctx}:\mathsf{deny}}
\]

## 5) Risk and contention classification rules

\[
\frac{\psi < \tau_a}{\Gamma \vdash \mathsf{risk\_class}(\psi)=\mathsf{low}}
\quad
\frac{\tau_a \le \psi < \tau_d}{\Gamma \vdash \mathsf{risk\_class}(\psi)=\mathsf{mid}}
\quad
\frac{\psi \ge \tau_d}{\Gamma \vdash \mathsf{risk\_class}(\psi)=\mathsf{high}}
\]

\[
\frac{\beta < \beta_t}{\Gamma \vdash \mathsf{cont\_class}(\beta)=\mathsf{low}}
\quad
\frac{\beta_t \le \beta < \beta_d}{\Gamma \vdash \mathsf{cont\_class}(\beta)=\mathsf{mid}}
\quad
\frac{\beta \ge \beta_d}{\Gamma \vdash \mathsf{cont\_class}(\beta)=\mathsf{high}}
\]

Applicability:
\[
\frac{\Gamma \vdash \mathsf{risk\_class}(\psi)=\mathsf{mid}}
     {\Gamma \vdash \Sigma \Rightarrow R_{risk}:\mathsf{throttle}}
\quad
\frac{\Gamma \vdash \mathsf{risk\_class}(\psi)=\mathsf{high}}
     {\Gamma \vdash \Sigma \Rightarrow R_{risk}:\mathsf{deny}}
\]

\[
\frac{\Gamma \vdash \mathsf{cont\_class}(\beta)=\mathsf{mid}}
     {\Gamma \vdash \Sigma \Rightarrow R_{cont}:\mathsf{throttle}}
\quad
\frac{\Gamma \vdash \mathsf{cont\_class}(\beta)=\mathsf{high}}
     {\Gamma \vdash \Sigma \Rightarrow R_{cont}:\mathsf{deny}}
\]

## 6) Hard-violation dominance and composition algebra

Hard rule:
\[
\frac{\nu=\mathsf{true}}{\Gamma \vdash \Sigma \Rightarrow R_{hard}:\mathsf{deny}}\quad (HARD)
\]

Credential failure rule:
\[
\frac{\Gamma \vdash \neg\mathsf{cred\_valid}(\kappa,t)}{\Gamma \vdash \Sigma \Rightarrow R_{cred}:\mathsf{deny}}\quad (CRED\text{-}DENY)
\]

Define composition operator \(\sqcup\) over actions by severity max:
\[
a \sqcup b = \max_{\preceq}\{a,b\}
\]
with identity \(\bot=\mathsf{allow}\).

Given applicable rule set \(\mathcal R(\Sigma)=\{a_i\}\), final action is
\[
\mathsf{act}(\Sigma)=\bigsqcup_i a_i.
\]
Authorization rule:
\[
\frac{\forall i\in I.\ \Gamma\vdash\Sigma\Rightarrow R_i:a_i \quad a=\bigsqcup_{i\in I}a_i}
     {\Gamma\vdash\Sigma\Downarrow a}
\quad (AUTH)
\]

Monotonic composition side-condition:
if \(X\subseteq Y\) then \(\bigsqcup X \preceq \bigsqcup Y\).

## 7) Abstract transition semantics

We use a guarded small-step chain plus big-step authorization:

\[
\Sigma_0 \xrightarrow{check\_cred} \Sigma_1
\xrightarrow{classify\_ctx} \Sigma_2
\xrightarrow{classify\_risk/cont} \Sigma_3
\xrightarrow{collect\_rules} \Sigma_4
\xrightarrow{compose} \Sigma_5
\]
then \(\Gamma\vdash\Sigma_5\Downarrow a\).

Post-action updates (budget/replay-cache/invalidations) are modeled by
\(\Sigma_5 \xrightarrow{post(a)} \Sigma_6\).

## 8) Abstract model vs implementation instance

Abstract semantics above defines judgments/rules independent of code layout.
Implementation mapping:

- `policy.py` instantiates \(\preceq\), \(\sqcup\), and one concrete `AUTH` evaluator.
- `app.py` instantiates credential lifecycle, mismatch scoring, risk/context/contention signals.
- Thresholds and feature maps are implementation parameters satisfying the abstract side-conditions.

Therefore proofs in `docs/proofs.md` are over this rule system, with code serving as a concrete model instance.
