"""Formal authorization and state-transition semantics used by B4 variants."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class ControlAction(IntEnum):
    """Ordered action lattice (higher means more restrictive)."""

    ALLOW = 0
    THROTTLE = 1
    DENY = 2


@dataclass(frozen=True)
class RuntimeContext:
    ip: str
    asn: str
    country: str
    ua: str
    device_fp: str
    ts: int


@dataclass(frozen=True)
class CredentialEnvelope:
    subject_id: str
    exp: int
    cnf_jkt: str
    ctx_hash: str
    restricted: bool


@dataclass(frozen=True)
class AuthorizationState:
    """Authorization state tuple Σ for decision relation δ(Σ)->A.

    Tuple fields map to formal objects:
    - subject_state: identity / client principal state.
    - credential_valid: validity under signature/expiry/invalidation checks.
    - context_consistent: context-bound consistency class (within allowed drift).
    - request_state: current request metadata class.
    - resource_scope: requested endpoint/action scope.
    - risk_score: risk scalar in [0,1].
    - contention: shared budget contention scalar in [0,1].
    - hard_violation: hard policy violation predicate.
    - restricted_credential: restricted-scope credential predicate.
    """

    subject_state: str = "known"
    credential_valid: bool = True
    context_consistent: bool = True
    request_state: str = "api_call"
    resource_scope: str = "/v1/chat/completions"
    risk_score: float = 0.0
    contention: float = 0.0
    hard_violation: bool = False
    restricted_credential: bool = False


@dataclass(frozen=True)
class PolicyThresholds:
    tau_allow: float
    tau_deny: float
    contention_throttle: float
    contention_deny: float


def decide_action(state: AuthorizationState, thresholds: PolicyThresholds) -> ControlAction:
    """Implementation-grounded decision function δ(state)->action."""

    if not state.credential_valid or not state.context_consistent or state.hard_violation:
        return ControlAction.DENY
    if state.risk_score >= thresholds.tau_deny or state.contention >= thresholds.contention_deny:
        return ControlAction.DENY
    if (
        state.restricted_credential
        or state.risk_score >= thresholds.tau_allow
        or state.contention >= thresholds.contention_throttle
    ):
        return ControlAction.THROTTLE
    return ControlAction.ALLOW


def compose_actions(*actions: ControlAction) -> ControlAction:
    """Severity-max composition operator ⊔ over action lattice.

    The order is ALLOW < THROTTLE < DENY and composition returns max severity.
    """

    if not actions:
        return ControlAction.ALLOW
    return max(actions, key=int)


def is_more_permissive(a: ControlAction, b: ControlAction) -> bool:
    return int(a) < int(b)
