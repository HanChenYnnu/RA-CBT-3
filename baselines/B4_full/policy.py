"""Formalized authorization semantics used by B4 and ablation variants."""

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
    credential_valid: bool
    context_consistent: bool
    hard_violation: bool
    risk_score: float
    contention: float
    restricted_credential: bool


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


def is_more_permissive(a: ControlAction, b: ControlAction) -> bool:
    return int(a) < int(b)

