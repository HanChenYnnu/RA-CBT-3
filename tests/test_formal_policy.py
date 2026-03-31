from baselines.B4_full.policy import AuthorizationState, ControlAction, PolicyThresholds, compose_actions, decide_action, is_more_permissive


TH = PolicyThresholds(tau_allow=0.2, tau_deny=0.8, contention_throttle=0.5, contention_deny=0.9)


def test_invalid_credential_denied() -> None:
    action = decide_action(
        AuthorizationState(
            credential_valid=False,
            context_consistent=True,
            risk_score=0.0,
            contention=0.0,
            hard_violation=False,
            restricted_credential=False,
        ),
        TH,
    )
    assert action is ControlAction.DENY


def test_context_inconsistency_denied() -> None:
    action = decide_action(
        AuthorizationState(
            credential_valid=True,
            context_consistent=False,
            risk_score=0.0,
            contention=0.0,
            hard_violation=False,
            restricted_credential=False,
        ),
        TH,
    )
    assert action is ControlAction.DENY


def test_hard_violation_forces_deny() -> None:
    action = decide_action(
        AuthorizationState(
            credential_valid=True,
            context_consistent=True,
            risk_score=0.01,
            contention=0.01,
            hard_violation=True,
            restricted_credential=False,
        ),
        TH,
    )
    assert action is ControlAction.DENY


def test_monotonicity_under_increasing_risk() -> None:
    low = decide_action(
        AuthorizationState(credential_valid=True, context_consistent=True, hard_violation=False, risk_score=0.10, contention=0.10, restricted_credential=False),
        TH,
    )
    mid = decide_action(
        AuthorizationState(credential_valid=True, context_consistent=True, hard_violation=False, risk_score=0.30, contention=0.10, restricted_credential=False),
        TH,
    )
    high = decide_action(
        AuthorizationState(credential_valid=True, context_consistent=True, hard_violation=False, risk_score=0.90, contention=0.10, restricted_credential=False),
        TH,
    )
    assert not is_more_permissive(mid, low)
    assert not is_more_permissive(high, mid)


def test_invalid_or_inconsistent_never_allow() -> None:
    invalid = decide_action(AuthorizationState(credential_valid=False, context_consistent=True), TH)
    inconsistent = decide_action(AuthorizationState(credential_valid=True, context_consistent=False), TH)
    assert invalid is not ControlAction.ALLOW
    assert inconsistent is not ControlAction.ALLOW


def test_severity_max_composition_is_monotone() -> None:
    base = compose_actions(ControlAction.ALLOW, ControlAction.THROTTLE)
    stronger = compose_actions(ControlAction.ALLOW, ControlAction.THROTTLE, ControlAction.DENY)
    assert base is ControlAction.THROTTLE
    assert stronger is ControlAction.DENY
    assert not is_more_permissive(stronger, base)


def test_decision_determinism_for_fixed_state() -> None:
    s = AuthorizationState(credential_valid=True, context_consistent=True, hard_violation=False, risk_score=0.42, contention=0.22, restricted_credential=False)
    a1 = decide_action(s, TH)
    a2 = decide_action(s, TH)
    assert a1 is a2
