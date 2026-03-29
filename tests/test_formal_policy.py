from baselines.B4_full.policy import AuthorizationState, ControlAction, PolicyThresholds, decide_action, is_more_permissive


TH = PolicyThresholds(tau_allow=0.2, tau_deny=0.8, contention_throttle=0.5, contention_deny=0.9)


def test_invalid_credential_denied() -> None:
    action = decide_action(
        AuthorizationState(
            credential_valid=False,
            context_consistent=True,
            hard_violation=False,
            risk_score=0.0,
            contention=0.0,
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
            hard_violation=False,
            risk_score=0.0,
            contention=0.0,
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
            hard_violation=True,
            risk_score=0.01,
            contention=0.01,
            restricted_credential=False,
        ),
        TH,
    )
    assert action is ControlAction.DENY


def test_monotonicity_under_increasing_risk() -> None:
    low = decide_action(
        AuthorizationState(True, True, False, risk_score=0.10, contention=0.10, restricted_credential=False),
        TH,
    )
    mid = decide_action(
        AuthorizationState(True, True, False, risk_score=0.30, contention=0.10, restricted_credential=False),
        TH,
    )
    high = decide_action(
        AuthorizationState(True, True, False, risk_score=0.90, contention=0.10, restricted_credential=False),
        TH,
    )
    assert not is_more_permissive(mid, low)
    assert not is_more_permissive(high, mid)

