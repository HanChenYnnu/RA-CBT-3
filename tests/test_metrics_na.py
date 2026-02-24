from experiments.metrics import MIN_NON_DENY, _mean_defined, _pr, _roc, compute_b4_risk_evaluation
from experiments.types import EventRow


def test_single_class_is_na() -> None:
    labels = [0, 0, 0]
    scores = [0.1, 0.2, 0.3]
    assert _roc(labels, scores)[0] is None
    assert _pr(labels, scores)[0] is None


def test_macro_loso_exclude_na() -> None:
    assert _mean_defined([None, 0.4, 0.6]) == 0.5


def test_non_deny_min_sample_rule() -> None:
    events = []
    # total has both classes, non-deny too small (< MIN_NON_DENY)
    for i in range(MIN_NON_DENY - 1):
        events.append(EventRow("B4", "S1_key_leak_hard", 200, "ok", "allow", 1.0, 1, False, 0.7, 1, "attack"))
    events.append(EventRow("B4", "S1_benign_control_hard", 401, "deny", "deny", 1.0, 0, True, 0.2, 1, "benign"))
    ev = compute_b4_risk_evaluation(events)
    assert ev.non_deny_pr_auc is None


def test_loso_tiny_non_deny_regression_to_na() -> None:
    events = [
        EventRow("B4", "S3_replay_hard", 200, "ok", "allow", 1.0, 1, False, 0.8, 1, "attack"),
        EventRow("B4", "S3_benign_control_hard", 200, "ok", "allow", 1.0, 1, True, 0.2, 1, "benign"),
        EventRow("B4", "S1_key_leak_hard", 200, "ok", "deny", 1.0, 1, False, 0.7, 1, "attack"),
        EventRow("B4", "S1_benign_control_hard", 200, "ok", "deny", 1.0, 1, True, 0.1, 1, "benign"),
    ]
    ev = compute_b4_risk_evaluation(events, loso_groups={"S3_pair": ["S3_replay_hard", "S3_benign_control_hard"]})
    assert ev.loso_rows[0].n_non_deny < MIN_NON_DENY
    assert ev.loso_rows[0].non_deny_pr_auc is None
