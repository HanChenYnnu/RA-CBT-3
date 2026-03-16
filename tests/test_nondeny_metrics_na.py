from experiments.metrics import compute_b4_risk_evaluation
from experiments.types import EventRow


def test_non_deny_metrics_are_na_with_insufficient_class_counts() -> None:
    events = []
    # non-deny has <20 benign so non-deny AUROC/PR-AUC must be N/A
    for i in range(60):
        events.append(EventRow("B4", "S1_restricted_issuance_hard", 200, "ok", "throttle", 1.0, 1, False, 0.7, 7, "attack"))
    for i in range(10):
        events.append(EventRow("B4", "S1_benign_control_hard", 200, "ok", "throttle", 1.0, 1, True, 0.2, 7, "benign"))

    ev = compute_b4_risk_evaluation(events)
    assert ev.non_deny_auroc is None
    assert ev.non_deny_pr_auc is None
