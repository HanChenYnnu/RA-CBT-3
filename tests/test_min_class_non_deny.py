from experiments.metrics import MIN_CLASS_NON_DENY, MIN_NON_DENY, _mean_defined, compute_b4_risk_evaluation
from experiments.types import EventRow


def _evt(s: str, decision: str, label: str, risk: float, seed: int = 1) -> EventRow:
    return EventRow("B4", s, 200, "ok", decision, 1.0, 1, label == "benign", risk, seed, label)


def test_small_class_counts_force_na() -> None:
    events = []
    for i in range(MIN_NON_DENY):
        events.append(_evt("S3_replay_hard", "allow", "attack", 0.8 + (i % 2) * 0.01))
    for i in range(MIN_CLASS_NON_DENY - 1):
        events.append(_evt("S3_benign_control_hard", "allow", "benign", 0.2 + (i % 2) * 0.01))
    ev = compute_b4_risk_evaluation(events)
    assert ev.non_deny_auroc is None
    assert ev.non_deny_pr_auc is None


def test_macro_excludes_na() -> None:
    assert _mean_defined([None, 0.2, 0.4]) == 0.30000000000000004


def test_loso_mean_excludes_na() -> None:
    rows = [
        _evt("S1_key_leak_hard", "allow", "attack", 0.8),
        _evt("S1_benign_control_hard", "allow", "benign", 0.2),
        _evt("S3_replay_hard", "allow", "attack", 0.8),
    ]
    ev = compute_b4_risk_evaluation(rows, loso_groups={"S1_pair": ["S1_key_leak_hard", "S1_benign_control_hard"], "S3_pair": ["S3_replay_hard"]})
    assert _mean_defined([r.non_deny_pr_auc for r in ev.loso_rows]) is None
