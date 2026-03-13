from experiments.metrics import _served_topk_metrics
from experiments.preflight import validate_served_traffic_preflight
from experiments.types import EventRow


def _evt(scenario: str, label: str, decision: str = "throttle") -> EventRow:
    return EventRow("B4", scenario, 200, "ok", decision, 1.0, 1, label == "benign", 0.5, 7, label)


def test_served_attack_counts_preflight_targets() -> None:
    events = []
    events += [_evt("S1_restricted_issuance_hard", "attack") for _ in range(30)]
    events += [_evt("S1_benign_control_hard", "benign") for _ in range(40)]
    events += [_evt("S2_delegated_misuse_hard", "attack") for _ in range(30)]
    events += [_evt("S2_benign_control_hard", "benign") for _ in range(40)]
    events += [_evt("S3_replay_nearmiss_hard", "attack") for _ in range(30)]
    events += [_evt("S3_benign_control_hard", "benign") for _ in range(40)]
    validate_served_traffic_preflight(events)


def test_metrics_defined_once_min_class_counts_met() -> None:
    labels = [1] * 30 + [0] * 35
    scores = [1.0 - (i * 0.01) for i in range(len(labels))]
    s = _served_topk_metrics(labels, scores, name="S1_pair", bootstrap_seed=11)
    assert s.p_at_k[30] is not None
    assert s.non_deny_pr_auc is not None
