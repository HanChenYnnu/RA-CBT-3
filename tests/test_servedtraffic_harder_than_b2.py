import pytest

from experiments.expected_deltas import assert_defensibility_gates
from experiments.metrics import compute_b4_risk_evaluation, compute_b4_vs_b2_served_deltas, compute_metrics, compute_served_slices_for_baseline
from experiments.types import EventRow


def _evt(baseline: str, scenario: str, label: str, risk: float, seed: int = 7) -> EventRow:
    return EventRow(baseline, scenario, 200, "ok", "throttle", 15.0, 12, label == "benign", risk, seed, label)


def test_gate_fails_when_b4_not_significantly_better_than_b2() -> None:
    groups = {
        "S1_pair": ["S1_restricted_issuance_hard", "S1_benign_control_hard"],
        "S2_pair": ["S2_delegated_misuse_hard", "S2_benign_control_hard"],
        "S3_pair": ["S3_replay_blended_hard", "S3_benign_control_hard"],
    }
    events: list[EventRow] = []
    for baseline in ["B4", "B2"]:
        for i in range(120):
            events.append(_evt(baseline, "S1_restricted_issuance_hard", "attack", 0.60 + (i % 5) * 0.01))
            events.append(_evt(baseline, "S1_benign_control_hard", "benign", 0.59 + (i % 5) * 0.01))
            events.append(_evt(baseline, "S2_delegated_misuse_hard", "attack", 0.58 + (i % 5) * 0.01))
            events.append(_evt(baseline, "S2_benign_control_hard", "benign", 0.57 + (i % 5) * 0.01))
            events.append(_evt(baseline, "S3_replay_blended_hard", "attack", 0.56 + (i % 5) * 0.01))
            events.append(_evt(baseline, "S3_benign_control_hard", "benign", 0.55 + (i % 5) * 0.01))
    b4_eval = compute_b4_risk_evaluation([e for e in events if e.baseline == "B4"], loso_groups=groups)
    rows = compute_metrics(events, b4_eval=b4_eval)
    deltas = compute_b4_vs_b2_served_deltas(events, groups=groups, bootstrap_n=80)
    b2_served = compute_served_slices_for_baseline(events, baseline="B2", groups=groups)

    with pytest.raises(AssertionError):
        assert_defensibility_gates(rows, b4_eval, b2_served=b2_served, b4_b2_deltas=deltas)
