import pytest

from experiments.preflight import validate_served_traffic_preflight
from experiments.types import EventRow


def _e(scenario: str, label: str) -> EventRow:
    return EventRow("B4", scenario, 200, "ok", "throttle", 10.0, 10, label == "benign", 0.5, 7, label)


def test_strict_count_gate_requires_enough_non_deny() -> None:
    events: list[EventRow] = []
    # S1 attack count intentionally below 50 to trigger hard fail gate
    events += [_e("S1_restricted_issuance_hard", "attack") for _ in range(49)]
    events += [_e("S1_benign_control_hard", "benign") for _ in range(120)]
    # other families satisfy minima
    events += [_e("S2_delegated_misuse_hard", "attack") for _ in range(60)]
    events += [_e("S2_benign_control_hard", "benign") for _ in range(120)]
    events += [_e("S3_replay_nearmiss_hard", "attack") for _ in range(70)]
    events += [_e("S3_benign_control_hard", "benign") for _ in range(130)]

    with pytest.raises(RuntimeError):
        validate_served_traffic_preflight(events)
