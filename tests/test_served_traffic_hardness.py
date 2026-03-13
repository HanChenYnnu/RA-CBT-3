from experiments.preflight import validate_served_traffic_preflight
from experiments.types import EventRow


def _e(scenario: str, label: str, decision: str = "throttle") -> EventRow:
    return EventRow("B4", scenario, 200, "ok", decision, 16.0, 16, label == "benign", 0.4, 7, label)


def test_served_traffic_pair_counts_and_hard_paths() -> None:
    events: list[EventRow] = []
    events += [_e("S1_restricted_issuance_hard", "attack") for _ in range(55)]
    events += [_e("S1_benign_control_hard", "benign") for _ in range(120)]
    events += [_e("S2_delegated_misuse_hard", "attack") for _ in range(55)]
    events += [_e("S2_benign_control_hard", "benign") for _ in range(120)]
    events += [_e("S3_replay_nearmiss_hard", "attack") for _ in range(40)]
    events += [_e("S3_replay_blended_hard", "attack") for _ in range(20)]
    events += [_e("S3_benign_control_hard", "benign") for _ in range(130)]
    validate_served_traffic_preflight(events)
