from experiments.preflight import validate_served_traffic_preflight
from experiments.types import EventRow


def _evt(scenario: str, label: str, decision: str = "throttle") -> EventRow:
    return EventRow("B4", scenario, 200, "ok", decision, 1.0, 1, label == "benign", 0.5, 7, label)


def test_served_traffic_target_counts_reachable() -> None:
    events = []
    events += [_evt("S1_restricted_issuance_hard", "attack") for _ in range(55)]
    events += [_evt("S1_benign_control_hard", "benign") for _ in range(120)]
    events += [_evt("S2_delegated_misuse_hard", "attack") for _ in range(60)]
    events += [_evt("S2_benign_control_hard", "benign") for _ in range(130)]
    events += [_evt("S3_replay_nearmiss_hard", "attack") for _ in range(70)]
    events += [_evt("S3_benign_control_hard", "benign") for _ in range(140)]
    validate_served_traffic_preflight(events)
