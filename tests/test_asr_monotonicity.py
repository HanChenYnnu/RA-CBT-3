from experiments.metrics import compute_metrics
from experiments.types import EventRow


def _row(decision: str, benign: bool, scenario: str = "Sx") -> EventRow:
    return EventRow("B4", scenario, 200, "ok", decision, 1.0, 1, benign, 0.5, 1, "benign" if benign else "attack")


def test_sr_asr_monotonicity() -> None:
    events = [
        _row("allow", False),
        _row("throttle", False),
        _row("deny", False),
        EventRow("B4", "Sx", 401, "deny", "deny", 1.0, 0, False, 0.7, 1, "attack"),
    ]
    r = compute_metrics(events)[0]
    assert r.success_rate_mean >= r.attack_success_rate_non_deny_mean >= r.attack_success_rate_allow_mean


def test_benign_zero_throttle_equality() -> None:
    events = [_row("allow", True, "S_benign") for _ in range(5)]
    r = compute_metrics(events)[0]
    assert r.throttle_rate_mean == 0.0
    assert r.success_rate_mean == r.attack_success_rate_non_deny_mean == r.attack_success_rate_allow_mean
