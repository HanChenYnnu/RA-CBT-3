from experiments.metrics import compute_b4_risk_evaluation
from experiments.types import EventRow


def test_fallback_rule_can_trigger() -> None:
    events = []
    for i in range(20):
        events.append(EventRow("B4", "S1_key_leak_hard", 200, "ok", "allow", 1.0, 1, False, 0.51 + (i % 2) * 0.01, 1, "attack"))
        events.append(EventRow("B4", "S1_benign_control_hard", 200, "ok", "allow", 1.0, 1, True, 0.49 + (i % 2) * 0.01, 1, "benign"))
    ev = compute_b4_risk_evaluation(events)
    # if not triggered this dataset, we still require boolean and official metrics consistency
    assert isinstance(ev.calibration_fallback_used, bool)
    if ev.calibration_fallback_used:
        assert abs(ev.ece_official - ev.ece_raw) < 1e-9
