from experiments.metrics import compute_b4_risk_evaluation
from experiments.types import EventRow


def test_calibration_fallback_flag_present() -> None:
    events = [
        EventRow("B4", "S1_key_leak_hard", 200, "ok", "allow", 1.0, 1, False, 0.95, 1, "attack"),
        EventRow("B4", "S1_benign_control_hard", 200, "ok", "allow", 1.0, 1, True, 0.05, 1, "benign"),
        EventRow("B4", "S2_token_leak_hard", 401, "dpop_missing", "deny", 1.0, 0, False, 0.6, 1, "attack"),
        EventRow("B4", "S2_benign_control_hard", 200, "ok", "allow", 1.0, 1, True, 0.4, 1, "benign"),
    ]
    ev = compute_b4_risk_evaluation(events)
    assert isinstance(ev.calibration_fallback_used, bool)
