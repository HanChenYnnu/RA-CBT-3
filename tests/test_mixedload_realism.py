from experiments.expected_deltas import assert_budget_sweep_gates
from experiments.metrics import MetricRow


def _row(scale: str, sr_b: float, frr_b: float, thr_b: float, asr_a: float, asr_nd: float, cost: float) -> MetricRow:
    return MetricRow("B4", f"S4_mixedload_sweep_x{scale}", 1, 0, 0.2, 0, 0.6, 0, 100, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0.5, 0, 0.6, 0, 1, 1,
        0.8, 0.7, 0.7, 0.6, 0.1, 0.2, 300, 100, 200, 0.7, 0.6, 0.55, 0.5, 0.45, 0.1, 0.2, 0.3, 0.4, 0.5,
        3.0, 2.8, 2.4, 2.1, 2.0, 0.5, 0.7, 0.4, 0.6, 2.4, 3.2, 2.0, 2.4, 0.4, 0.6, 0.15, 0.25,
        sr_b, frr_b, thr_b, 20.0, asr_a, asr_nd, cost, 0.3, 21.0)


def test_realism_gates() -> None:
    rows = [
        _row("1.00", 0.998, 0.002, 0.03, 0.28, 0.62, 1000),
        _row("0.70", 0.991, 0.008, 0.06, 0.27, 0.61, 760),
        _row("0.50", 0.978, 0.012, 0.10, 0.26, 0.59, 680),
        _row("0.35", 0.959, 0.018, 0.16, 0.24, 0.57, 620),
        _row("0.25", 0.942, 0.024, 0.24, 0.23, 0.55, 590),
    ]
    assert_budget_sweep_gates(rows)
