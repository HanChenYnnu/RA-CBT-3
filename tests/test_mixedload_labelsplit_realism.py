import pytest

from experiments.expected_deltas import assert_budget_sweep_gates
from experiments.metrics import MetricRow


def _row(scale: str, sr_b: float, frr_b: float, thr_b: float, asr_a: float, asr_nd: float, cost: float) -> MetricRow:
    return MetricRow(
        "B4", f"S4_mixedload_sweep_x{scale}", 1, 0, 0.2, 0, 0.6, 0, 100, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0.5, 0, 0.6, 0, 1, 1,
        0.8, 0.7, 0.7, 0.6, 0.1, 0.2, 300, 100, 200,
        0.7, 0.6, 0.55, 0.5, 0.45, 0.1, 0.2, 0.3, 0.4, 0.5,
        3.0, 2.8, 2.4, 2.1, 2.0,
        0.5, 0.7, 0.4, 0.6, 2.4, 3.2, 2.0, 2.4, 0.4, 0.6, 0.15, 0.25,
        sr_b, frr_b, thr_b, 20.0, asr_a, asr_nd, cost, 0.3, 21.0,
    )


def test_labelsplit_realism_gate_rejects_missing_controlled_point() -> None:
    rows = [
        _row("1.00", 1.0, 0.0, 0.0, 0.28, 0.62, 1000),
        _row("0.70", 1.0, 0.0, 0.0, 0.26, 0.60, 800),
        _row("0.50", 1.0, 0.0, 0.0, 0.24, 0.58, 680),
        _row("0.35", 0.999, 0.0, 0.01, 0.23, 0.56, 620),
        _row("0.25", 0.998, 0.0, 0.02, 0.22, 0.54, 590),
    ]
    with pytest.raises(AssertionError):
        assert_budget_sweep_gates(rows)
