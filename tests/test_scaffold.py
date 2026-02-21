from experiments.expected_deltas import assert_required_deltas
from experiments.metrics import attack_success_rate
from experiments.runner import planned_baselines, synthetic_rows
from experiments.scenarios import SCENARIOS


def test_baseline_list() -> None:
    assert planned_baselines() == ["B0", "B1", "B2", "B3", "B4"]


def test_scenario_minimums() -> None:
    assert SCENARIOS["S4_burst"] >= 1000
    assert SCENARIOS["S5_slowdrip"] >= 300


def test_attack_success_rate() -> None:
    assert attack_success_rate(3, 6) == 0.5


def test_required_deltas() -> None:
    assert_required_deltas(synthetic_rows())
