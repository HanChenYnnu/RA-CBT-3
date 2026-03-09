from experiments.metrics import MetricRow
from experiments.plots import generate_plots
from experiments.metrics import B4RiskEvaluation


def _row(name: str, cost: float) -> MetricRow:
    return MetricRow("B4", name, 1, 0, 0.3, 0, 0.8, 0, cost, 0, 0, 0, 0.2, 0, 1, 0, 1, 0, 0.5, 0, 0.7, 0, 10, 20, 0.8, 0.7, 0.7, 0.6, 0.1, 0.4, 40, 60, 0.4, 0.3, 0.2, 0.2, 0.3, 0.4, 1.0, 0.8, 0.5)


def test_budget_plots_generated() -> None:
    rows = [_row(f"S4_budget_sweep_x{s}", c) for s, c in [("1.00", 1000.0), ("0.70", 700.0), ("0.50", 500.0), ("0.35", 360.0), ("0.25", 260.0)]]
    ev = B4RiskEvaluation(None, None, None, None, None, None, 0, 0, 0, 0, 0, 0, False, [], [], [], [], [], [], [], [], None, None, 0.5, 0, 0, 0, 0)
    paths = generate_plots(rows, b4_eval=ev)
    names = {p.name for p in paths}
    assert "b4_budget_cost_vs_asr_allow.svg" in names
    assert "b4_budget_cost_vs_asr_non_deny.svg" in names
    assert "b4_budget_cost_vs_throttle.svg" in names
