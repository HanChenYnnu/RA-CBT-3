from pathlib import Path

from scripts.run_all import check_budget_gates, run_budget_sweep, write_outputs, synthesize_samples, compute_row, BURST_LEVELS, SCENARIOS


def test_budget_sweep_has_expected_rows_and_passes_gate(tmp_path, monkeypatch):
    rows = run_budget_sweep()
    assert 4 <= len(rows) <= 5
    check_budget_gates(rows)


def test_budget_plots_are_generated(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    samples = synthesize_samples(42)
    core_rows = [compute_row(samples, burst, scenario) for burst in BURST_LEVELS for scenario in SCENARIOS]
    sweep_rows = run_budget_sweep()
    write_outputs(core_rows, sweep_rows, samples)
    plots = Path("results/plots")
    assert (plots / "pareto_cost_vs_asr_allow.svg").exists()
    assert (plots / "pareto_cost_vs_asr_non_deny.svg").exists()
    assert (plots / "pareto_cost_vs_throttle.svg").exists()
