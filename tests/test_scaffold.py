from pathlib import Path
import os

from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.expected_deltas import assert_defensibility_gates, assert_required_security_deltas
from experiments.metrics import compute_b4_risk_evaluation, compute_b4_vs_b2_served_deltas, compute_metrics, compute_served_slices_for_baseline
from experiments.runner import ensure_coverage, run_b4_calibration_phase, run_selected
from scripts.run_all import LOSO_GROUPS
from experiments.scenarios import ALL_SCENARIOS


def _run_full(tmp_path: Path):
    os.environ["B2_RPM_LIMIT"] = os.environ["B3_RPM_LIMIT"] = os.environ["B4_RPM_LIMIT"] = "2000"
    os.environ["B2_TPM_LIMIT"] = os.environ["B3_TPM_LIMIT"] = os.environ["B4_TPM_LIMIT"] = "200000"

    seed = 9
    run_b4_calibration_phase(out_dir=tmp_path, n=80, seed=seed)
    calibrate(
        benign_path=tmp_path / "raw" / f"seed{seed}_B4_calibration_benign.jsonl",
        attack_path=tmp_path / "raw" / f"seed{seed}_B4_calibration_attack.jsonl",
        output_path=Path("baselines/B4_full/calibration.json"),
    )
    events = run_selected(baselines=["B0", "B1", "B2", "B3", "B4"], scenarios=ALL_SCENARIOS, out_dir=tmp_path, seed=seed)
    b4_eval = compute_b4_risk_evaluation(events)
    rows = compute_metrics(events, b4_eval=b4_eval)
    ensure_coverage(rows, ["B0", "B1", "B2", "B3", "B4"], ALL_SCENARIOS)
    b2_served = compute_served_slices_for_baseline(events, baseline="B2", groups=LOSO_GROUPS)
    deltas = compute_b4_vs_b2_served_deltas(events, groups=LOSO_GROUPS, bootstrap_n=50)
    return rows, b4_eval, b2_served, deltas


def test_security_and_gates(tmp_path: Path) -> None:
    rows, b4_eval, b2_served, deltas = _run_full(tmp_path)
    assert_required_security_deltas(rows)
    assert_defensibility_gates(rows, b4_eval, b2_served=b2_served, b4_b2_deltas=deltas)


def test_coverage_gate_fails_on_missing() -> None:
    class Row:
        def __init__(self, baseline: str, scenario: str):
            self.baseline = baseline
            self.scenario = scenario

    try:
        ensure_coverage([Row("B0", "S1_key_leak")], ["B0", "B1"], ["S1_key_leak"])
    except RuntimeError:
        pass
    else:
        raise AssertionError("coverage gate should fail")
