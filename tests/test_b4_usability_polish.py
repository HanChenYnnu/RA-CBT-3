from pathlib import Path

from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.metrics import compute_b4_risk_evaluation, compute_metrics
from experiments.runner import run_b4_calibration_phase, run_selected


def _rows_for(tmp_path: Path, scenarios: list[str], seed: int = 23):
    run_b4_calibration_phase(out_dir=tmp_path, n=80, seed=seed)
    calibrate(
        benign_path=tmp_path / "raw" / f"seed{seed}_B4_calibration_benign.jsonl",
        attack_path=tmp_path / "raw" / f"seed{seed}_B4_calibration_attack.jsonl",
        output_path=Path("baselines/B4_full/calibration.json"),
    )
    events = run_selected(baselines=["B0", "B4"], scenarios=scenarios, out_dir=tmp_path, seed=seed)
    return compute_metrics(events, b4_eval=compute_b4_risk_evaluation(events))


def _pick(rows, baseline: str, scenario: str):
    return next(r for r in rows if r.baseline == baseline and r.scenario == scenario)


def test_b4_drift_usability(tmp_path: Path) -> None:
    rows = _rows_for(tmp_path, ["S6_drift"])
    b4 = _pick(rows, "B4", "S6_drift")
    b0 = _pick(rows, "B0", "S6_drift")
    assert b4.attack_success_rate_allow_mean >= 0.70
    assert b4.false_reject_rate_mean <= 0.02
    assert 0.15 <= b4.throttle_rate_mean <= 0.60
    assert b4.cost_leakage_tokens_mean <= 1.25 * b0.cost_leakage_tokens_mean


def test_b4_s1_soften(tmp_path: Path) -> None:
    rows = _rows_for(tmp_path, ["S1_key_leak"])
    b4 = _pick(rows, "B4", "S1_key_leak")
    b0 = _pick(rows, "B0", "S1_key_leak")
    assert b4.success_rate_mean >= 0.70
    assert b4.attack_success_rate_allow_mean <= 0.10
    assert b4.attack_success_rate_non_deny_mean >= 0.60
    assert b4.cost_leakage_tokens_mean <= 0.35 * b0.cost_leakage_tokens_mean
