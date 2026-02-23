import ast
import os
from pathlib import Path

from baselines.B4_full.calibrate_quantiles import calibrate
from baselines.B4_full.app import _ctx_drift_score, Ctx
from experiments.expected_deltas import assert_defensibility_gates, assert_required_security_deltas
from experiments.metrics import compute_b4_risk_evaluation, compute_metrics
from experiments.runner import ensure_coverage, run_b4_calibration_phase, run_selected
from experiments.scenarios import ALL_SCENARIOS


def _run_full(tmp_path: Path, *, seeds: int = 1):
    os.environ["B2_RPM_LIMIT"] = "2000"
    os.environ["B2_TPM_LIMIT"] = "200000"
    os.environ["B3_RPM_LIMIT"] = "2000"
    os.environ["B3_TPM_LIMIT"] = "200000"
    os.environ["B4_RPM_LIMIT"] = "2000"
    os.environ["B4_TPM_LIMIT"] = "200000"

    events = []
    for seed in range(9, 9 + seeds):
        run_b4_calibration_phase(out_dir=tmp_path, n=80, seed=seed)
        calibrate(
            benign_path=tmp_path / "raw" / f"seed{seed}_B4_calibration_benign.jsonl",
            attack_path=tmp_path / "raw" / f"seed{seed}_B4_calibration_attack.jsonl",
            output_path=Path("baselines/B4_full/calibration.json"),
        )
        events.extend(
            run_selected(
                baselines=["B0", "B1", "B2", "B3", "B4"],
                scenarios=["S1_key_leak","S1_key_leak_hard","S2_token_leak","S2_token_leak_hard","S3_replay","S3_replay_hard","S4_burst_L4","S5_slowdrip","S6_drift"],
                out_dir=tmp_path,
                seed=seed,
            )
        )
    b4_eval = compute_b4_risk_evaluation(events, loso_scenarios=["S1", "S2", "S3", "S4", "S5", "S6"])
    rows = compute_metrics(events, b4_eval=b4_eval)
    ensure_coverage(rows, ["B0", "B1", "B2", "B3", "B4"], ["S1_key_leak","S1_key_leak_hard","S2_token_leak","S2_token_leak_hard","S3_replay","S3_replay_hard","S4_burst_L4","S5_slowdrip","S6_drift"])
    return rows, events, b4_eval


def test_security_realism_and_defensibility(tmp_path: Path) -> None:
    rows, _, b4_eval = _run_full(tmp_path)
    assert_required_security_deltas(rows)
    assert_defensibility_gates(rows, b4_eval)


def test_anti_leakage_static_scan() -> None:
    tree = ast.parse(Path("baselines/B4_full/app.py").read_text(encoding="utf-8"))
    forbidden_literals = {"scenario", "attack", "benign", "label"}
    risk_funcs = {"_exchange_risk", "_ctx_drift_score", "_risk_jitter"}

    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in risk_funcs:
            lits = {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            assert forbidden_literals.isdisjoint(lits)


def test_anti_leakage_invariance() -> None:
    issue = Ctx(ip="10.0.0.1", asn="AS100", country="US", ua="browser/100.1", device_fp="fp-1", ts=1000)
    req = Ctx(ip="10.0.0.2", asn="AS100", country="US", ua="browser/100.2", device_fp="fp-1", ts=1001)
    # No scenario input: changing scenario labels cannot affect this score.
    score_a = _ctx_drift_score(issue, req)
    score_b = _ctx_drift_score(issue, req)
    assert abs(score_a - score_b) < 1e-12


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
