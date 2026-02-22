import os
from pathlib import Path

from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.metrics import compute_b4_auroc, compute_b4_calibration_metrics, compute_b4_risk_summary, compute_metrics
from experiments.runner import ensure_coverage, run_b4_calibration_phase, run_selected
from experiments.scenarios import ALL_SCENARIOS
from experiments.types import EventRow


def _run_full(tmp_path: Path, *, seeds: int = 3):
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
                scenarios=ALL_SCENARIOS,
                out_dir=tmp_path,
                seed=seed,
            )
        )
    rows = compute_metrics(events)
    ensure_coverage(rows, ["B0", "B1", "B2", "B3", "B4"], ALL_SCENARIOS)
    return rows, events


def test_security_realism_and_curves(tmp_path: Path) -> None:
    rows, events = _run_full(tmp_path)

    def pick(baseline: str, scenario: str):
        return next(r for r in rows if r.baseline == baseline and r.scenario == scenario)

    # hard security deltas
    assert pick("B2", "S2_token_leak").attack_success_rate_mean >= 0.5
    assert pick("B3", "S2_token_leak").attack_success_rate_mean <= 0.05
    assert pick("B4", "S2_token_leak").attack_success_rate_mean <= 0.05
    assert pick("B3", "S3_replay").attack_success_rate_mean < pick("B2", "S3_replay").attack_success_rate_mean
    assert pick("B4", "S3_replay").attack_success_rate_mean < pick("B2", "S3_replay").attack_success_rate_mean
    assert pick("B4", "S4_burst_L4").cost_leakage_tokens_mean <= pick("B0", "S4_burst_L4").cost_leakage_tokens_mean / 5

    # progressive throttle curve
    assert 0.05 <= pick("B4", "S4_burst_L1").throttle_rate_mean <= 0.6
    assert pick("B4", "S4_burst_L4").throttle_rate_mean >= 0.6
    assert pick("B4", "S4_burst_L1").throttle_rate_mean < 1.0

    # multi-seed std should not be all zero
    stds = [
        pick("B4", "S4_burst_L2").p95_ms_std,
        pick("B4", "S4_burst_L3").throttle_rate_std,
        pick("B4", "S4_burst_L4").cost_leakage_tokens_std,
    ]
    assert any(s > 0.0 for s in stds)

    # latency realism
    assert pick("B0", "S4_burst_L4").p95_ms_mean > pick("B0", "S5_slowdrip").p95_ms_mean
    assert pick("B4", "S2_token_leak").p95_ms_mean > pick("B4", "S2_token_leak").p50_ms_mean

    # risk spread / calibration stats
    auroc, _ = compute_b4_auroc(events)
    brier, ece, bins = compute_b4_calibration_metrics(events)
    assert 0.7 <= auroc <= 1.0
    assert 0.0 <= ece <= 0.5
    assert brier >= 0.0
    assert len(bins) >= 4

    risk_summary = compute_b4_risk_summary(events)
    ad = risk_summary["attack_deny"]
    bo = risk_summary["benign_overall"]
    assert ad["p90"] - ad["p50"] > 0.02
    assert bo["p90"] - bo["p50"] > 0.0


def test_auroc_direction_not_inverted() -> None:
    events = [
        EventRow("B4", "s", 200, "ok", "allow", 10.0, 1, False, 0.1, 1, "benign"),
        EventRow("B4", "s", 200, "ok", "allow", 10.1, 1, False, 0.2, 1, "benign"),
        EventRow("B4", "s", 200, "ok", "allow", 10.2, 1, False, 0.8, 1, "attack"),
        EventRow("B4", "s", 200, "ok", "allow", 10.3, 1, False, 0.9, 1, "attack"),
    ]
    auroc, _ = compute_b4_auroc(events)
    assert auroc > 0.7


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
