"""Smoke run with small-N but enforced deltas."""

from __future__ import annotations

from pathlib import Path

from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.metrics import compute_b4_auroc, compute_metrics
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import run_b4_calibration_phase, run_selected


def main() -> None:
    out = Path("results")
    seed = 11
    run_b4_calibration_phase(out_dir=out, n=40, seed=seed)
    calibrate(
        benign_path=out / "raw" / f"seed{seed}_B4_calibration_benign.jsonl",
        attack_path=out / "raw" / f"seed{seed}_B4_calibration_attack.jsonl",
        output_path=Path("baselines/B4_full/calibration.json"),
    )

    scenarios = ["S1_key_leak", "S2_token_leak", "S3_replay", "S4_burst", "S5_slowdrip", "S6_drift"]
    baselines = ["B0", "B1", "B2", "B3", "B4"]
    events = run_selected(baselines=baselines, scenarios=scenarios, out_dir=out, seed=seed)
    rows = compute_metrics(events)

    def pick(b: str, s: str):
        return next(r for r in rows if r.baseline == b and r.scenario == s)

    assert pick("B2", "S2_token_leak").attack_success_rate_allow_mean >= 0.5
    assert pick("B3", "S2_token_leak").attack_success_rate_allow_mean <= 0.05
    assert pick("B4", "S2_token_leak").attack_success_rate_allow_mean <= 0.05

    assert pick("B3", "S1_key_leak").attack_success_rate_allow_mean >= 0.8
    assert pick("B4", "S1_key_leak").attack_success_rate_allow_mean <= 0.4

    assert pick("B4", "S4_burst").cost_leakage_tokens_mean <= pick("B0", "S4_burst").cost_leakage_tokens_mean / 5

    auroc, roc = compute_b4_auroc(events)
    write_report(rows, seeds=1, calibration=None, b4_auroc=auroc)
    plots = generate_plots(rows, roc_points=roc)
    print(f"[smoke_run] events={len(events)} rows={len(rows)} plots={len(plots)} auroc={auroc:.4f}")


if __name__ == "__main__":
    main()
