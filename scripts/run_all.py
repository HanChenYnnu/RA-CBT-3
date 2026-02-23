"""Canonical one-command runner."""

from __future__ import annotations

import argparse
import subprocess
from glob import glob
from pathlib import Path

from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.expected_deltas import assert_defensibility_gates, assert_required_security_deltas
from experiments.metrics import compute_b4_risk_evaluation, compute_b4_risk_summary, compute_metrics
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import ensure_coverage, planned_baselines, run_b4_calibration_phase, run_selected
from experiments.scenarios import SCENARIOS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic experiments.")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--seeds", type=int, default=1)
    parser.add_argument("--baselines", default=",".join(planned_baselines()))
    parser.add_argument("--scenarios", default=",".join(SCENARIOS.keys()))
    parser.add_argument("--out-dir", default="results")
    parser.add_argument("--publish-results", default="false")
    return parser


def _csv_arg(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"Invalid boolean value: {value}")


def _publish_results() -> None:
    svg_paths = sorted(glob("results/plots/*.svg"))
    if len(svg_paths) < 5:
        raise RuntimeError("Expected at least 5 SVG plots before publish")
    paths = ["results/report.csv", "results/report.md", *svg_paths]
    subprocess.run(["git", "add", *paths], check=True)
    status = subprocess.run(["git", "diff", "--cached", "--quiet"], check=False)
    if status.returncode == 0:
        print("[run_all] publish-results enabled but no result changes to commit")
        return
    subprocess.run(["git", "commit", "-m", "results: update report and svg plots"], check=True)


def main() -> None:
    args = build_parser().parse_args()
    baselines = _csv_arg(args.baselines)
    scenarios = _csv_arg(args.scenarios)
    out_dir = Path(args.out_dir)
    publish_results = _parse_bool(args.publish_results)
    seeds = [args.seed + i for i in range(max(1, args.seeds))]

    import os
    os.environ.setdefault("B2_RPM_LIMIT", "5000")
    os.environ.setdefault("B2_TPM_LIMIT", "500000")
    os.environ.setdefault("B3_RPM_LIMIT", "5000")
    os.environ.setdefault("B3_TPM_LIMIT", "500000")
    os.environ.setdefault("B4_RPM_LIMIT", "5000")
    os.environ.setdefault("B4_TPM_LIMIT", "500000")

    all_events = []
    calibration_summary: dict[str, float] | None = None
    for seed in seeds:
        if "B4" in baselines:
            run_b4_calibration_phase(out_dir=out_dir, n=120, seed=seed)
            calibration_summary = calibrate(
                benign_path=out_dir / "raw" / f"seed{seed}_B4_calibration_benign.jsonl",
                attack_path=out_dir / "raw" / f"seed{seed}_B4_calibration_attack.jsonl",
                output_path=Path("baselines/B4_full/calibration.json"),
            )
        all_events.extend(run_selected(baselines=baselines, scenarios=scenarios, out_dir=out_dir, seed=seed))

    b4_eval = compute_b4_risk_evaluation(all_events, loso_scenarios=["S1", "S2", "S3", "S4", "S5", "S6"])
    rows = compute_metrics(all_events, b4_eval=b4_eval)
    ensure_coverage(rows, baselines, scenarios)
    assert_required_security_deltas(rows)
    assert_defensibility_gates(rows, b4_eval)

    risk_summary = compute_b4_risk_summary(all_events)
    write_report(rows, seeds=len(seeds), b4_eval=b4_eval, calibration=calibration_summary, risk_summary=risk_summary)
    plots = generate_plots(rows, b4_eval=b4_eval)
    print(f"[run_all] events={len(all_events)} rows={len(rows)} plots={len(plots)} overall_auroc={b4_eval.overall_auroc:.4f} overall_pr={b4_eval.overall_pr_auc:.4f}")

    if publish_results:
        _publish_results()


if __name__ == "__main__":
    main()
