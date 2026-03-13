"""Canonical one-command runner."""

from __future__ import annotations

import argparse
import subprocess
from glob import glob
from pathlib import Path

from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.expected_deltas import assert_budget_sweep_gates, assert_defensibility_gates, assert_required_security_deltas
from experiments.metrics import compute_b4_risk_evaluation, compute_b4_risk_summary, compute_b4_vs_b2_served_deltas, compute_decision_latency_stats, compute_metrics, compute_served_slices_for_baseline
from experiments.budget_sweep import run_b4_budget_sweep
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import ensure_coverage, planned_baselines, run_b4_calibration_phase, run_selected
from experiments.preflight import validate_contracts_declared, validate_from_audit_file, validate_served_traffic_preflight
from experiments.scenario_audit import reset_audit
from experiments.scenarios import SCENARIOS


LOSO_GROUPS = {
    "S1_pair": ["S1_key_leak_hard", "S1_restricted_issuance_hard", "S1_benign_control_hard"],
    "S2_pair": ["S2_token_leak_hard", "S2_delegated_misuse_hard", "S2_benign_control_hard"],
    "S3_pair": ["S3_replay_hard", "S3_replay_nearmiss_hard", "S3_replay_blended_hard", "S3_benign_control_hard"],
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run deterministic experiments.")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--seeds", type=int, default=1)
    p.add_argument("--baselines", default=",".join(planned_baselines()))
    p.add_argument("--scenarios", default=",".join(SCENARIOS.keys()))
    p.add_argument("--out-dir", default="results")
    p.add_argument("--publish-results", default="false")
    return p


def _csv_arg(value: str) -> list[str]:
    return [i.strip() for i in value.split(",") if i.strip()]


def _parse_bool(value: str) -> bool:
    n = value.strip().lower()
    if n in {"1", "true", "yes", "y", "on"}:
        return True
    if n in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"Invalid boolean value: {value}")


def _publish_results() -> None:
    svg_paths = sorted(glob("results/plots/*.svg"))
    if len(svg_paths) < 5:
        raise RuntimeError("Expected at least 5 SVG plots before publish")
    paths = ["results/report.csv", "results/report.md", *svg_paths]
    subprocess.run(["git", "add", *paths], check=True)
    if subprocess.run(["git", "diff", "--cached", "--quiet"], check=False).returncode != 0:
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

    reset_audit()
    validate_contracts_declared(baselines=baselines, scenarios=scenarios, seed=seeds[0], n_by_scenario=SCENARIOS)
    events = []
    calibration_summary: dict[str, float] | None = None
    for seed in seeds:
        if "B4" in baselines:
            run_b4_calibration_phase(out_dir=out_dir, n=120, seed=seed)
            calibration_summary = calibrate(
                benign_path=out_dir / "raw" / f"seed{seed}_B4_calibration_benign.jsonl",
                attack_path=out_dir / "raw" / f"seed{seed}_B4_calibration_attack.jsonl",
                output_path=Path("baselines/B4_full/calibration.json"),
            )
        events.extend(run_selected(baselines=baselines, scenarios=scenarios, out_dir=out_dir, seed=seed))
        if "B4" in baselines:
            events.extend(run_b4_budget_sweep(out_dir=out_dir, seed=seed))

    validate_from_audit_file()
    validate_served_traffic_preflight(events)
    b4_eval = compute_b4_risk_evaluation(events, loso_groups=LOSO_GROUPS)
    rows = compute_metrics(events, b4_eval=b4_eval)
    ensure_coverage(rows, baselines, scenarios)
    b2_served = compute_served_slices_for_baseline(events, baseline="B2", groups=LOSO_GROUPS)
    b4_b2_deltas = compute_b4_vs_b2_served_deltas(events, groups=LOSO_GROUPS)
    assert_required_security_deltas(rows)
    assert_defensibility_gates(rows, b4_eval, b2_served=b2_served, b4_b2_deltas=b4_b2_deltas)
    assert_budget_sweep_gates(rows)

    risk_summary = compute_b4_risk_summary(events)
    decision_latency = compute_decision_latency_stats(events, ["B4", "B3"])
    write_report(rows, seeds=len(seeds), b4_eval=b4_eval, calibration=calibration_summary, risk_summary=risk_summary, decision_latency=decision_latency, b2_served=b2_served, b4_b2_deltas=b4_b2_deltas)
    plots = generate_plots(rows, b4_eval=b4_eval, b2_served=b2_served, b4_b2_deltas=b4_b2_deltas)
    print(f"[run_all] events={len(events)} rows={len(rows)} plots={len(plots)} overall_auroc={b4_eval.overall_auroc}")

    if publish_results:
        _publish_results()


if __name__ == "__main__":
    main()
