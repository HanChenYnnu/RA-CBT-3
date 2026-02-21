"""Canonical one-command runner."""

from __future__ import annotations

import argparse
import subprocess
from glob import glob
from pathlib import Path

from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.metrics import compute_metrics
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import ensure_coverage, planned_baselines, run_b4_calibration_phase, run_selected
from experiments.scenarios import SCENARIOS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic experiments.")
    parser.add_argument("--seed", type=int, default=7)
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
    if len(svg_paths) < 3:
        raise RuntimeError("Expected at least 3 SVG plots before publish")

    paths = ["results/report.csv", "results/report.md", *svg_paths]
    subprocess.run(["git", "add", *paths], check=True)

    status = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        check=False,
    )
    if status.returncode == 0:
        print("[run_all] publish-results enabled but no result changes to commit")
        return

    subprocess.run(
        ["git", "commit", "-m", "results: update report and svg plots"],
        check=True,
    )
    print("[run_all] committed refreshed results artifacts")

def main() -> None:
    args = build_parser().parse_args()
    baselines = _csv_arg(args.baselines)
    scenarios = _csv_arg(args.scenarios)
    out_dir = Path(args.out_dir)
    publish_results = _parse_bool(args.publish_results)

    print(
        f"[run_all] seed={args.seed} baselines={baselines} scenarios={scenarios} "
        f"publish_results={publish_results}"
    )

    if "B4" in baselines:
        run_b4_calibration_phase(out_dir=out_dir, n=120)
        thresholds = calibrate(
            input_path=out_dir / "raw" / "B4_calibration.jsonl",
            output_path=Path("baselines/B4_full/calibration.json"),
        )
        print(f"[run_all] calibrated B4 thresholds: {thresholds}")

    events = run_selected(baselines=baselines, scenarios=scenarios, out_dir=out_dir)
    rows = compute_metrics(events)
    ensure_coverage(rows, baselines, scenarios)
    write_report(rows)
    plots = generate_plots(rows)
    print(f"[run_all] events={len(events)} rows={len(rows)} plots={len(plots)}")

    if publish_results:
        _publish_results()


if __name__ == "__main__":
    main()
