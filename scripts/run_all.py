"""Canonical one-command runner."""

from __future__ import annotations

import argparse
from pathlib import Path

from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.metrics import compute_metrics
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import planned_baselines, run_b4_calibration_phase, run_selected
from experiments.scenarios import SCENARIOS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic experiments.")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--baselines", default=",".join(planned_baselines()))
    parser.add_argument("--scenarios", default=",".join(SCENARIOS.keys()))
    parser.add_argument("--out-dir", default="results")
    return parser


def _csv_arg(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def main() -> None:
    args = build_parser().parse_args()
    baselines = _csv_arg(args.baselines)
    scenarios = _csv_arg(args.scenarios)
    out_dir = Path(args.out_dir)

    print(f"[run_all] seed={args.seed} baselines={baselines} scenarios={scenarios}")

    if "B4" in baselines:
        run_b4_calibration_phase(out_dir=out_dir, n=120)
        thresholds = calibrate(
            input_path=out_dir / "raw" / "B4_calibration.jsonl",
            output_path=Path("baselines/B4_full/calibration.json"),
        )
        print(f"[run_all] calibrated B4 thresholds: {thresholds}")

    events = run_selected(baselines=baselines, scenarios=scenarios, out_dir=out_dir)
    rows = compute_metrics(events)
    write_report(rows)
    plots = generate_plots(rows)
    print(f"[run_all] events={len(events)} rows={len(rows)} plots={len(plots)}")


if __name__ == "__main__":
    main()
