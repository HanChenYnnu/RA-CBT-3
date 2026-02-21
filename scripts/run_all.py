"""Canonical one-command runner."""

from __future__ import annotations

import argparse
from pathlib import Path

from experiments.metrics import compute_metrics
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import run_selected
from experiments.scenarios import SCENARIOS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic experiments.")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--baselines", default="B0,B1,B2,B3,B4")
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
    events = run_selected(baselines=baselines, scenarios=scenarios, out_dir=out_dir)
    rows = compute_metrics(events)
    write_report(rows)
    plots = generate_plots(rows)
    print(f"[run_all] events={len(events)} rows={len(rows)} plots={len(plots)}")


if __name__ == "__main__":
    main()
