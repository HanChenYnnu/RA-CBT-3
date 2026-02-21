"""Canonical one-command runner."""

from __future__ import annotations

import argparse

from experiments.metrics import compute_metrics
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import synthetic_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run all deterministic stage1 experiments.")
    parser.add_argument("--seed", type=int, default=7)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    print(f"[run_all] deterministic stage1 run; seed={args.seed}")
    events = synthetic_events()
    rows = compute_metrics(events)
    write_report(rows)
    plots = generate_plots(rows)
    print(f"[run_all] wrote results/report.csv and results/report.md from {len(events)} events")
    print(f"[run_all] wrote {len(plots)} SVG plots")


if __name__ == "__main__":
    main()
