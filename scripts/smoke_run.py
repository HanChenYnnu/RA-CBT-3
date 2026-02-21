"""Synthetic smoke run for B0 integration."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import compute_metrics
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import run_selected


def main() -> None:
    events = run_selected(baselines=["B0"], scenarios=["S4_burst"], out_dir=Path("results"))
    rows = compute_metrics(events)
    write_report(rows)
    plots = generate_plots(rows)
    print(f"[smoke_run] events={len(events)} metric_rows={len(rows)} plots={len(plots)}")


if __name__ == "__main__":
    main()
