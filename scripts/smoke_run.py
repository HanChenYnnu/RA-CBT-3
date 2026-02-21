"""Synthetic smoke run for stage1 harness."""

from __future__ import annotations

from experiments.metrics import compute_metrics
from experiments.plots import generate_plots
from experiments.report import write_report
from experiments.runner import synthetic_events


def main() -> None:
    events = synthetic_events()[:8]
    rows = compute_metrics(events)
    write_report(rows)
    plots = generate_plots(rows)
    print(f"[smoke_run] events={len(events)} metric_rows={len(rows)} plots={len(plots)}")


if __name__ == "__main__":
    main()
