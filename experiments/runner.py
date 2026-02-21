"""Experiment runner orchestration."""

from __future__ import annotations

from pathlib import Path

from baselines.B0_static.harness import run_b0_scenario
from baselines.B1_ip_allowlist.harness import run_b1_scenario
from baselines.B2_bearer_short.harness import run_b2_scenario
from experiments.scenarios import SCENARIOS
from experiments.types import EventRow


def planned_baselines() -> list[str]:
    return ["B0", "B1", "B2", "B3", "B4"]


def run_selected(*, baselines: list[str], scenarios: list[str], out_dir: Path) -> list[EventRow]:
    events: list[EventRow] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    for baseline in baselines:
        for scenario in scenarios:
            n = SCENARIOS.get(scenario, 0)
            if n <= 0:
                continue
            if baseline == "B0" and scenario not in {"S4_burst", "S6_drift"}:
                continue
            if baseline == "B1" and scenario != "S6_drift":
                continue
            if baseline == "B2" and scenario != "S2_token_leak":
                continue

            log_path = raw_dir / f"{baseline}_{scenario}.jsonl"
            if log_path.exists():
                log_path.unlink()

            if baseline == "B0":
                events.extend(run_b0_scenario(scenario=scenario, n=n, log_path=log_path))
            elif baseline == "B1":
                events.extend(run_b1_scenario(scenario=scenario, n=n, log_path=log_path))
            elif baseline == "B2":
                events.extend(run_b2_scenario(scenario=scenario, n=n, log_path=log_path))
    return events
