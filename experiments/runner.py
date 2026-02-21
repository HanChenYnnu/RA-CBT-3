"""Experiment runner orchestration."""

from __future__ import annotations

from pathlib import Path

from baselines.B0_static.harness import run_b0_scenario
from baselines.B1_ip_allowlist.harness import run_b1_scenario
from baselines.B2_bearer_short.harness import run_b2_scenario
from baselines.B3_pop_only.harness import run_b3_scenario
from baselines.B4_full.harness import run_b4_calibration, run_b4_scenario
from experiments.scenarios import ALL_SCENARIOS, SCENARIOS
from experiments.types import EventRow


def planned_baselines() -> list[str]:
    return ["B0", "B1", "B2", "B3", "B4"]




def _baseline_supports_scenario(baseline: str, scenario: str) -> bool:
    return baseline in planned_baselines() and scenario in ALL_SCENARIOS


def ensure_coverage(rows: list[object], baselines: list[str], scenarios: list[str]) -> None:
    existing = {(getattr(r, "baseline"), getattr(r, "scenario")) for r in rows}
    expected = {
        (baseline, scenario)
        for baseline in baselines
        for scenario in scenarios
        if _baseline_supports_scenario(baseline, scenario)
    }
    missing = sorted(expected - existing)
    if missing:
        names = ", ".join(f"{b}/{s}" for b, s in missing)
        raise RuntimeError(f"Coverage gate failed; missing baseline/scenario rows: {names}")


def run_selected(*, baselines: list[str], scenarios: list[str], out_dir: Path) -> list[EventRow]:
    events: list[EventRow] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    unknown = sorted(set(scenarios) - set(ALL_SCENARIOS))
    if unknown:
        raise ValueError(f"Unknown scenarios: {unknown}")

    for baseline in baselines:
        for scenario in scenarios:
            n = SCENARIOS.get(scenario, 0)
            if n <= 0:
                continue
            log_path = raw_dir / f"{baseline}_{scenario}.jsonl"
            if log_path.exists():
                log_path.unlink()

            if not _baseline_supports_scenario(baseline, scenario):
                continue

            if baseline == "B0":
                events.extend(run_b0_scenario(scenario=scenario, n=n, log_path=log_path))
            elif baseline == "B1":
                events.extend(run_b1_scenario(scenario=scenario, n=n, log_path=log_path))
            elif baseline == "B2":
                events.extend(run_b2_scenario(scenario=scenario, n=n, log_path=log_path))
            elif baseline == "B3":
                events.extend(run_b3_scenario(scenario=scenario, n=n, log_path=log_path))
            elif baseline == "B4":
                events.extend(run_b4_scenario(scenario=scenario, n=n, log_path=log_path))

    return events


def run_b4_calibration_phase(out_dir: Path, n: int = 100) -> None:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    log_path = raw_dir / "B4_calibration.jsonl"
    if log_path.exists():
        log_path.unlink()
    run_b4_calibration(n=n, log_path=log_path)
