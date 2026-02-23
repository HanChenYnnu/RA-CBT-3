"""Experiment runner orchestration with strict adapter coverage."""

from __future__ import annotations

import os
from pathlib import Path

from baselines.B0_static.harness import run_b0_scenario
from baselines.B1_ip_allowlist.harness import run_b1_scenario
from baselines.B2_bearer_short.harness import run_b2_scenario
from baselines.B3_pop_only.harness import run_b3_scenario
from baselines.B4_full.harness import run_b4_calibration, run_b4_scenario
from experiments.scenario_contract import scenario_manifest
from experiments.scenarios import ALL_SCENARIOS, SCENARIOS
from experiments.types import EventRow


def planned_baselines() -> list[str]:
    return ["B0", "B1", "B2", "B3", "B4"]


def ensure_coverage(rows: list[object], baselines: list[str], scenarios: list[str]) -> None:
    existing = {(getattr(r, "baseline"), getattr(r, "scenario")) for r in rows}
    expected = {(b, s) for b in baselines for s in scenarios}
    missing = sorted(expected - existing)
    if missing:
        names = ", ".join(f"{b}/{s}" for b, s in missing)
        raise RuntimeError(f"Coverage gate failed; missing baseline/scenario rows: {names}")


def preflight_validate(*, baselines: list[str], scenarios: list[str], seed: int) -> None:
    for baseline in baselines:
        for scenario in scenarios:
            n = SCENARIOS.get(scenario, 0)
            scenario_manifest(scenario=scenario, baseline=baseline, seed=seed, n=n)


def run_selected(*, baselines: list[str], scenarios: list[str], out_dir: Path, seed: int) -> list[EventRow]:
    events: list[EventRow] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    os.environ["EXPERIMENT_SEED"] = str(seed)

    unknown = sorted(set(scenarios) - set(ALL_SCENARIOS))
    if unknown:
        raise ValueError(f"Unknown scenarios: {unknown}")

    preflight_validate(baselines=baselines, scenarios=scenarios, seed=seed)

    for baseline in baselines:
        for scenario in scenarios:
            n = SCENARIOS.get(scenario, 0)
            log_path = raw_dir / f"seed{seed}_{baseline}_{scenario}.jsonl"
            if log_path.exists():
                log_path.unlink()

            if baseline == "B0":
                events.extend(run_b0_scenario(scenario=scenario, n=n, log_path=log_path, seed=seed))
            elif baseline == "B1":
                events.extend(run_b1_scenario(scenario=scenario, n=n, log_path=log_path, seed=seed))
            elif baseline == "B2":
                events.extend(run_b2_scenario(scenario=scenario, n=n, log_path=log_path, seed=seed))
            elif baseline == "B3":
                events.extend(run_b3_scenario(scenario=scenario, n=n, log_path=log_path, seed=seed))
            elif baseline == "B4":
                events.extend(run_b4_scenario(scenario=scenario, n=n, log_path=log_path, seed=seed))

    return events


def run_b4_calibration_phase(out_dir: Path, n: int, seed: int) -> None:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    benign = raw_dir / f"seed{seed}_B4_calibration_benign.jsonl"
    attack = raw_dir / f"seed{seed}_B4_calibration_attack.jsonl"
    if benign.exists():
        benign.unlink()
    if attack.exists():
        attack.unlink()
    os.environ["EXPERIMENT_SEED"] = str(seed)
    run_b4_calibration(n=n, benign_log_path=benign, attack_log_path=attack, seed=seed)
