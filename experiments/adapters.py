"""Baseline adapter utilities for consistent scenario semantics."""

from __future__ import annotations

import json
from pathlib import Path

from experiments.scenarios import BENIGN_SCENARIOS
from experiments.types import EventRow


def scenario_label(scenario: str) -> str:
    return "benign" if scenario in BENIGN_SCENARIOS else "attack"


def read_events_from_log(*, log_path: Path, scenario: str, seed: int) -> list[EventRow]:
    label = scenario_label(scenario)
    benign = label == "benign"
    out: list[EventRow] = []
    if not log_path.exists():
        return []
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            out.append(
                EventRow(
                    baseline=str(record["baseline"]),
                    scenario=str(record["scenario"]),
                    status_code=int(record["status_code"]),
                    reason=str(record["reason"]),
                    decision=str(record["decision"]),
                    latency_ms=int(record["latency_ms"]),
                    usage_total_tokens=int(record["usage_total_tokens"]),
                    benign=benign,
                    risk=float(record.get("risk", -1.0)),
                    seed=seed,
                    label=label,
                )
            )
    return out
