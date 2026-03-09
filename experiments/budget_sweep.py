"""B4 budget sweep experiment helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from baselines.B4_full.harness import run_b4_scenario
from experiments.types import EventRow

SCALES = [1.00, 0.70, 0.50, 0.35, 0.25]
SWEEP_COUNTS = {"S3_replay_nearmiss_hard": 24, "S1_key_leak_hard": 24, "S3_benign_control_hard": 96}


@dataclass(frozen=True)
class SweepGateRow:
    scale: float
    scenario: str
    cost: float
    asr_allow: float
    asr_non_deny: float
    throttle_rate: float


def _scaled(base: int, scale: float) -> int:
    return max(1, int(round(base * scale)))


def run_b4_budget_sweep(*, out_dir: Path, seed: int) -> list[EventRow]:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    prior = {
        "B4_RPM_LIMIT": os.environ.get("B4_RPM_LIMIT"),
        "B4_TPM_LIMIT": os.environ.get("B4_TPM_LIMIT"),
        "B4_MAXTOK_SCALE": os.environ.get("B4_MAXTOK_SCALE"),
    }

    sweep_events: list[EventRow] = []
    for scale in SCALES:
        os.environ["B4_RPM_LIMIT"] = str(_scaled(5000, scale))
        os.environ["B4_TPM_LIMIT"] = str(_scaled(500000, scale))
        os.environ["B4_MAXTOK_SCALE"] = f"{scale:.2f}"
        sweep_name = f"S4_budget_sweep_x{scale:.2f}"

        for src, n in SWEEP_COUNTS.items():
            log_path = raw_dir / f"seed{seed}_B4_{sweep_name}_{src}.jsonl"
            events = run_b4_scenario(scenario=src, n=n, log_path=log_path, seed=seed)
            sweep_events.extend([
                EventRow(
                    baseline=e.baseline,
                    scenario=sweep_name,
                    status_code=e.status_code,
                    reason=e.reason,
                    decision=e.decision,
                    latency_ms=e.latency_ms,
                    usage_total_tokens=e.usage_total_tokens,
                    benign=e.benign,
                    risk=e.risk,
                    seed=e.seed,
                    label=e.label,
                )
                for e in events
            ])

    for k, v in prior.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return sweep_events
