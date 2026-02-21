"""Harness for B1 IP allowlist baseline."""

from __future__ import annotations

import json
import os
from pathlib import Path

from baselines.B1_ip_allowlist.app import create_app
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient


def run_b1_scenario(*, scenario: str, n: int, log_path: Path) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()

    with TestClient(app) as client:
        for req in scenario_requests(scenario, n):
            xff = str(req.get("x_forwarded_for", ""))
            client.post("/v1/chat/completions", json=req, headers={"X-Forwarded-For": xff})

    events: list[EventRow] = []
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            events.append(
                EventRow(
                    baseline=str(record["baseline"]),
                    scenario=str(record["scenario"]),
                    status_code=int(record["status_code"]),
                    reason=str(record["reason"]),
                    decision=str(record["decision"]),
                    latency_ms=int(record["latency_ms"]),
                    usage_total_tokens=int(record["usage_total_tokens"]),
                    benign=scenario == "S6_drift",
                )
            )
    return events
