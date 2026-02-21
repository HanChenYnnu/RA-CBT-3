"""Harness utilities to execute scenarios against B0 app."""

from __future__ import annotations

import json
import os
from pathlib import Path

from baselines.B0_static.app import create_app
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient


def run_b0_scenario(*, scenario: str, n: int, log_path: Path) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()
    with TestClient(app) as client:
        for req in scenario_requests(scenario, n):
            xff = str(req.get("x_forwarded_for", "10.0.0.10"))
            response = client.post(
                "/v1/chat/completions",
                json=req,
                headers={"X-Forwarded-For": xff},
            )
            _ = response.json()

    # Build metrics from contract logs so tests verify shape.
    logged_events: list[EventRow] = []
    with log_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            logged_events.append(
                EventRow(
                    baseline=record["baseline"],
                    scenario=record["scenario"],
                    status_code=int(record["status_code"]),
                    reason=str(record["reason"]),
                    decision=str(record["decision"]),
                    latency_ms=int(record["latency_ms"]),
                    usage_total_tokens=int(record["usage_total_tokens"]),
                    benign=scenario == "S6_drift",
                )
            )
    return logged_events
