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
    events: list[EventRow] = []
    with TestClient(app) as client:
        for index, req in enumerate(scenario_requests(scenario, n), start=1):
            response = client.post("/v1/chat/completions", json=req)
            body = response.json()
            events.append(
                EventRow(
                    baseline="B0",
                    scenario=scenario,
                    status_code=response.status_code,
                    reason="ok" if response.status_code == 200 else "upstream_error",
                    decision="allow" if response.status_code == 200 else "deny",
                    latency_ms=1 + (index % 7),
                    usage_total_tokens=int(body.get("usage", {}).get("total_tokens", 0)),
                    benign=False,
                )
            )

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
                    benign=False,
                )
            )
    return logged_events
