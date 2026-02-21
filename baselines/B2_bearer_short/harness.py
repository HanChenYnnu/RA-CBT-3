"""Harness for B2 short bearer baseline."""

from __future__ import annotations

import json
import os
from pathlib import Path

from baselines.B2_bearer_short.app import create_app
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

USER_KEY = "user-key-demo"


def run_b2_scenario(*, scenario: str, n: int, log_path: Path) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()

    with TestClient(app) as client:
        exchange = client.post(
            "/auth/exchange",
            json={},
            headers={"Authorization": f"Bearer {USER_KEY}"},
        )
        access_token = exchange.json()["access_token"]

        # Attacker steals short-lived access token and directly calls chat endpoint.
        for req in scenario_requests(scenario, n):
            client.post(
                "/v1/chat/completions",
                json=req,
                headers={"Authorization": f"Bearer {access_token}"},
            )

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
                    benign=False,
                )
            )
    return events
