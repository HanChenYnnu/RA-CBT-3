"""Harness for B1 IP allowlist baseline."""

from __future__ import annotations

import os
from pathlib import Path

from baselines.B1_ip_allowlist.app import create_app
from experiments.adapters import read_events_from_log
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient


def run_b1_scenario(*, scenario: str, n: int, log_path: Path, seed: int) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()
    with TestClient(app) as client:
        for req in scenario_requests(scenario, n, seed=seed):
            xff = str(req.get("x_forwarded_for", "10.0.0.10"))
            client.post("/v1/chat/completions", json=req, headers={"X-Forwarded-For": xff})
    return read_events_from_log(log_path=log_path, scenario=scenario, seed=seed)
