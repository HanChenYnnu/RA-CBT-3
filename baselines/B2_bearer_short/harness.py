"""Harness for B2 short bearer baseline with scenario-correct actors."""

from __future__ import annotations

import os
from pathlib import Path

from baselines.B2_bearer_short.app import create_app
from experiments.adapters import read_events_from_log
from experiments.scenario_audit import record_sample
from experiments.scenario_contract import get_capabilities, scenario_manifest, validate_request_semantics
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

USER_KEY = "user-key-demo"


def _exchange(client: TestClient) -> str:
    return client.post("/auth/exchange", json={}, headers={"Authorization": f"Bearer {USER_KEY}"}).json()["access_token"]


def run_b2_scenario(*, scenario: str, n: int, log_path: Path, seed: int) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()
    manifest = scenario_manifest(scenario=scenario, baseline="B2", seed=seed, n=n)

    with TestClient(app) as client:
        requests = scenario_requests(scenario, n, seed=seed, baseline="B2")
        token = _exchange(client)
        for req in requests:
            headers = {"Authorization": f"Bearer {token}"}
            if "x_forwarded_for" in req:
                headers["X-Forwarded-For"] = str(req["x_forwarded_for"])
            exchange_called = get_capabilities(scenario).can_exchange_token
            validate_request_semantics(scenario=scenario, auth_present=True, dpop_present=False, exchange_called=exchange_called)
            record_sample(scenario=scenario, baseline="B2", caps=manifest, auth_present=True, dpop_present=False, exchange_called=exchange_called, replay_key="")
            client.post("/v1/chat/completions", json=req, headers=headers)

    return read_events_from_log(log_path=log_path, scenario=scenario, seed=seed)
