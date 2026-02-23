"""Harness for B2 short bearer baseline with scenario-correct actors."""

from __future__ import annotations

import os
from pathlib import Path

from baselines.B2_bearer_short.app import create_app
from experiments.adapters import read_events_from_log
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

USER_KEY = "user-key-demo"


def _exchange(client: TestClient) -> str:
    return client.post(
        "/auth/exchange",
        json={},
        headers={"Authorization": f"Bearer {USER_KEY}"},
    ).json()["access_token"]


def run_b2_scenario(*, scenario: str, n: int, log_path: Path, seed: int) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()

    with TestClient(app) as client:
        requests = scenario_requests(scenario, n, seed=seed)

        if scenario == "S1_key_leak":
            # attacker has user key and can mint their own token.
            token = _exchange(client)
            for req in requests:
                client.post(
                    "/v1/chat/completions",
                    json=req,
                    headers={"Authorization": f"Bearer {token}"},
                )
        elif scenario in {"S2_token_leak", "S2_token_leak_hard", "S2a_token_leak_missing_dpop", "S2b_token_leak_wrong_key_dpop"}:
            token = _exchange(client)
            # attacker only has stolen token; B2 still accepts.
            for req in requests:
                client.post(
                    "/v1/chat/completions",
                    json=req,
                    headers={"Authorization": f"Bearer {token}"},
                )
        elif scenario == "S3_replay_hard":
            token = _exchange(client)
            for req in requests:
                client.post(
                    "/v1/chat/completions",
                    json=req,
                    headers={"Authorization": f"Bearer {token}"},
                )
        else:
            token = _exchange(client)
            for req in requests:
                headers = {"Authorization": f"Bearer {token}"}
                if "x_forwarded_for" in req:
                    headers["X-Forwarded-For"] = str(req["x_forwarded_for"])
                client.post("/v1/chat/completions", json=req, headers=headers)

    return read_events_from_log(log_path=log_path, scenario=scenario, seed=seed)
