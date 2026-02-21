"""Harness for B3 DPoP baseline with realistic scenario semantics."""

from __future__ import annotations

import json
import os
from pathlib import Path

from baselines.B3_pop_only.app import create_app, jwk_thumbprint, make_dpop_proof
from experiments.adapters import read_events_from_log
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

USER_KEY = "user-key-demo"
LEGIT_JWK = "legit-public-jwk"
LEGIT_PRIVATE = "legit-private-key"
ATTACKER_JWK = "attacker-public-jwk"
ATTACKER_PRIVATE = "attacker-private-key"


def _exchange(client: TestClient, jwk: str) -> tuple[str, str]:
    response = client.post(
        "/auth/exchange",
        json={"client_jwk": jwk},
        headers={"Authorization": f"Bearer {USER_KEY}"},
    ).json()
    return str(response["access_token"]), str(response["cnf"]["jkt"])


def _proof(private_key: str, token: str, jti: str, jkt: str) -> str:
    payload = json.loads(make_dpop_proof(private_key, "POST", "/v1/chat/completions", token, jti, jkt))
    payload["private_key_hint"] = private_key
    return json.dumps(payload)


def run_b3_scenario(*, scenario: str, n: int, log_path: Path, seed: int) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()

    with TestClient(app) as client:
        requests = scenario_requests(scenario, n)

        if scenario == "S1_key_leak":
            # attacker has user_key and can bind PoP to attacker key.
            token, jkt = _exchange(client, ATTACKER_JWK)
            for idx, req in enumerate(requests):
                client.post(
                    "/v1/chat/completions",
                    json=req,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "DPoP": _proof(ATTACKER_PRIVATE, token, f"s1-{idx}", jkt),
                    },
                )
        elif scenario in {"S2_token_leak", "S2a_token_leak_missing_dpop", "S2b_token_leak_wrong_key_dpop"}:
            token, legit_jkt = _exchange(client, LEGIT_JWK)
            for idx, req in enumerate(requests):
                headers = {"Authorization": f"Bearer {token}"}
                if scenario == "S2b_token_leak_wrong_key_dpop" or (
                    scenario == "S2_token_leak" and idx % 2 == 1
                ):
                    headers["DPoP"] = _proof(ATTACKER_PRIVATE, token, f"s2-{idx}", "wrong-jkt")
                client.post("/v1/chat/completions", json=req, headers=headers)
        elif scenario == "S3_replay":
            token, jkt = _exchange(client, LEGIT_JWK)
            replay = _proof(LEGIT_PRIVATE, token, "s3-replay", jkt)
            for req in requests:
                client.post(
                    "/v1/chat/completions",
                    json=req,
                    headers={"Authorization": f"Bearer {token}", "DPoP": replay},
                )
        else:
            token, jkt = _exchange(client, LEGIT_JWK)
            for idx, req in enumerate(requests):
                headers = {
                    "Authorization": f"Bearer {token}",
                    "DPoP": _proof(LEGIT_PRIVATE, token, f"{scenario}-{idx}", jkt),
                }
                if "x_forwarded_for" in req:
                    headers["X-Forwarded-For"] = str(req["x_forwarded_for"])
                client.post("/v1/chat/completions", json=req, headers=headers)

    return read_events_from_log(log_path=log_path, scenario=scenario, seed=seed)
