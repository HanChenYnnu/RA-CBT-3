"""Harness for B3 DPoP PoP baseline."""

from __future__ import annotations

import json
import os
from pathlib import Path

from baselines.B3_pop_only.app import create_app, jwk_thumbprint, make_dpop_proof
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

USER_KEY = "user-key-demo"
LEGIT_JWK = "legit-public-jwk"
LEGIT_PRIVATE = "legit-private-key"
ATTACKER_PRIVATE = "attacker-private-key"


def run_b3_scenario(*, scenario: str, n: int, log_path: Path) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()

    with TestClient(app) as client:
        exchange = client.post(
            "/auth/exchange",
            json={"client_jwk": LEGIT_JWK},
            headers={"Authorization": f"Bearer {USER_KEY}"},
        )
        access_token = exchange.json()["access_token"]
        jkt = jwk_thumbprint(LEGIT_JWK)

        requests = scenario_requests(scenario, n)
        replay_jti = f"{scenario}-replay"
        for idx, req in enumerate(requests):
            headers = {"Authorization": f"Bearer {access_token}"}

            if scenario == "S2_token_leak":
                if idx % 2 == 0:
                    pass  # missing DPoP
                else:
                    # wrong key DPoP: attacker has no legitimate private key
                    proof = make_dpop_proof(
                        ATTACKER_PRIVATE,
                        "POST",
                        "/v1/chat/completions",
                        access_token,
                        f"{scenario}-{idx}",
                        "wrong-jkt",
                    )
                    proof_data = json.loads(proof)
                    proof_data["private_key_hint"] = ATTACKER_PRIVATE
                    headers["DPoP"] = json.dumps(proof_data)
            elif scenario == "S3_replay":
                proof = make_dpop_proof(
                    LEGIT_PRIVATE,
                    "POST",
                    "/v1/chat/completions",
                    access_token,
                    replay_jti,
                    jkt,
                )
                proof_data = json.loads(proof)
                proof_data["private_key_hint"] = LEGIT_PRIVATE
                headers["DPoP"] = json.dumps(proof_data)

            client.post("/v1/chat/completions", json=req, headers=headers)

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
