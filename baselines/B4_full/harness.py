"""Harness for B4 full baseline."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from baselines.B4_full.app import create_app, make_dpop_proof
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

USER_KEY = "user-key-demo"
LEGIT_JWK = "legit-public-jwk"
LEGIT_PRIVATE = "legit-private-key"
ATTACKER_PRIVATE = "attacker-private-key"


def _ctx(ip: str, asn: str, country: str, ua: str, device_fp: str) -> str:
    return json.dumps(
        {
            "ip": ip,
            "asn": asn,
            "country": country,
            "ua": ua,
            "device_fp": device_fp,
            "ts": int(time.time()),
        }
    )


def run_b4_calibration(*, n: int, log_path: Path) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()
    with TestClient(app) as client:
        ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
        exchange = client.post(
            "/auth/exchange",
            json={"client_jwk": LEGIT_JWK},
            headers={
                "Authorization": f"Bearer {USER_KEY}",
                "X-Forwarded-For": "10.0.0.11",
                "X-CTX": ctx,
            },
        )
        token = exchange.json()["access_token"]
        jkt = exchange.json()["cnf"]["jkt"]
        for idx in range(n):
            proof = json.loads(
                make_dpop_proof(
                    LEGIT_PRIVATE,
                    "POST",
                    "/v1/chat/completions",
                    token,
                    f"cal-{idx}",
                    jkt,
                )
            )
            proof["private_key_hint"] = LEGIT_PRIVATE
            client.post(
                "/v1/chat/completions",
                json={
                    "scenario": "S6_drift",
                    "request_id": f"cal-{idx}",
                    "messages": [{"role": "user", "content": f"benign {idx}"}],
                    "max_tokens": 20,
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "DPoP": json.dumps(proof),
                    "X-Forwarded-For": "10.0.0.11",
                    "X-CTX": ctx,
                },
            )
    return []


def run_b4_scenario(*, scenario: str, n: int, log_path: Path) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()

    with TestClient(app) as client:
        exchange_ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
        exchange = client.post(
            "/auth/exchange",
            json={"client_jwk": LEGIT_JWK},
            headers={
                "Authorization": f"Bearer {USER_KEY}",
                "X-Forwarded-For": "10.0.0.11",
                "X-CTX": exchange_ctx,
            },
        )
        access_token = exchange.json()["access_token"]
        jkt = exchange.json()["cnf"]["jkt"]

        replay_jti = f"{scenario}-replay"
        for idx, req in enumerate(scenario_requests(scenario, n)):
            headers = {
                "Authorization": f"Bearer {access_token}",
                "X-Forwarded-For": "10.0.0.11",
                "X-CTX": exchange_ctx,
            }

            if scenario == "S2_token_leak":
                if idx % 2 == 0:
                    pass
                else:
                    proof = json.loads(
                        make_dpop_proof(
                            ATTACKER_PRIVATE,
                            "POST",
                            "/v1/chat/completions",
                            access_token,
                            f"s2-{idx}",
                            "wrong-jkt",
                        )
                    )
                    proof["private_key_hint"] = ATTACKER_PRIVATE
                    headers["DPoP"] = json.dumps(proof)

            elif scenario == "S3_replay":
                proof = json.loads(
                    make_dpop_proof(
                        LEGIT_PRIVATE,
                        "POST",
                        "/v1/chat/completions",
                        access_token,
                        replay_jti,
                        jkt,
                    )
                )
                proof["private_key_hint"] = LEGIT_PRIVATE
                headers["DPoP"] = json.dumps(proof)

            elif scenario == "S4_burst":
                req_ctx = _ctx(
                    ip=f"10.0.0.{(idx % 5) + 20}",
                    asn="AS100",
                    country="US",
                    ua=f"browser/100.{idx % 5}",
                    device_fp="fp-1" if idx % 3 else "fp-drift",
                )
                headers["X-Forwarded-For"] = f"10.0.0.{(idx % 5) + 20}"
                headers["X-CTX"] = req_ctx
                proof = json.loads(
                    make_dpop_proof(
                        LEGIT_PRIVATE,
                        "POST",
                        "/v1/chat/completions",
                        access_token,
                        f"s4-{idx}",
                        jkt,
                    )
                )
                proof["private_key_hint"] = LEGIT_PRIVATE
                headers["DPoP"] = json.dumps(proof)

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
