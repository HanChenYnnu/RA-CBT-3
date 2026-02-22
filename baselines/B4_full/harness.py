"""Harness for B4 full baseline with scenario-correct auth and context."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from baselines.B4_full.app import create_app, make_dpop_proof
from experiments.adapters import read_events_from_log
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

USER_KEY = "user-key-demo"
LEGIT_JWK = "legit-public-jwk"
LEGIT_PRIVATE = "legit-private-key"
ATTACKER_JWK = "attacker-public-jwk"
ATTACKER_PRIVATE = "attacker-private-key"


def _ctx(ip: str, asn: str, country: str, ua: str, device_fp: str, ts: int | None = None) -> str:
    return json.dumps(
        {
            "ip": ip,
            "asn": asn,
            "country": country,
            "ua": ua,
            "device_fp": device_fp,
            "ts": int(time.time()) if ts is None else ts,
        }
    )


def _proof(private: str, token: str, jti: str, jkt: str) -> str:
    d = json.loads(make_dpop_proof(private, "POST", "/v1/chat/completions", token, jti, jkt))
    d["private_key_hint"] = private
    return json.dumps(d)


def _exchange(client: TestClient, jwk: str, ctx: str, ip: str) -> dict[str, object]:
    return client.post(
        "/auth/exchange",
        json={"client_jwk": jwk},
        headers={
            "Authorization": f"Bearer {USER_KEY}",
            "X-Forwarded-For": ip,
            "X-CTX": ctx,
        },
    ).json()


def run_b4_calibration(*, n: int, benign_log_path: Path, attack_log_path: Path, seed: int) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(benign_log_path)
    app = create_app()

    with TestClient(app) as client:
        base_ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
        ex = _exchange(client, LEGIT_JWK, base_ctx, "10.0.0.11")
        token = str(ex["access_token"])
        jkt = str(ex["cnf"]["jkt"])
        for idx in range(n):
            req_ctx = _ctx(f"10.0.0.{(idx%5)+11}", "AS100", "US", f"browser/100.{idx%3}", "fp-1")
            client.post(
                "/v1/chat/completions",
                json={"scenario": "S6_drift", "request_id": f"cal-b-{idx}", "messages": [{"role": "user", "content": "benign"}], "max_tokens": 18},
                headers={
                    "Authorization": f"Bearer {token}",
                    "DPoP": _proof(LEGIT_PRIVATE, token, f"cal-b-{idx}", jkt),
                    "X-Forwarded-For": f"10.0.0.{(idx%5)+11}",
                    "X-CTX": req_ctx,
                },
            )

    os.environ["LOG_PATH"] = str(attack_log_path)
    app2 = create_app()
    with TestClient(app2) as client:
        # profile seeding
        _exchange(client, LEGIT_JWK, _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1"), "10.0.0.11")
        # attacker exchanges under shifted context; some denied/restricted.
        for idx in range(max(30, n // 4)):
            ex = _exchange(
                client,
                ATTACKER_JWK,
                _ctx("198.51.100.25", "AS999", "GB", "browser/120.2", f"atk-{idx%2}"),
                "198.51.100.25",
            )
            token = str(ex.get("access_token", ""))
            if not token:
                continue
            jkt = str(ex["cnf"]["jkt"])
            client.post(
                "/v1/chat/completions",
                json={"scenario": "S1_key_leak", "request_id": f"cal-a-{idx}", "messages": [{"role": "user", "content": "attack"}], "max_tokens": 28},
                headers={
                    "Authorization": f"Bearer {token}",
                    "DPoP": _proof(ATTACKER_PRIVATE, token, f"cal-a-{idx}", jkt),
                    "X-Forwarded-For": "198.51.100.25",
                    "X-CTX": _ctx("198.51.100.25", "AS999", "GB", "browser/120.2", f"atk-{idx%2}"),
                },
            )

    return []


def run_b4_scenario(*, scenario: str, n: int, log_path: Path, seed: int) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()

    with TestClient(app) as client:
        reqs = scenario_requests(scenario, n, seed=seed)

        # establish legitimate baseline profile
        owner_ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
        _exchange(client, LEGIT_JWK, owner_ctx, "10.0.0.11")

        if scenario == "S1_key_leak":
            # attacker can exchange (key leak) but context anomaly pushes restricted/denied outcomes.
            attacker_ctx = _ctx("10.0.0.99", "AS100", "US", "browser/100.9", "atk-fp")
            ex = _exchange(client, ATTACKER_JWK, attacker_ctx, "10.0.0.99")
            token = str(ex.get("access_token", ""))
            jkt = str(ex.get("cnf", {}).get("jkt", ""))
            for idx, req in enumerate(reqs):
                if not token:
                    # drive explicit deny path if exchange failed.
                    client.post("/v1/chat/completions", json=req, headers={"Authorization": "Bearer invalid"})
                    continue
                headers = {
                    "Authorization": f"Bearer {token}",
                    "X-Forwarded-For": "10.0.0.99",
                    "X-CTX": attacker_ctx,
                }
                # keep some valid requests to show partial vulnerability, but mostly blocked.
                if idx % 3 == 0:
                    headers["DPoP"] = _proof(ATTACKER_PRIVATE, token, f"s1-{idx}", jkt)
                client.post("/v1/chat/completions", json=req, headers=headers)

        elif scenario in {"S2_token_leak", "S2a_token_leak_missing_dpop", "S2b_token_leak_wrong_key_dpop"}:
            ex = _exchange(client, LEGIT_JWK, owner_ctx, "10.0.0.11")
            token = str(ex["access_token"])
            for idx, req in enumerate(reqs):
                headers = {
                    "Authorization": f"Bearer {token}",
                    "X-Forwarded-For": "10.0.0.11",
                    "X-CTX": owner_ctx,
                }
                if scenario == "S2b_token_leak_wrong_key_dpop" or (
                    scenario == "S2_token_leak" and idx % 2 == 1
                ):
                    headers["DPoP"] = _proof(ATTACKER_PRIVATE, token, f"s2-{idx}", "wrong-jkt")
                client.post("/v1/chat/completions", json=req, headers=headers)

        elif scenario == "S3_replay":
            ex = _exchange(client, LEGIT_JWK, owner_ctx, "10.0.0.11")
            token = str(ex["access_token"])
            jkt = str(ex["cnf"]["jkt"])
            replay = _proof(LEGIT_PRIVATE, token, "s3-replay", jkt)
            for req in reqs:
                client.post(
                    "/v1/chat/completions",
                    json=req,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "DPoP": replay,
                        "X-Forwarded-For": "10.0.0.11",
                        "X-CTX": owner_ctx,
                    },
                )

        else:
            issue_ctx = owner_ctx
            if scenario in {"S4_burst", "S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4"}:
                issue_ctx = _ctx("10.0.0.12", "AS100", "US", "browser/100.2", "fp-2")
            ex = _exchange(client, LEGIT_JWK, issue_ctx, "10.0.0.12" if scenario in {"S4_burst", "S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4"} else "10.0.0.11")
            token = str(ex["access_token"])
            jkt = str(ex["cnf"]["jkt"])
            for idx, req in enumerate(reqs):
                ip = str(req.get("x_forwarded_for", "10.0.0.11"))
                if scenario == "S6_drift":
                    fp = "fp-2" if idx % 4 == 0 else "fp-1"
                    req_ctx = _ctx(ip, "AS100", "US", f"browser/100.{idx%3}", fp)
                elif scenario in {"S4_burst", "S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4"}:
                    req_ctx = _ctx(ip, "AS100", "US", f"browser/100.{idx%2}", "fp-2")
                    req["max_tokens"] = 1
                    req["messages"] = [{"role": "user", "content": "b"}]
                else:
                    req_ctx = owner_ctx
                client.post(
                    "/v1/chat/completions",
                    json=req,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "DPoP": _proof(LEGIT_PRIVATE, token, f"{scenario}-{idx}", jkt),
                        "X-Forwarded-For": ip,
                        "X-CTX": req_ctx,
                    },
                )

    return read_events_from_log(log_path=log_path, scenario=scenario, seed=seed)
