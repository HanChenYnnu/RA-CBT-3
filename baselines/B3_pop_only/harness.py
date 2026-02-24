"""Harness for B3 DPoP baseline with realistic scenario semantics."""

from __future__ import annotations

import json
import os
from pathlib import Path

from baselines.B3_pop_only.app import create_app, make_dpop_proof
from experiments.adapters import read_events_from_log
from experiments.scenario_audit import record_sample
from experiments.scenario_contract import scenario_manifest, validate_request_semantics
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

USER_KEY = "user-key-demo"
LEGIT_JWK = "legit-public-jwk"
LEGIT_PRIVATE = "legit-private-key"
ATTACKER_JWK = "attacker-public-jwk"
ATTACKER_PRIVATE = "attacker-private-key"


def _exchange(client: TestClient, jwk: str) -> tuple[str, str]:
    response = client.post("/auth/exchange", json={"client_jwk": jwk}, headers={"Authorization": f"Bearer {USER_KEY}"}).json()
    return str(response["access_token"]), str(response["cnf"]["jkt"])


def _proof(private_key: str, token: str, jti: str, jkt: str) -> str:
    payload = json.loads(make_dpop_proof(private_key, "POST", "/v1/chat/completions", token, jti, jkt))
    payload["private_key_hint"] = private_key
    return json.dumps(payload)


def run_b3_scenario(*, scenario: str, n: int, log_path: Path, seed: int) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()
    manifest = scenario_manifest(scenario=scenario, baseline="B3", seed=seed, n=n)

    with TestClient(app) as client:
        requests = scenario_requests(scenario, n, seed=seed, baseline="B3")
        victim_token, victim_jkt = _exchange(client, LEGIT_JWK)

        if scenario in {"S1_key_leak", "S1_key_leak_hard"}:
            token, jkt = _exchange(client, ATTACKER_JWK)
            for idx, req in enumerate(requests):
                dpop = _proof(ATTACKER_PRIVATE, token, f"s1-{idx}", jkt)
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=True)
                record_sample(scenario=scenario, baseline="B3", caps=manifest, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=True, replay_key="", asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers={"Authorization": f"Bearer {token}", "DPoP": dpop})
        elif scenario in {"S2_token_leak", "S2_token_leak_hard", "S2a_token_leak_missing_dpop", "S2b_token_leak_wrong_key_dpop"}:
            for idx, req in enumerate(requests):
                headers = {"Authorization": f"Bearer {victim_token}"}
                if scenario == "S2b_token_leak_wrong_key_dpop" or (scenario == "S2_token_leak" and idx % 2 == 1):
                    headers["DPoP"] = _proof(ATTACKER_PRIVATE, victim_token, f"s2-{idx}", "wrong-jkt")
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present="DPoP" in headers, dpop_valid=False, exchange_called=False)
                record_sample(scenario=scenario, baseline="B3", caps=manifest, auth_present=True, dpop_present="DPoP" in headers, dpop_valid=False, exchange_called=False, replay_key="", asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers=headers)
        elif scenario in {"S3_replay", "S3_replay_hard"}:
            replay = _proof(LEGIT_PRIVATE, victim_token, "s3-replay", victim_jkt)
            for idx, req in enumerate(requests):
                if scenario == "S3_replay_hard" and idx % 5 == 0:
                    replay = _proof(LEGIT_PRIVATE, victim_token, f"s3-replay-hard-{idx//5}", victim_jkt)
                replay_key = json.loads(replay).get("jti", "")
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=False)
                record_sample(scenario=scenario, baseline="B3", caps=manifest, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=False, replay_key=replay_key, asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers={"Authorization": f"Bearer {victim_token}", "DPoP": replay})
        else:
            for idx, req in enumerate(requests):
                headers = {"Authorization": f"Bearer {victim_token}", "DPoP": _proof(LEGIT_PRIVATE, victim_token, f"{scenario}-{idx}", victim_jkt)}
                if "x_forwarded_for" in req:
                    headers["X-Forwarded-For"] = str(req["x_forwarded_for"])
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=True)
                record_sample(scenario=scenario, baseline="B3", caps=manifest, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=True, replay_key="", asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers=headers)

    return read_events_from_log(log_path=log_path, scenario=scenario, seed=seed)
