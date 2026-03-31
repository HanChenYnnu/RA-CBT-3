"""Harness for B4 full baseline with scenario-correct auth and context."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from baselines.B4_full.app import create_app, make_dpop_proof
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


def _ctx(ip: str, asn: str, country: str, ua: str, device_fp: str, ts: int | None = None) -> str:
    return json.dumps({"ip": ip, "asn": asn, "country": country, "ua": ua, "device_fp": device_fp, "ts": int(time.time()) if ts is None else ts})


def _proof(private: str, token: str, jti: str, jkt: str) -> str:
    d = json.loads(make_dpop_proof(private, "POST", "/v1/chat/completions", token, jti, jkt))
    d["private_key_hint"] = private
    return json.dumps(d)


def _exchange(client: TestClient, jwk: str, ctx: str, ip: str) -> dict[str, object]:
    return client.post("/auth/exchange", json={"client_jwk": jwk}, headers={"Authorization": f"Bearer {USER_KEY}", "X-Forwarded-For": ip, "X-CTX": ctx}).json()


def run_b4_calibration(*, n: int, benign_log_path: Path, attack_log_path: Path, seed: int) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(benign_log_path)
    app = create_app()
    with TestClient(app) as client:
        base_ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
        ex = _exchange(client, LEGIT_JWK, base_ctx, "10.0.0.11")
        token, jkt = str(ex["access_token"]), str(ex["cnf"]["jkt"])
        for idx in range(n):
            req_ctx = _ctx(f"10.0.0.{(idx%5)+11}", "AS100", "US", f"browser/100.{idx%3}", "fp-1")
            client.post("/v1/chat/completions", json={"scenario": "S6_drift", "request_id": f"cal-b-{idx}", "messages": [{"role": "user", "content": "benign"}], "max_tokens": 18}, headers={"Authorization": f"Bearer {token}", "DPoP": _proof(LEGIT_PRIVATE, token, f"cal-b-{idx}", jkt), "X-Forwarded-For": f"10.0.0.{(idx%5)+11}", "X-CTX": req_ctx})

    os.environ["LOG_PATH"] = str(attack_log_path)
    app2 = create_app()
    with TestClient(app2) as client:
        _exchange(client, LEGIT_JWK, _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1"), "10.0.0.11")
        for idx in range(max(30, n // 4)):
            ex = _exchange(client, ATTACKER_JWK, _ctx("198.51.100.25", "AS999", "GB", "browser/120.2", f"atk-{idx%2}"), "198.51.100.25")
            token = str(ex.get("access_token", ""))
            if token:
                jkt = str(ex["cnf"]["jkt"])
                client.post("/v1/chat/completions", json={"scenario": "S1_key_leak", "request_id": f"cal-a-{idx}", "messages": [{"role": "user", "content": "attack"}], "max_tokens": 28}, headers={"Authorization": f"Bearer {token}", "DPoP": _proof(ATTACKER_PRIVATE, token, f"cal-a-{idx}", jkt), "X-Forwarded-For": "198.51.100.25", "X-CTX": _ctx("198.51.100.25", "AS999", "GB", "browser/120.2", f"atk-{idx%2}")})
    return []


def run_b4_scenario(*, scenario: str, n: int, log_path: Path, seed: int) -> list[EventRow]:
    return run_b4_variant_scenario(
        scenario=scenario,
        n=n,
        log_path=log_path,
        seed=seed,
        baseline_label="B4",
        disable_ctx_binding=False,
        disable_multi_action=False,
        weak_signals=False,
        simple_policy=False,
    )


def run_b4_variant_scenario(
    *,
    scenario: str,
    n: int,
    log_path: Path,
    seed: int,
    baseline_label: str,
    disable_ctx_binding: bool,
    disable_multi_action: bool,
    weak_signals: bool,
    simple_policy: bool,
) -> list[EventRow]:
    os.environ["LOG_PATH"] = str(log_path)
    os.environ["BASELINE_LABEL"] = baseline_label
    os.environ["B4_DISABLE_CTX_BINDING"] = "1" if disable_ctx_binding else "0"
    os.environ["B4_DISABLE_MULTI_ACTION"] = "1" if disable_multi_action else "0"
    os.environ["B4_WEAK_SIGNALS"] = "1" if weak_signals else "0"
    os.environ["B4_SIMPLE_POLICY"] = "1" if simple_policy else "0"
    app = create_app()
    manifest = scenario_manifest(scenario=scenario, baseline="B4", seed=seed, n=n)

    with TestClient(app) as client:
        reqs = scenario_requests(scenario, n, seed=seed, baseline="B4")
        max_tok_scale = float(os.environ.get("B4_MAXTOK_SCALE", "1.0"))
        if abs(max_tok_scale - 1.0) > 1e-9:
            for req in reqs:
                req["max_tokens"] = max(1, int(round(int(req.get("max_tokens", 1)) * max_tok_scale)))
        owner_ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
        owner_ex = _exchange(client, LEGIT_JWK, owner_ctx, "10.0.0.11")
        owner_token, owner_jkt = str(owner_ex["access_token"]), str(owner_ex["cnf"]["jkt"])

        if scenario in {"S1_key_leak", "S1_key_leak_hard", "S1_restricted_issuance_hard"}:
            attacker_ctx = _ctx("10.0.0.99", "AS100", "US", "browser/100.9", "fp-1" if scenario in {"S1_key_leak_hard", "S1_restricted_issuance_hard"} else "atk-fp")
            ex = _exchange(client, ATTACKER_JWK, attacker_ctx, "10.0.0.99")
            token = str(ex.get("access_token", ""))
            jkt = str(ex.get("cnf", {}).get("jkt", ""))
            for idx, req in enumerate(reqs):
                headers = {"Authorization": f"Bearer {token}", "X-Forwarded-For": "10.0.0.99", "X-CTX": attacker_ctx}
                if token and ((scenario == "S1_key_leak_hard" and idx % 20 == 0) or scenario in {"S1_key_leak", "S1_restricted_issuance_hard"}):
                    headers["DPoP"] = _proof(ATTACKER_PRIVATE, token, f"s1-{idx}", jkt)
                validate_request_semantics(scenario=scenario, auth_present=bool(token), dpop_present="DPoP" in headers, dpop_valid="DPoP" in headers, exchange_called=True)
                record_sample(scenario=scenario, baseline="B4", caps=manifest, auth_present=bool(token), dpop_present="DPoP" in headers, dpop_valid="DPoP" in headers, exchange_called=True, replay_key="", asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers=headers if token else {"Authorization": "Bearer invalid"})

        elif scenario in {"S2_token_leak", "S2_token_leak_hard", "S2a_token_leak_missing_dpop", "S2b_token_leak_wrong_key_dpop", "S2_delegated_misuse_hard"}:
            for idx, req in enumerate(reqs):
                headers = {"Authorization": f"Bearer {owner_token}", "X-Forwarded-For": "10.0.0.11", "X-CTX": owner_ctx}
                dpop_valid = False
                if scenario == "S2_delegated_misuse_hard":
                    headers["DPoP"] = _proof(LEGIT_PRIVATE, owner_token, f"s2-delegated-{idx}", owner_jkt)
                    headers["X-Forwarded-For"] = "10.0.0.13"
                    headers["X-CTX"] = _ctx("10.0.0.13", "AS100", "US", "browser/100.3", "fp-1")
                    dpop_valid = True
                elif scenario == "S2b_token_leak_wrong_key_dpop" or (scenario == "S2_token_leak" and idx % 2 == 1):
                    headers["DPoP"] = _proof(ATTACKER_PRIVATE, owner_token, f"s2-{idx}", "wrong-jkt")
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present="DPoP" in headers, dpop_valid=dpop_valid, exchange_called=False)
                record_sample(scenario=scenario, baseline="B4", caps=manifest, auth_present=True, dpop_present="DPoP" in headers, dpop_valid=dpop_valid, exchange_called=False, replay_key="", asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers=headers)

        elif scenario in {"S3_replay", "S3_replay_hard", "S3_replay_nearmiss_hard", "S3_replay_blended_hard"}:
            replay = _proof(LEGIT_PRIVATE, owner_token, "s3-replay", owner_jkt)
            for idx, req in enumerate(reqs):
                if scenario == "S3_replay_hard":
                    replay = _proof(LEGIT_PRIVATE, owner_token, "s3-replay-hard-fixed", owner_jkt)
                elif scenario == "S3_replay_nearmiss_hard":
                    replay = _proof(LEGIT_PRIVATE, owner_token, f"s3-replay-nearmiss-{idx % 100}", owner_jkt)
                elif scenario == "S3_replay_blended_hard":
                    replay = _proof(LEGIT_PRIVATE, owner_token, f"s3-replay-blended-{idx % 200}", owner_jkt)
                replay_key = json.loads(replay).get("jti", "")
                req_ctx = owner_ctx if scenario not in {"S3_replay_nearmiss_hard", "S3_replay_blended_hard"} or idx % 3 == 0 else _ctx("10.0.0.77", "AS100", "US", "browser/100.1", "fp-mismatch")
                req_ip = "10.0.0.11" if req_ctx == owner_ctx else "10.0.0.77"
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=False)
                record_sample(scenario=scenario, baseline="B4", caps=manifest, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=False, replay_key=replay_key, asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers={"Authorization": f"Bearer {owner_token}", "DPoP": replay, "X-Forwarded-For": req_ip, "X-CTX": req_ctx})

        elif scenario in {"S7_cross_device_reuse_attack", "S7_cross_device_reuse_benign"}:
            issue_ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
            ex = _exchange(client, LEGIT_JWK, issue_ctx, "10.0.0.11")
            token, jkt = str(ex["access_token"]), str(ex["cnf"]["jkt"])
            for idx, req in enumerate(reqs):
                if scenario == "S7_cross_device_reuse_attack":
                    ip = f"203.0.113.{(idx % 50) + 1}"
                    req_ctx = _ctx(ip, "AS999", "GB", f"browser/120.{idx%2}", f"atk-fp-{idx%3}")
                else:
                    ip = f"10.0.0.{(idx % 15) + 1}"
                    req_ctx = _ctx(ip, "AS100", "US", f"browser/100.{idx%3}", "fp-1")
                headers = {"Authorization": f"Bearer {token}", "DPoP": _proof(LEGIT_PRIVATE, token, f"{scenario}-{idx}", jkt), "X-Forwarded-For": ip, "X-CTX": req_ctx}
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=scenario == "S7_cross_device_reuse_benign")
                record_sample(scenario=scenario, baseline="B4", caps=manifest, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=scenario == "S7_cross_device_reuse_benign", replay_key="", asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers=headers)
        elif scenario in {"S8_camouflaged_replay_attack", "S8_camouflaged_replay_benign"}:
            issue_ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
            ex = _exchange(client, LEGIT_JWK, issue_ctx, "10.0.0.11")
            token, jkt = str(ex["access_token"]), str(ex["cnf"]["jkt"])
            stable_replay = _proof(LEGIT_PRIVATE, token, "s8-fixed-replay", jkt)
            for idx, req in enumerate(reqs):
                if scenario == "S8_camouflaged_replay_attack":
                    if idx < 50:
                        proof = _proof(LEGIT_PRIVATE, token, f"s8-warmup-{idx}", jkt)
                        req_ctx = issue_ctx
                        req_ip = "10.0.0.11"
                    elif idx % 3 == 0:
                        proof = stable_replay
                        req_ctx = issue_ctx
                        req_ip = "10.0.0.11"
                    elif idx % 3 == 1:
                        proof = stable_replay
                        req_ctx = _ctx("10.0.0.37", "AS100", "US", "browser/100.1", "fp-1")
                        req_ip = "10.0.0.37"
                    else:
                        proof = stable_replay
                        req_ctx = _ctx("198.51.100.41", "AS999", "GB", "browser/120.1", "fp-x")
                        req_ip = "198.51.100.41"
                else:
                    proof = _proof(LEGIT_PRIVATE, token, f"s8-benign-{idx}", jkt)
                    req_ctx = _ctx(f"10.0.0.{(idx % 8) + 9}", "AS100", "US", f"browser/100.{idx%2}", "fp-1")
                    req_ip = f"10.0.0.{(idx % 8) + 9}"
                replay_key = json.loads(proof).get("jti", "")
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=True)
                record_sample(scenario=scenario, baseline="B4", caps=manifest, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=True, replay_key=replay_key, asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers={"Authorization": f"Bearer {token}", "DPoP": proof, "X-Forwarded-For": req_ip, "X-CTX": req_ctx})
        else:
            burst = {"S4_burst", "S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4"}
            issue_ctx = _ctx("10.0.0.12", "AS100", "US", "browser/100.2", "fp-2") if scenario in burst else owner_ctx
            ex = _exchange(client, LEGIT_JWK, issue_ctx, "10.0.0.12" if scenario in burst else "10.0.0.11")
            token, jkt = str(ex["access_token"]), str(ex["cnf"]["jkt"])
            for idx, req in enumerate(reqs):
                ip = str(req.get("x_forwarded_for", "10.0.0.11"))
                req_ctx = issue_ctx
                if scenario == "S6_drift":
                    req_ctx = _ctx(ip, "AS100", "US", f"browser/100.{idx%3}", "fp-2" if idx % 4 == 0 else "fp-1")
                elif scenario in burst:
                    req_ctx = _ctx(ip, "AS100", "US", f"browser/100.{idx%2}", "fp-2")
                    req["max_tokens"] = 1
                    req["messages"] = [{"role": "user", "content": "b"}]
                headers = {"Authorization": f"Bearer {token}", "DPoP": _proof(LEGIT_PRIVATE, token, f"{scenario}-{idx}", jkt), "X-Forwarded-For": ip, "X-CTX": req_ctx}
                validate_request_semantics(scenario=scenario, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=True)
                record_sample(scenario=scenario, baseline="B4", caps=manifest, auth_present=True, dpop_present=True, dpop_valid=True, exchange_called=True, replay_key="", asn="AS100", country="US", ua_family="browser", max_tokens=int(req.get("max_tokens", 0)))
                client.post("/v1/chat/completions", json=req, headers=headers)

    events = read_events_from_log(log_path=log_path, scenario=scenario, seed=seed)
    os.environ.pop("BASELINE_LABEL", None)
    os.environ.pop("B4_DISABLE_CTX_BINDING", None)
    os.environ.pop("B4_DISABLE_MULTI_ACTION", None)
    os.environ.pop("B4_WEAK_SIGNALS", None)
    os.environ.pop("B4_SIMPLE_POLICY", None)
    return events
