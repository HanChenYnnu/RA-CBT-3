import json
import os
from pathlib import Path

from baselines.B0_static.app import REQUIRED_LOG_KEYS
from baselines.B0_static.app import create_app as create_b0_app
from baselines.B2_bearer_short.app import create_app as create_b2_app
from baselines.B3_pop_only.app import create_app as create_b3_app
from baselines.B3_pop_only.app import jwk_thumbprint, make_dpop_proof
from experiments.metrics import compute_metrics
from experiments.runner import run_selected
from fastapi.testclient import TestClient


def test_b0_contract_log_keys_and_types(tmp_path: Path) -> None:
    log_path = tmp_path / "b0.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    app = create_b0_app()
    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S4_burst",
                "request_id": "req-1",
                "messages": [{"role": "user", "content": "hello world"}],
                "max_tokens": 40,
            },
            headers={"X-Forwarded-For": "10.0.0.10"},
        )
    assert response.status_code == 200
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert set(record.keys()) == REQUIRED_LOG_KEYS


def test_b2_exchange_call_missing_invalid_and_budget(tmp_path: Path) -> None:
    log_path = tmp_path / "b2.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    os.environ["B2_RPM_LIMIT"] = "2"
    os.environ["B2_TPM_LIMIT"] = "50"
    app = create_b2_app()

    with TestClient(app) as client:
        missing = client.post(
            "/v1/chat/completions",
            json={"scenario": "S2_token_leak", "messages": []},
        )
        assert missing.status_code == 401

        invalid = client.post(
            "/v1/chat/completions",
            json={"scenario": "S2_token_leak", "messages": []},
            headers={"Authorization": "Bearer invalid.token"},
        )
        assert invalid.status_code == 401

        exchange = client.post(
            "/auth/exchange",
            json={},
            headers={"Authorization": "Bearer user-key"},
        )
        token = exchange.json()["access_token"]

        ok = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S2_token_leak",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 20,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert ok.status_code == 200

        over_budget = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S2_token_leak",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 45,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert over_budget.status_code == 429


def test_b3_dpop_missing_jkt_ath_replay(tmp_path: Path) -> None:
    log_path = tmp_path / "b3.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    os.environ["B3_RPM_LIMIT"] = "20"
    os.environ["B3_TPM_LIMIT"] = "500"
    app = create_b3_app()

    legit_jwk = "legit-pub"
    legit_private = "legit-private"
    wrong_private = "wrong-private"

    with TestClient(app) as client:
        exchange = client.post(
            "/auth/exchange",
            json={"client_jwk": legit_jwk},
            headers={"Authorization": "Bearer user-key"},
        )
        token = exchange.json()["access_token"]
        jkt = jwk_thumbprint(legit_jwk)

        missing = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S2_token_leak",
                "messages": [{"role": "user", "content": "a"}],
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert missing.status_code == 401

        wrong_jkt_proof = json.loads(
            make_dpop_proof(
                wrong_private,
                "POST",
                "/v1/chat/completions",
                token,
                "j1",
                "wrong-jkt",
            )
        )
        wrong_jkt_proof["private_key_hint"] = wrong_private
        wrong_jkt = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S2_token_leak",
                "messages": [{"role": "user", "content": "b"}],
            },
            headers={"Authorization": f"Bearer {token}", "DPoP": json.dumps(wrong_jkt_proof)},
        )
        assert wrong_jkt.status_code == 401

        ath_bad = json.loads(
            make_dpop_proof(
                legit_private,
                "POST",
                "/v1/chat/completions",
                token,
                "j2",
                jkt,
            )
        )
        ath_bad["private_key_hint"] = legit_private
        ath_bad["ath"] = "tampered-ath"
        ath_bad["signature"] = "sig-mismatch"
        wrong_ath = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S2_token_leak",
                "messages": [{"role": "user", "content": "c"}],
            },
            headers={"Authorization": f"Bearer {token}", "DPoP": json.dumps(ath_bad)},
        )
        assert wrong_ath.status_code == 401

        first = json.loads(
            make_dpop_proof(
                legit_private,
                "POST",
                "/v1/chat/completions",
                token,
                "replay-jti",
                jkt,
            )
        )
        first["private_key_hint"] = legit_private
        ok = client.post(
            "/v1/chat/completions",
            json={"scenario": "S3_replay", "messages": [{"role": "user", "content": "d"}]},
            headers={"Authorization": f"Bearer {token}", "DPoP": json.dumps(first)},
        )
        assert ok.status_code == 200

        replay = client.post(
            "/v1/chat/completions",
            json={"scenario": "S3_replay", "messages": [{"role": "user", "content": "e"}]},
            headers={"Authorization": f"Bearer {token}", "DPoP": json.dumps(first)},
        )
        assert replay.status_code == 401

    reasons = [
        json.loads(line)["reason"] for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    assert "dpop_missing" in reasons
    assert "jkt_mismatch" in reasons
    assert "ath_mismatch" in reasons
    assert "replay" in reasons


def test_expected_b2_b3_deltas(tmp_path: Path) -> None:
    os.environ["B2_RPM_LIMIT"] = "300"
    os.environ["B2_TPM_LIMIT"] = "20000"
    os.environ["B3_RPM_LIMIT"] = "300"
    os.environ["B3_TPM_LIMIT"] = "20000"

    events = run_selected(
        baselines=["B2", "B3"],
        scenarios=["S2_token_leak", "S3_replay"],
        out_dir=tmp_path,
    )
    rows = compute_metrics(events)
    b2_s2 = next(r for r in rows if r.baseline == "B2" and r.scenario == "S2_token_leak")
    b3_s2 = next(r for r in rows if r.baseline == "B3" and r.scenario == "S2_token_leak")
    b2_s3 = next(r for r in rows if r.baseline == "B2" and r.scenario == "S3_replay")
    b3_s3 = next(r for r in rows if r.baseline == "B3" and r.scenario == "S3_replay")

    assert b2_s2.attack_success_rate >= 0.5
    assert b3_s2.attack_success_rate <= 0.05
    assert b3_s3.attack_success_rate < b2_s3.attack_success_rate
