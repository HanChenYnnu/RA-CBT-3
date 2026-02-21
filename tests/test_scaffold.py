import json
import os
from pathlib import Path

from baselines.B0_static.app import REQUIRED_LOG_KEYS
from baselines.B0_static.app import create_app as create_b0_app
from baselines.B1_ip_allowlist.app import create_app as create_b1_app
from baselines.B2_bearer_short.app import create_app as create_b2_app
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


def test_b1_allowed_vs_denied_ip(tmp_path: Path) -> None:
    log_path = tmp_path / "b1.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    app = create_b1_app()

    with TestClient(app) as client:
        allowed = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S6_drift",
                "request_id": "allow-1",
                "messages": [{"role": "user", "content": "ok"}],
                "max_tokens": 30,
            },
            headers={"X-Forwarded-For": "10.0.0.55"},
        )
        denied = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S6_drift",
                "request_id": "deny-1",
                "messages": [{"role": "user", "content": "blocked"}],
                "max_tokens": 30,
            },
            headers={"X-Forwarded-For": "203.0.113.99"},
        )

    assert allowed.status_code == 200
    assert denied.status_code == 403


def test_drift_frr_b1_greater_than_b0(tmp_path: Path) -> None:
    events = run_selected(baselines=["B0", "B1"], scenarios=["S6_drift"], out_dir=tmp_path)
    rows = compute_metrics(events)
    b0 = next(row for row in rows if row.baseline == "B0" and row.scenario == "S6_drift")
    b1 = next(row for row in rows if row.baseline == "B1" and row.scenario == "S6_drift")
    assert b1.false_reject_rate > b0.false_reject_rate


def test_b2_exchange_call_missing_invalid_and_budget(tmp_path: Path) -> None:
    log_path = tmp_path / "b2.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    os.environ["B2_RPM_LIMIT"] = "2"
    os.environ["B2_TPM_LIMIT"] = "50"
    app = create_b2_app()

    with TestClient(app) as client:
        missing = client.post(
            "/v1/chat/completions",
            json={"scenario": "S2_token_leak", "messages": [], "max_tokens": 10},
        )
        assert missing.status_code == 401

        invalid = client.post(
            "/v1/chat/completions",
            json={"scenario": "S2_token_leak", "messages": [], "max_tokens": 10},
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


def test_s2_token_leak_b2_attack_success_high(tmp_path: Path) -> None:
    os.environ["B2_RPM_LIMIT"] = "200"
    os.environ["B2_TPM_LIMIT"] = "10000"
    events = run_selected(baselines=["B2"], scenarios=["S2_token_leak"], out_dir=tmp_path)
    rows = compute_metrics(events)
    row = next(item for item in rows if item.baseline == "B2" and item.scenario == "S2_token_leak")
    assert row.attack_success_rate >= 0.5
