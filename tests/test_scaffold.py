import json
import os
from pathlib import Path

from baselines.B0_static.app import REQUIRED_LOG_KEYS
from baselines.B0_static.app import create_app as create_b0_app
from baselines.B1_ip_allowlist.app import create_app as create_b1_app
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
    assert isinstance(record["status_code"], int)
    assert isinstance(record["usage_total_tokens"], int)


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

    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["reason"] == "ok"
    assert records[1]["reason"] == "ip_not_allowed"
    assert records[1]["usage_total_tokens"] == 0


def test_drift_frr_b1_greater_than_b0(tmp_path: Path) -> None:
    events = run_selected(
        baselines=["B0", "B1"],
        scenarios=["S6_drift"],
        out_dir=tmp_path,
    )
    rows = compute_metrics(events)
    b0 = next(row for row in rows if row.baseline == "B0" and row.scenario == "S6_drift")
    b1 = next(row for row in rows if row.baseline == "B1" and row.scenario == "S6_drift")
    assert b1.false_reject_rate > b0.false_reject_rate
