import json
import os
from pathlib import Path

from baselines.B0_static.app import REQUIRED_LOG_KEYS, create_app
from baselines.B0_static.harness import run_b0_scenario
from experiments.metrics import compute_metrics
from fastapi.testclient import TestClient


def test_b0_contract_log_keys_and_types(tmp_path: Path) -> None:
    log_path = tmp_path / "b0.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S4_burst",
                "request_id": "req-1",
                "messages": [{"role": "user", "content": "hello world"}],
                "max_tokens": 40,
            },
        )
    assert response.status_code == 200

    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    record = records[0]
    assert set(record.keys()) == REQUIRED_LOG_KEYS
    assert isinstance(record["ts_ms"], int)
    assert isinstance(record["baseline"], str)
    assert isinstance(record["status_code"], int)
    assert isinstance(record["latency_ms"], int)
    assert isinstance(record["usage_total_tokens"], int)
    assert isinstance(record["risk"], float)


def test_burst_cost_scales_with_n(tmp_path: Path) -> None:
    small = run_b0_scenario(scenario="S4_burst", n=10, log_path=tmp_path / "small.jsonl")
    large = run_b0_scenario(scenario="S4_burst", n=60, log_path=tmp_path / "large.jsonl")

    small_cost = compute_metrics(small)[0].cost_leakage_tokens
    large_cost = compute_metrics(large)[0].cost_leakage_tokens
    assert large_cost > small_cost
