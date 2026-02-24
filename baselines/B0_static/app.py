"""B0 static baseline FastAPI application."""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from experiments.latency import latency_ms_with_jitter
from experiments.mock_upstream import chat_completion
from fastapi import FastAPI

REQUIRED_LOG_KEYS = {
    "ts_ms",
    "baseline",
    "scenario",
    "request_id",
    "status_code",
    "decision",
    "reason",
    "latency_ms",
    "precharge_tokens",
    "usage_total_tokens",
    "budget_before",
    "budget_after",
    "risk",
}


def _append_log(record: dict[str, Any]) -> None:
    log_path = Path(os.environ.get("LOG_PATH", "results/raw/b0.jsonl"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def create_app() -> FastAPI:
    app = FastAPI(title="B0 Static Baseline")

    @app.post("/v1/chat/completions")
    def chat_completions(payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        request_id = str(payload.get("request_id") or uuid.uuid4().hex)
        scenario = str(payload.get("scenario", "unknown"))
        if scenario == "S4_burst":
            time.sleep(0.003)
        elif scenario == "S5_slowdrip":
            time.sleep(0.001)
        messages = payload.get("messages", [])
        max_tokens = int(payload.get("max_tokens", 64))

        upstream = chat_completion(
            model=str(payload.get("model", "gpt-mock")),
            messages=messages,
            max_tokens=max_tokens,
            request_id=request_id,
        )

        latency_ms = latency_ms_with_jitter(started=started, request_id=request_id)
        usage_total_tokens = int(upstream["usage"]["total_tokens"])
        log_record = {
            "ts_ms": int(time.time() * 1000),
            "baseline": "B0",
            "scenario": scenario,
            "request_id": request_id,
            "status_code": 200,
            "decision": "allow",
            "reason": "ok",
            "latency_ms": latency_ms,
            "precharge_tokens": 0,
            "usage_total_tokens": usage_total_tokens,
            "budget_before": -1,
            "budget_after": -1,
            "risk": -1.0,
        }
        _append_log(log_record)
        return upstream

    return app
