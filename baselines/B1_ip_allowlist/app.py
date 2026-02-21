"""B1 IP allowlist baseline application."""

from __future__ import annotations

import ipaddress
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from experiments.mock_upstream import chat_completion
from fastapi import FastAPI


def _load_allowlist(config_path: Path) -> list[ipaddress._BaseNetwork]:
    cidrs: list[ipaddress._BaseNetwork] = []
    for line in config_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("-"):
            cidr = stripped.removeprefix("-").strip()
            cidrs.append(ipaddress.ip_network(cidr, strict=False))
    return cidrs


def _ip_allowed(ip: str, allowlist: list[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in network for network in allowlist)


def _append_log(record: dict[str, Any]) -> None:
    log_path = Path(os.environ.get("LOG_PATH", "results/raw/b1.jsonl"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def create_app(config_path: Path | None = None) -> FastAPI:
    app = FastAPI(title="B1 IP Allowlist Baseline")
    cfg_path = config_path or (Path(__file__).resolve().parent / "config.yaml")
    allowlist = _load_allowlist(cfg_path)

    @app.post("/v1/chat/completions")
    def chat_completions(payload: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        request_id = str(payload.get("request_id") or uuid.uuid4().hex)
        scenario = str(payload.get("scenario", "unknown"))
        headers = payload.get("_headers", {})
        xff = str(headers.get("X-Forwarded-For", ""))

        if not _ip_allowed(xff, allowlist):
            latency_ms = int((time.perf_counter() - started) * 1000) + 1
            record = {
                "ts_ms": int(time.time() * 1000),
                "baseline": "B1",
                "scenario": scenario,
                "request_id": request_id,
                "status_code": 403,
                "decision": "deny",
                "reason": "ip_not_allowed",
                "latency_ms": latency_ms,
                "precharge_tokens": 0,
                "usage_total_tokens": 0,
                "budget_before": -1,
                "budget_after": -1,
                "risk": -1.0,
            }
            _append_log(record)
            return {"error": "ip_not_allowed", "_status_code": 403}

        upstream = chat_completion(
            model=str(payload.get("model", "gpt-mock")),
            messages=payload.get("messages", []),
            max_tokens=int(payload.get("max_tokens", 64)),
            request_id=request_id,
        )
        latency_ms = int((time.perf_counter() - started) * 1000) + 1
        usage_total_tokens = int(upstream["usage"]["total_tokens"])
        record = {
            "ts_ms": int(time.time() * 1000),
            "baseline": "B1",
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
        _append_log(record)
        return upstream

    return app
