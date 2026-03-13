"""B4 budget sweep experiment helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path

from baselines.B4_full.harness import _ctx, _exchange, _proof, LEGIT_JWK, LEGIT_PRIVATE
from baselines.B4_full.app import create_app
from experiments.adapters import scenario_label
from experiments.scenarios import scenario_requests
from experiments.types import EventRow
from fastapi.testclient import TestClient

SCALES = [1.00, 0.70, 0.50, 0.35, 0.25]
SWEEP_COUNTS = {
    "S3_replay_nearmiss_hard": 44,
    "S3_replay_blended_hard": 44,
    "S1_restricted_issuance_hard": 44,
    "S2_delegated_misuse_hard": 44,
    "S3_benign_control_hard": 140,
}


def _scaled(base: int, scale: float) -> int:
    return max(1, int(round(base * scale)))


def _run_mixedload_for_scale(*, out_dir: Path, seed: int, scale: float) -> list[EventRow]:
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    sweep_name = f"S4_mixedload_sweep_x{scale:.2f}"
    log_path = raw_dir / f"seed{seed}_B4_{sweep_name}.jsonl"

    os.environ["LOG_PATH"] = str(log_path)
    app = create_app()
    events: list[EventRow] = []
    with TestClient(app) as client:
        owner_ctx = _ctx("10.0.0.11", "AS100", "US", "browser/100.1", "fp-1")
        owner_ex = _exchange(client, LEGIT_JWK, owner_ctx, "10.0.0.11")
        owner_token, owner_jkt = str(owner_ex["access_token"]), str(owner_ex["cnf"]["jkt"])

        req_by_scenario = {s: scenario_requests(s, n, seed=seed, baseline="B4") for s, n in SWEEP_COUNTS.items()}
        max_n = max(len(v) for v in req_by_scenario.values())

        for i in range(max_n):
            for scenario, reqs in req_by_scenario.items():
                if i >= len(reqs):
                    continue
                req = dict(reqs[i])
                req["scenario"] = scenario
                headers = {
                    "Authorization": f"Bearer {owner_token}",
                    "DPoP": _proof(LEGIT_PRIVATE, owner_token, f"{scenario}-{i}", owner_jkt),
                    "X-Forwarded-For": "10.0.0.11",
                    "X-CTX": owner_ctx,
                }
                if scenario == "S2_delegated_misuse_hard":
                    headers["X-Forwarded-For"] = "10.0.0.13"
                    headers["X-CTX"] = _ctx("10.0.0.13", "AS100", "US", "browser/100.3", "fp-1")
                client.post("/v1/chat/completions", json=req, headers=headers)

    if not log_path.exists():
        return []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        rec = json.loads(line)
        src = str(rec.get("scenario", ""))
        label = scenario_label(src)
        events.append(
            EventRow(
                baseline="B4",
                scenario=sweep_name,
                status_code=int(rec["status_code"]),
                reason=str(rec["reason"]),
                decision=str(rec["decision"]),
                latency_ms=float(rec["latency_ms"]),
                usage_total_tokens=int(rec["usage_total_tokens"]),
                benign=(label == "benign"),
                risk=float(rec.get("risk", -1.0)),
                seed=seed,
                label=label,
            )
        )
    return events


def run_b4_budget_sweep(*, out_dir: Path, seed: int) -> list[EventRow]:
    prior = {
        "B4_RPM_LIMIT": os.environ.get("B4_RPM_LIMIT"),
        "B4_TPM_LIMIT": os.environ.get("B4_TPM_LIMIT"),
        "B4_MAXTOK_SCALE": os.environ.get("B4_MAXTOK_SCALE"),
    }

    sweep_events: list[EventRow] = []
    for scale in SCALES:
        os.environ["B4_RPM_LIMIT"] = str(_scaled(150, scale))
        os.environ["B4_TPM_LIMIT"] = str(_scaled(2100, scale))
        os.environ["B4_MAXTOK_SCALE"] = "1.00"
        sweep_events.extend(_run_mixedload_for_scale(out_dir=out_dir, seed=seed, scale=scale))

    for k, v in prior.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return sweep_events
