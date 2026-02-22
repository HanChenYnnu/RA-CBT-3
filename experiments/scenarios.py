"""Scenario catalog and deterministic request generators."""

from __future__ import annotations

import hashlib
import random

SCENARIOS = {
    "S1_key_leak": 80,
    "S2_token_leak": 120,
    "S2a_token_leak_missing_dpop": 40,
    "S2b_token_leak_wrong_key_dpop": 40,
    "S3_replay": 120,
    "S4_burst": 300,
    "S4_burst_L1": 120,
    "S4_burst_L2": 180,
    "S4_burst_L3": 240,
    "S4_burst_L4": 300,
    "S5_slowdrip": 300,
    "S6_drift": 150,
}

ALL_SCENARIOS = list(SCENARIOS.keys())
BENIGN_SCENARIOS = {"S5_slowdrip", "S6_drift", "S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4", "S4_burst"}
BURST_LEVELS = ["S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4"]


def _default_request(scenario: str, idx: int) -> dict[str, object]:
    return {
        "model": "gpt-mock",
        "scenario": scenario,
        "request_id": f"{scenario}-{idx}",
        "messages": [{"role": "user", "content": f"{scenario} payload {idx}"}],
        "max_tokens": 24,
        "x_forwarded_for": "10.0.0.10",
    }


def _seed_shuffle(requests: list[dict[str, object]], *, scenario: str, seed: int) -> list[dict[str, object]]:
    key = int(hashlib.sha256(f"{scenario}:{seed}".encode()).hexdigest()[:8], 16)
    rng = random.Random(key)
    rng.shuffle(requests)
    return requests


def scenario_requests(scenario: str, n: int, *, seed: int) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    burst_style = {"S4_burst": 4, "S4_burst_L1": 1, "S4_burst_L2": 2, "S4_burst_L3": 3, "S4_burst_L4": 4}
    if scenario in burst_style:
        mult = burst_style[scenario]
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["messages"] = [{"role": "user", "content": "burst load " + ("x" * ((idx % (8 * mult)) + 12))}]
            req["max_tokens"] = 18 + mult * 4 + (idx % (6 * mult))
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    if scenario == "S5_slowdrip":
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["messages"] = [{"role": "user", "content": "slowdrip " + ("y" * ((idx % 7) + 8))}]
            req["max_tokens"] = 14 + (idx % 8)
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    if scenario == "S6_drift":
        boundary = max(1, n // 3)
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["x_forwarded_for"] = (
                f"10.0.0.{(idx % 180) + 1}" if idx < boundary else f"203.0.113.{(idx % 180) + 1}"
            )
            req["messages"] = [{"role": "user", "content": "benign drift"}]
            req["max_tokens"] = 16
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    for idx in range(n):
        requests.append(_default_request(scenario, idx))
    return _seed_shuffle(requests, scenario=scenario, seed=seed)
