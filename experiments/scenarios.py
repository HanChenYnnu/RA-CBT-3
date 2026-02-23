"""Scenario catalog and deterministic request generators."""

from __future__ import annotations

import hashlib
import random

SCENARIOS = {
    "S1_key_leak": 30,
    "S1_key_leak_hard": 60,
    "S2_token_leak": 40,
    "S2_token_leak_hard": 180,
    "S2a_token_leak_missing_dpop": 20,
    "S2b_token_leak_wrong_key_dpop": 20,
    "S3_replay": 40,
    "S3_replay_hard": 180,
    "S4_burst": 70,
    "S4_burst_L1": 40,
    "S4_burst_L2": 50,
    "S4_burst_L3": 60,
    "S4_burst_L4": 70,
    "S5_slowdrip": 60,
    "S6_drift": 50,
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

    if scenario == "S1_key_leak_hard":
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["messages"] = [{"role": "user", "content": "plausible-key-leak " + ("k" * ((idx % 6) + 8))}]
            req["max_tokens"] = 16 + (idx % 6)
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    if scenario == "S2_token_leak_hard":
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["messages"] = [{"role": "user", "content": "plausible-token-use " + ("t" * ((idx % 5) + 7))}]
            req["max_tokens"] = 14 + (idx % 5)
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    if scenario == "S3_replay_hard":
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["messages"] = [{"role": "user", "content": "replay-like-timing"}]
            req["max_tokens"] = 15 + (idx % 4)
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    for idx in range(n):
        requests.append(_default_request(scenario, idx))
    return _seed_shuffle(requests, scenario=scenario, seed=seed)
