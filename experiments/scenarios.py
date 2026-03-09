"""Scenario catalog and deterministic request generators."""

from __future__ import annotations

import hashlib
import random

from experiments.scenario_contract import PAIRED_CONTROLS, scenario_manifest

SCENARIOS = {
    "S1_key_leak": 30,
    "S1_key_leak_hard": 40,
    "S1_benign_control_hard": 40,
    "S2_token_leak": 40,
    "S2_token_leak_hard": 80,
    "S2_benign_control_hard": 80,
    "S2a_token_leak_missing_dpop": 20,
    "S2b_token_leak_wrong_key_dpop": 20,
    "S3_replay": 40,
    "S3_replay_hard": 300,
    "S3_replay_nearmiss_hard": 600,
    "S3_benign_control_hard": 220,
    "S4_burst": 70,
    "S4_burst_L1": 40,
    "S4_burst_L2": 50,
    "S4_burst_L3": 60,
    "S4_burst_L4": 70,
    "S5_slowdrip": 60,
    "S6_drift": 50,
}

ALL_SCENARIOS = list(SCENARIOS.keys())
BENIGN_SCENARIOS = {
    "S5_slowdrip", "S6_drift", "S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4", "S4_burst",
    "S1_benign_control_hard", "S2_benign_control_hard", "S3_benign_control_hard",
}
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


def _hard_context_payload(scenario: str, idx: int) -> tuple[str, int]:
    if scenario.startswith("S1"):
        return ("near-benign-account-use " + ("k" * ((idx % 6) + 8)), 16 + (idx % 6))
    if scenario.startswith("S2"):
        return ("near-benign-token-use " + ("t" * ((idx % 5) + 7)), 14 + (idx % 5))
    return ("near-benign-timing-pattern", 15 + (idx % 4))


def scenario_requests(scenario: str, n: int, *, seed: int, baseline: str | None = None) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []
    manifest = scenario_manifest(scenario=scenario, baseline=baseline or "unknown", seed=seed, n=n)

    burst_style = {"S4_burst": 4, "S4_burst_L1": 1, "S4_burst_L2": 2, "S4_burst_L3": 3, "S4_burst_L4": 4}
    if scenario in burst_style:
        mult = burst_style[scenario]
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["messages"] = [{"role": "user", "content": "burst load " + ("x" * ((idx % (8 * mult)) + 12))}]
            req["max_tokens"] = 18 + mult * 4 + (idx % (6 * mult))
            req["_capability_manifest"] = manifest
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    if scenario in {"S5_slowdrip", "S6_drift"}:
        for idx in range(n):
            req = _default_request(scenario, idx)
            if scenario == "S5_slowdrip":
                req["messages"] = [{"role": "user", "content": "slowdrip " + ("y" * ((idx % 7) + 8))}]
                req["max_tokens"] = 14 + (idx % 8)
            else:
                boundary = max(1, n // 3)
                req["x_forwarded_for"] = f"10.0.0.{(idx % 180) + 1}" if idx < boundary else f"203.0.113.{(idx % 180) + 1}"
                req["messages"] = [{"role": "user", "content": "benign drift"}]
                req["max_tokens"] = 16
            req["_capability_manifest"] = manifest
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    hard_group = set(PAIRED_CONTROLS.keys()) | set(PAIRED_CONTROLS.values())
    if scenario in hard_group:
        for idx in range(n):
            req = _default_request(scenario, idx)
            msg, max_t = _hard_context_payload(scenario, idx)
            req["messages"] = [{"role": "user", "content": msg}]
            req["max_tokens"] = max_t
            req["_capability_manifest"] = manifest
            requests.append(req)
        return _seed_shuffle(requests, scenario=scenario, seed=seed)

    for idx in range(n):
        req = _default_request(scenario, idx)
        req["_capability_manifest"] = manifest
        requests.append(req)
    return _seed_shuffle(requests, scenario=scenario, seed=seed)
