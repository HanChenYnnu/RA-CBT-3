"""Scenario catalog and deterministic request generators."""

from __future__ import annotations

SCENARIOS = {
    "S1_key_leak": 40,
    "S2_token_leak": 120,
    "S2a_token_leak_missing_dpop": 40,
    "S2b_token_leak_wrong_key_dpop": 40,
    "S3_replay": 120,
    "S4_burst": 1000,
    "S5_slowdrip": 300,
    "S6_drift": 150,
}


def _default_request(scenario: str, idx: int) -> dict[str, object]:
    return {
        "model": "gpt-mock",
        "scenario": scenario,
        "request_id": f"{scenario}-{idx}",
        "messages": [{"role": "user", "content": f"{scenario} payload {idx}"}],
        "max_tokens": 24,
        "x_forwarded_for": "10.0.0.10",
    }


def scenario_requests(scenario: str, n: int) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    if scenario == "S4_burst":
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["messages"] = [
                {"role": "user", "content": "burst load " + ("x" * ((idx % 20) + 20))}
            ]
            req["max_tokens"] = 32 + (idx % 64)
            requests.append(req)
        return requests

    if scenario == "S6_drift":
        boundary = max(1, n // 2)
        for idx in range(n):
            req = _default_request(scenario, idx)
            req["x_forwarded_for"] = (
                f"10.0.0.{(idx % 200) + 1}" if idx < boundary else f"203.0.113.{(idx % 200) + 1}"
            )
            requests.append(req)
        return requests

    for idx in range(n):
        requests.append(_default_request(scenario, idx))
    return requests
