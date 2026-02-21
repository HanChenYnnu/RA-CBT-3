"""Scenario catalog and deterministic request generators."""

from __future__ import annotations

SCENARIOS = {
    "S1_key_leak": 40,
    "S2a_token_leak_missing_dpop": 40,
    "S2b_token_leak_wrong_key_dpop": 40,
    "S3_replay": 120,
    "S4_burst": 1000,
    "S5_slowdrip": 300,
    "S6_drift": 150,
}


def scenario_requests(scenario: str, n: int) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []
    if scenario == "S4_burst":
        for idx in range(n):
            text = "burst load " + ("x" * ((idx % 20) + 20))
            requests.append(
                {
                    "model": "gpt-mock",
                    "scenario": scenario,
                    "request_id": f"{scenario}-{idx}",
                    "messages": [{"role": "user", "content": text}],
                    "max_tokens": 32 + (idx % 64),
                    "x_forwarded_for": "10.0.0.10",
                }
            )
        return requests

    if scenario == "S6_drift":
        boundary = max(1, n // 2)
        for idx in range(n):
            if idx < boundary:
                ip = f"10.0.0.{(idx % 200) + 1}"
            else:
                ip = f"203.0.113.{(idx % 200) + 1}"
            requests.append(
                {
                    "model": "gpt-mock",
                    "scenario": scenario,
                    "request_id": f"{scenario}-{idx}",
                    "messages": [{"role": "user", "content": f"drift event {idx}"}],
                    "max_tokens": 40,
                    "x_forwarded_for": ip,
                }
            )
        return requests

    return requests
