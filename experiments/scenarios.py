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
    if scenario != "S4_burst":
        return []
    requests: list[dict[str, object]] = []
    for idx in range(n):
        text = "burst load " + ("x" * ((idx % 20) + 20))
        requests.append(
            {
                "model": "gpt-mock",
                "scenario": scenario,
                "request_id": f"{scenario}-{idx}",
                "messages": [{"role": "user", "content": text}],
                "max_tokens": 32 + (idx % 64),
            }
        )
    return requests
