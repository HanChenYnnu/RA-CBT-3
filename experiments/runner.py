"""Deterministic synthetic harness data generation."""

from __future__ import annotations

from dataclasses import dataclass

from experiments.mock_upstream import chat_completion


@dataclass(frozen=True)
class EventRow:
    baseline: str
    scenario: str
    status_code: int
    reason: str
    decision: str
    latency_ms: int
    usage_total_tokens: int
    benign: bool


def planned_baselines() -> list[str]:
    return ["B0", "B1", "B2", "B3", "B4"]


def _ok_event(
    baseline: str,
    scenario: str,
    prompt: str,
    max_tokens: int,
    latency_ms: int,
) -> EventRow:
    response = chat_completion(
        model="gpt-mock",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens,
        request_id=f"{baseline}-{scenario}-{latency_ms}",
    )
    usage_total_tokens = int(response["usage"]["total_tokens"])
    return EventRow(
        baseline=baseline,
        scenario=scenario,
        status_code=200,
        reason="ok",
        decision="allow",
        latency_ms=latency_ms,
        usage_total_tokens=usage_total_tokens,
        benign=scenario in {"S1_key_leak", "S6_drift"},
    )


def _deny_event(baseline: str, scenario: str, reason: str, latency_ms: int) -> EventRow:
    return EventRow(
        baseline=baseline,
        scenario=scenario,
        status_code=401,
        reason=reason,
        decision="deny",
        latency_ms=latency_ms,
        usage_total_tokens=0,
        benign=False,
    )


def synthetic_events() -> list[EventRow]:
    return [
        _ok_event("B0", "S4_burst", "burst prompt " * 100, 256, 35),
        _ok_event("B0", "S4_burst", "burst prompt " * 90, 220, 30),
        _ok_event("B2", "S2_token_leak", "stolen bearer token" * 6, 180, 28),
        _ok_event("B2", "S2_token_leak", "stolen bearer token" * 5, 120, 29),
        _deny_event("B3", "S2_token_leak", "dpop_missing", 24),
        _ok_event("B3", "S2_token_leak", "valid pop once", 40, 26),
        _deny_event("B4", "S2_token_leak", "jkt_mismatch", 26),
        _deny_event("B4", "S2_token_leak", "dpop_missing", 27),
        _ok_event("B2", "S3_replay", "replay accepted", 120, 33),
        _ok_event("B3", "S3_replay", "first request", 70, 31),
        _deny_event("B3", "S3_replay", "replay", 32),
        _ok_event("B4", "S3_replay", "first request", 70, 34),
        _deny_event("B4", "S3_replay", "replay", 35),
        _ok_event("B4", "S4_burst", "tight budget" * 10, 30, 36),
        _deny_event("B4", "S4_burst", "budget", 37),
        _ok_event("B1", "S1_key_leak", "benign traffic" * 5, 60, 25),
        _ok_event("B1", "S6_drift", "benign drift" * 7, 70, 27),
    ]
