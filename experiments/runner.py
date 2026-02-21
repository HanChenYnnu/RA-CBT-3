"""Deterministic stage0 runner data."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MetricRow:
    baseline: str
    scenario: str
    attack_success_rate: float
    cost_leakage_tokens: int
    false_reject_rate: float
    throttle_rate: float
    p50_ms: int
    p95_ms: int


def planned_baselines() -> list[str]:
    return ["B0", "B1", "B2", "B3", "B4"]


def synthetic_rows() -> list[MetricRow]:
    return [
        MetricRow("B0", "S4_burst", 1.0, 10000, 0.0, 0.0, 22, 51),
        MetricRow("B2", "S2_token_leak", 0.8, 5200, 0.01, 0.01, 23, 55),
        MetricRow("B3", "S2_token_leak", 0.02, 400, 0.02, 0.01, 24, 60),
        MetricRow("B4", "S2_token_leak", 0.01, 300, 0.02, 0.02, 25, 62),
        MetricRow("B2", "S3_replay", 0.6, 3000, 0.01, 0.02, 22, 53),
        MetricRow("B3", "S3_replay", 0.05, 700, 0.02, 0.02, 24, 58),
        MetricRow("B4", "S3_replay", 0.03, 600, 0.01, 0.03, 26, 61),
        MetricRow("B4", "S4_burst", 0.2, 1500, 0.03, 0.3, 30, 75),
    ]
