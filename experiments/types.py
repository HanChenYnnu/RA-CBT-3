"""Shared datatypes for experiment events."""

from __future__ import annotations

from dataclasses import dataclass


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
    risk: float
    seed: int
    label: str
