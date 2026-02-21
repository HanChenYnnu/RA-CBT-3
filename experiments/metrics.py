"""Metrics computation over synthetic event rows."""

from __future__ import annotations

from dataclasses import dataclass

from experiments.types import EventRow


@dataclass(frozen=True)
class MetricRow:
    baseline: str
    scenario: str
    attack_success_rate: float
    cost_leakage_tokens: int
    false_reject_rate: float
    throttle_rate: float
    p50_ms: float
    p95_ms: float


def attack_success_rate(success_ok: int, total: int) -> float:
    return 0.0 if total == 0 else success_ok / total


def _percentile(values: list[int], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * percentile))
    return float(ordered[index])


def compute_metrics(events: list[EventRow]) -> list[MetricRow]:
    grouped: dict[tuple[str, str], list[EventRow]] = {}
    for event in events:
        grouped.setdefault((event.baseline, event.scenario), []).append(event)

    rows: list[MetricRow] = []
    for (baseline, scenario), bucket in sorted(grouped.items()):
        total = len(bucket)
        success_ok = sum(1 for row in bucket if 200 <= row.status_code < 300 and row.reason == "ok")
        cost_sum = sum(row.usage_total_tokens for row in bucket if row.usage_total_tokens > 0)
        benign = [row for row in bucket if row.benign]
        benign_den = max(1, len(benign))
        false_reject = sum(1 for row in benign if row.decision == "deny") / benign_den
        throttle = sum(1 for row in benign if row.decision == "throttle") / benign_den
        latencies = [row.latency_ms for row in bucket]
        rows.append(
            MetricRow(
                baseline=baseline,
                scenario=scenario,
                attack_success_rate=attack_success_rate(success_ok, total),
                cost_leakage_tokens=cost_sum,
                false_reject_rate=false_reject,
                throttle_rate=throttle,
                p50_ms=_percentile(latencies, 0.5),
                p95_ms=_percentile(latencies, 0.95),
            )
        )
    return rows
