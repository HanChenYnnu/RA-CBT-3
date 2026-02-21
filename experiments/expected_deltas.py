"""Hard delta checks required by prompts."""

from __future__ import annotations

from collections.abc import Iterable

from experiments.metrics import MetricRow


def _pick(rows: Iterable[MetricRow], baseline: str, scenario: str) -> MetricRow:
    for row in rows:
        if row.baseline == baseline and row.scenario == scenario:
            return row
    raise AssertionError(f"Missing row for {baseline}/{scenario}")


def assert_b2_b3_deltas(rows: list[MetricRow]) -> None:
    b2_s2 = _pick(rows, "B2", "S2_token_leak")
    b3_s2 = _pick(rows, "B3", "S2_token_leak")
    assert b2_s2.attack_success_rate >= 0.5
    assert b3_s2.attack_success_rate <= 0.05

    b2_s3 = _pick(rows, "B2", "S3_replay")
    b3_s3 = _pick(rows, "B3", "S3_replay")
    assert b3_s3.attack_success_rate < b2_s3.attack_success_rate
