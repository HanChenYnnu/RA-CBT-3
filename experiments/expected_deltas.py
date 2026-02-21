"""Hard delta checks required by prompt."""

from __future__ import annotations

from collections.abc import Iterable

from experiments.runner import MetricRow


def _pick(rows: Iterable[MetricRow], baseline: str, scenario: str) -> MetricRow:
    for row in rows:
        if row.baseline == baseline and row.scenario == scenario:
            return row
    raise AssertionError(f"Missing row for {baseline}/{scenario}")


def assert_required_deltas(rows: list[MetricRow]) -> None:
    b2_s2 = _pick(rows, "B2", "S2_token_leak")
    b3_s2 = _pick(rows, "B3", "S2_token_leak")
    b4_s2 = _pick(rows, "B4", "S2_token_leak")
    assert b3_s2.attack_success_rate <= 0.05
    assert b4_s2.attack_success_rate <= 0.05
    assert b2_s2.attack_success_rate >= 0.5

    b2_s3 = _pick(rows, "B2", "S3_replay")
    b3_s3 = _pick(rows, "B3", "S3_replay")
    b4_s3 = _pick(rows, "B4", "S3_replay")
    assert b3_s3.attack_success_rate < (b2_s3.attack_success_rate / 2)
    assert b4_s3.attack_success_rate < (b2_s3.attack_success_rate / 2)

    b0_s4 = _pick(rows, "B0", "S4_burst")
    b4_s4 = _pick(rows, "B4", "S4_burst")
    assert b4_s4.cost_leakage_tokens <= (b0_s4.cost_leakage_tokens / 5)
