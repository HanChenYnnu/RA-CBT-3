"""Hard delta checks and defensibility gates."""

from __future__ import annotations

import math
from collections.abc import Iterable

from experiments.metrics import B4RiskEvaluation, MetricRow

HARD_ATTACK_SCENARIOS = ["S1_key_leak_hard", "S2_token_leak_hard", "S3_replay_hard"]


def _pick(rows: Iterable[MetricRow], baseline: str, scenario: str) -> MetricRow:
    for row in rows:
        if row.baseline == baseline and row.scenario == scenario:
            return row
    raise AssertionError(f"Missing row for {baseline}/{scenario}")


def assert_required_security_deltas(rows: list[MetricRow]) -> None:
    b2_s2 = _pick(rows, "B2", "S2_token_leak")
    b3_s2 = _pick(rows, "B3", "S2_token_leak")
    b4_s2 = _pick(rows, "B4", "S2_token_leak")
    assert b2_s2.attack_success_rate_mean >= 0.5
    assert b3_s2.attack_success_rate_mean <= 0.05
    assert b4_s2.attack_success_rate_mean <= 0.05

    b2_s3 = _pick(rows, "B2", "S3_replay")
    b3_s3 = _pick(rows, "B3", "S3_replay")
    b4_s3 = _pick(rows, "B4", "S3_replay")
    assert b3_s3.attack_success_rate_mean < b2_s3.attack_success_rate_mean
    assert b4_s3.attack_success_rate_mean < b2_s3.attack_success_rate_mean

    b0_l4 = _pick(rows, "B0", "S4_burst_L4")
    b4_l4 = _pick(rows, "B4", "S4_burst_L4")
    assert b4_l4.cost_leakage_tokens_mean <= b0_l4.cost_leakage_tokens_mean / 5.0


def assert_defensibility_gates(rows: list[MetricRow], b4_eval: B4RiskEvaluation) -> None:
    for scenario in HARD_ATTACK_SCENARIOS:
        row = _pick(rows, "B4", scenario)
        if not (row.attack_allow_count_mean >= 5 or row.attack_throttle_count_mean >= 5):
            raise AssertionError("Not defensible: too few surviving attacks.")

    if b4_eval.overall_auroc is not None and b4_eval.overall_auroc >= 0.99:
        if (b4_eval.allowed_only_pr_auc is None or b4_eval.allowed_only_pr_auc < 0.10) or (
            b4_eval.loso_mean_pr_auc is None or b4_eval.loso_mean_pr_auc < 0.10
        ):
            raise AssertionError("Not defensible: high AUROC without allowed-only/LOSO evidence.")

    s5 = _pick(rows, "B4", "S5_slowdrip")
    s6 = _pick(rows, "B4", "S6_drift")
    assert s5.throttle_rate_mean <= 0.10
    assert s5.attack_success_rate_mean >= 0.95
    assert s5.false_reject_rate_mean <= 0.02
    assert 0.20 <= s6.throttle_rate_mean <= 0.60
    assert s6.attack_success_rate_mean >= 0.90
    assert s6.false_reject_rate_mean <= 0.02

    if b4_eval.ece_calibrated > b4_eval.ece_raw + 0.02:
        raise AssertionError("Calibration honesty gate failed: calibrated ECE worsened > 0.02.")

    s2_hard = _pick(rows, "B4", "S2_token_leak_hard")
    if s2_hard.attack_success_rate_mean > 0.05:
        raise AssertionError("Semantic violation: attacker likely has PoP key or exchange path was used.")


def fmt_metric(value: float | None) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "N/A"
    return f"{value:.4f}"
