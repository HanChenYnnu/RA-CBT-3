"""Hard delta checks and defensibility gates."""

from __future__ import annotations

from collections.abc import Iterable

from experiments.metrics import B4RiskEvaluation, MetricRow
from experiments.scenario_contract import PAIRED_CONTROLS

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
    assert b2_s2.attack_success_rate_allow_mean >= 0.5
    assert b3_s2.attack_success_rate_allow_mean <= 0.05
    assert b4_s2.attack_success_rate_allow_mean <= 0.05

    b2_s3 = _pick(rows, "B2", "S3_replay")
    b3_s3 = _pick(rows, "B3", "S3_replay")
    b4_s3 = _pick(rows, "B4", "S3_replay")
    assert b3_s3.attack_success_rate_allow_mean < b2_s3.attack_success_rate_allow_mean
    assert b4_s3.attack_success_rate_allow_mean < b2_s3.attack_success_rate_allow_mean

    b0_l4 = _pick(rows, "B0", "S4_burst_L4")
    b4_l4 = _pick(rows, "B4", "S4_burst_L4")
    assert b4_l4.cost_leakage_tokens_mean <= b0_l4.cost_leakage_tokens_mean / 5.0


def assert_defensibility_gates(rows: list[MetricRow], b4_eval: B4RiskEvaluation) -> None:
    # hard semantic attack ASR gates
    if _pick(rows, "B4", "S1_key_leak_hard").attack_success_rate_allow_mean > 0.10:
        raise AssertionError("Defensibility failure: hard scenario semantics or controls are broken.")
    if _pick(rows, "B4", "S2_token_leak_hard").attack_success_rate_allow_mean > 0.05:
        raise AssertionError("Defensibility failure: hard scenario semantics or controls are broken.")
    if _pick(rows, "B4", "S3_replay_hard").attack_success_rate_allow_mean > 0.05:
        raise AssertionError("Defensibility failure: hard scenario semantics or controls are broken.")
    if _pick(rows, "B3", "S2_token_leak_hard").attack_success_rate_allow_mean > 0.05:
        raise AssertionError("Defensibility failure: B3 S2 hard gate broken.")
    if _pick(rows, "B3", "S3_replay_hard").attack_success_rate_allow_mean > 0.05:
        raise AssertionError("Defensibility failure: B3 S3 hard gate broken.")
    if _pick(rows, "B2", "S2_token_leak_hard").attack_success_rate_allow_mean < 0.5:
        raise AssertionError("Defensibility failure: B2 S2 hard should remain high without PoP.")

    # paired benign usability gates
    for _, control in PAIRED_CONTROLS.items():
        c = _pick(rows, "B4", control)
        if c.false_reject_rate_mean > 0.05 or c.throttle_rate_mean > 0.15 or c.attack_success_rate_allow_mean < 0.95:
            raise AssertionError("Defensibility failure: hard scenario semantics or controls are broken.")

    # drift usability gates
    s5 = _pick(rows, "B4", "S5_slowdrip")
    s6 = _pick(rows, "B4", "S6_drift")
    assert s5.throttle_rate_mean <= 0.10
    assert s5.success_rate_mean >= 0.95
    assert s5.false_reject_rate_mean <= 0.02
    assert 0.15 <= s6.throttle_rate_mean <= 0.60
    assert s6.success_rate_mean >= 0.90
    assert s6.false_reject_rate_mean <= 0.02


    # usability polish targets
    b4_s6 = _pick(rows, "B4", "S6_drift")
    b0_s6 = _pick(rows, "B0", "S6_drift")
    if b4_s6.attack_success_rate_allow_mean < 0.70:
        raise AssertionError("Usability target failed: B4 S6_drift ASR_allow < 0.70")
    if b4_s6.false_reject_rate_mean > 0.02:
        raise AssertionError("Usability target failed: B4 S6_drift FRR > 0.02")
    if not (0.15 <= b4_s6.throttle_rate_mean <= 0.60):
        raise AssertionError("Usability target failed: B4 S6_drift throttle outside [0.15,0.60]")
    if b4_s6.cost_leakage_tokens_mean > 1.25 * b0_s6.cost_leakage_tokens_mean:
        raise AssertionError("Usability target failed: B4 S6_drift cost exceeds +25% of B0")

    b4_s1 = _pick(rows, "B4", "S1_key_leak")
    b0_s1 = _pick(rows, "B0", "S1_key_leak")
    if b4_s1.success_rate_mean < 0.70:
        raise AssertionError("Usability target failed: B4 S1_key_leak SR < 0.70")
    if b4_s1.attack_success_rate_allow_mean > 0.10:
        raise AssertionError("Usability target failed: B4 S1_key_leak ASR_allow > 0.10")
    if b4_s1.attack_success_rate_non_deny_mean < 0.60:
        raise AssertionError("Usability target failed: B4 S1_key_leak ASR_non_deny < 0.60")
    if b4_s1.cost_leakage_tokens_mean > 0.35 * b0_s1.cost_leakage_tokens_mean:
        raise AssertionError("Usability target failed: B4 S1_key_leak cost too high")

    # calibration honesty
    if b4_eval.ece_calibrated > b4_eval.ece_raw + 0.02:
        raise AssertionError("Calibration honesty gate failed: calibrated ECE worsened > 0.02.")

    # N/A metric guard
    if b4_eval.macro_family_auroc == 0.0:
        raise AssertionError("Macro AUROC suspiciously zero; single-class metrics may be coerced.")

    # latency realism reject paths
    s2 = _pick(rows, "B4", "S2_token_leak")
    s3 = _pick(rows, "B4", "S3_replay")
    if (s2.p95_ms_std > 0.0 or s3.p95_ms_std > 0.0) and (s2.p95_ms_std < 0.20 or s3.p95_ms_std < 0.20):
        raise AssertionError("Latency realism gate failed: reject path too uniform.")
    if (s2.p95_ms_std > 0.0 or s3.p95_ms_std > 0.0) and abs(s2.p95_ms_mean - s3.p95_ms_mean) < 0.10:
        raise AssertionError("Latency realism gate failed: reject path too uniform.")

    s3_pair = next((r for r in b4_eval.loso_rows if r.heldout_scenario == "S3_pair"), None)
    if s3_pair is None or s3_pair.n_attack_non_deny < 30:
        raise AssertionError("Defensibility failure: S3_pair must include at least 30 non-deny attack samples.")

    s3_served = next((s for s in b4_eval.served_traffic_slices if s.name == "S3_pair"), None)
    if s3_served is None or s3_served.p_at_k[30] is None or s3_served.lift_at_k[30] is None:
        raise AssertionError("Defensibility failure: S3_pair served-traffic metrics are undefined.")
    if s3_served.p_at_k[30] < 0.25:
        raise AssertionError("Defensibility failure: S3_pair non_deny_p_at_30 below threshold.")
    if s3_served.lift_at_k[30] < 3.0:
        raise AssertionError("Defensibility failure: S3_pair lift@30 below threshold.")

    p30_ci = s3_served.p_ci[30]
    if p30_ci[0] is None or p30_ci[1] is None or (p30_ci[1] - p30_ci[0]) >= 0.5:
        raise AssertionError("Defensibility failure: S3_pair p@30 CI width is too wide.")


def assert_budget_sweep_gates(rows: list[MetricRow]) -> None:
    sweep = sorted([r for r in rows if r.baseline == "B4" and r.scenario.startswith("S4_budget_sweep_x")], key=lambda r: r.scenario, reverse=True)
    if len(sweep) < 4:
        raise AssertionError("Budget sweep failed: expected at least 4 sweep rows for B4.")

    costs = [r.cost_attack for r in sweep]
    for i in range(1, len(costs)):
        if costs[i] > costs[i - 1] * 1.05:
            raise AssertionError("Budget sweep failed: attack cost increased as budget scale decreased.")

    for r in sweep:
        if r.sr_benign < 0.90 or r.frr_benign > 0.02:
            raise AssertionError("Budget sweep failed: benign usability violated.")

    asr = [r.asr_allow_attack for r in sweep]
    if all(asr[i] < asr[i + 1] for i in range(len(asr) - 1)):
        raise AssertionError("Budget sweep failed: ASR_allow_attack increases monotonically as scale tightens.")
