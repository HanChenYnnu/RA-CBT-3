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


def assert_defensibility_gates(rows: list[MetricRow], b4_eval: B4RiskEvaluation, *, b2_served: dict[str, object], b4_b2_deltas: list[object]) -> None:
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

    for _, control in PAIRED_CONTROLS.items():
        c = _pick(rows, "B4", control)
        if c.false_reject_rate_mean > 0.05 or c.throttle_rate_mean > 0.15 or c.attack_success_rate_allow_mean < 0.95:
            raise AssertionError("Defensibility failure: hard scenario semantics or controls are broken.")

    # calibration honesty
    if b4_eval.ece_calibrated > b4_eval.ece_raw + 0.02:
        raise AssertionError("Calibration honesty gate failed: calibrated ECE worsened > 0.02.")

    pair_served = {}
    for pair_name in ["S1_pair", "S2_pair", "S3_pair"]:
        served = next((ss for ss in b4_eval.served_traffic_slices if ss.name == pair_name), None)
        if served is None:
            raise AssertionError(f"Defensibility failure: {pair_name} served-traffic slice missing.")
        pair_served[pair_name] = served
        if served.n_attack_non_deny < 50:
            raise AssertionError(f"Served-traffic evidence insufficient for {pair_name}")
        if served.n_benign_non_deny < 100:
            raise AssertionError(f"Served-traffic evidence insufficient for {pair_name}")
        if served.p_at_k[30] is None or served.lift_at_k[30] is None or served.p_at_k[100] is None or served.lift_at_k[100] is None:
            raise AssertionError(f"Defensibility failure: {pair_name} top-k metrics undefined.")

    if pair_served["S1_pair"].p_at_k[30] < 0.20 or pair_served["S1_pair"].lift_at_k[30] < 2.0:
        raise AssertionError("Defensibility failure: S1_pair P@30/lift@30 thresholds not met.")
    if pair_served["S2_pair"].p_at_k[30] < 0.20 or pair_served["S2_pair"].lift_at_k[30] < 2.0:
        raise AssertionError("Defensibility failure: S2_pair P@30/lift@30 thresholds not met.")

    saturation_pairs = 0
    for pair_name in ["S1_pair", "S2_pair", "S3_pair"]:
        sp = pair_served[pair_name]
        if sp.p_at_k[100] is not None and sp.p_at_k[100] < 1.0 and sp.lift_at_k[100] is not None and sp.lift_at_k[100] >= 2.0:
            saturation_pairs += 1
    if saturation_pairs < 1:
        raise AssertionError("Served-traffic ranking still too easy / saturated.")

    delta_lookup = {d.slice_name: d for d in b4_b2_deltas}
    lift_sig_pairs = sum(1 for name in ["S1_pair", "S2_pair", "S3_pair"] if name in delta_lookup and delta_lookup[name].delta_lift_at_100_ci_low is not None and delta_lookup[name].delta_lift_at_100_ci_low > 0)
    pr_sig_pairs = sum(1 for name in ["S1_pair", "S2_pair", "S3_pair"] if name in delta_lookup and delta_lookup[name].delta_pr_auc_ci_low is not None and delta_lookup[name].delta_pr_auc_ci_low > 0)
    if lift_sig_pairs < 2 or pr_sig_pairs < 1:
        raise AssertionError("B4 does not significantly outperform B2 on harder served-traffic ranking.")

    for pair_name in ["S1_pair", "S2_pair", "S3_pair"]:
        b2 = b2_served.get(pair_name)
        if b2 is None or b2.p_at_k[30] is None:
            raise AssertionError(f"Defensibility failure: B2 served slice missing/undefined for {pair_name}.")


def assert_budget_sweep_gates(rows: list[MetricRow]) -> None:
    sweep = sorted([r for r in rows if r.baseline == "B4" and r.scenario.startswith("S4_mixedload_sweep_x")], key=lambda r: r.scenario, reverse=True)
    if len(sweep) < 4:
        raise AssertionError("Budget sweep failed: expected at least 4 sweep rows for B4.")

    costs = [r.cost_attack for r in sweep]
    for i in range(1, len(costs)):
        if costs[i] > costs[i - 1] * 1.05:
            raise AssertionError("Budget sweep failed: attack cost increased as budget scale decreased.")

    highest = sweep[-1]
    if not (highest.sr_benign < 1.0):
        raise AssertionError("Budget sweep failed: highest-contention SR_benign must be < 1.0.")
    if highest.frr_benign > 0.03:
        raise AssertionError("Budget sweep failed: highest-contention FRR_benign > 0.03.")
    if not (highest.throttle_benign > 0.0):
        raise AssertionError("Budget sweep failed: highest-contention throttle_benign must be > 0.0.")

    asr = [r.asr_allow_attack for r in sweep]
    for i in range(1, len(asr)):
        if asr[i] > asr[i - 1] + 0.02:
            raise AssertionError("Budget sweep failed: ASR_allow_attack materially increased as scale tightened.")

    asr_nd = [r.asr_non_deny_attack for r in sweep]
    for i in range(1, len(asr_nd)):
        if asr_nd[i] > asr_nd[i - 1] + 0.03:
            raise AssertionError("Budget sweep failed: ASR_non_deny_attack materially increased as scale tightened.")

    if all(abs(r.sr_benign - 1.0) < 1e-9 and abs(r.frr_benign) < 1e-9 and abs(r.throttle_benign) < 1e-9 for r in sweep):
        raise AssertionError("Budget sweep failed: benign panel is perfectly flat across scales.")

    baseline_cost = sweep[0].cost_attack
    if not any(r.cost_attack <= baseline_cost * 0.70 for r in sweep[1:]):
        raise AssertionError("Budget sweep failed: no useful operating point reducing attack cost.")

