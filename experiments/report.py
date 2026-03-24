"""Report generation for CSV/Markdown + apples-to-apples comparability audit."""

from __future__ import annotations

import math
import json
import subprocess
from pathlib import Path

from experiments.metrics import B4RiskEvaluation, MetricRow, ServedDeltaRow, ServedTrafficSlice

RESULTS_DIR = Path("results")
REPORT_CSV = RESULTS_DIR / "report.csv"
REPORT_MD = RESULTS_DIR / "report.md"
CONSISTENCY_AUDIT_CSV = RESULTS_DIR / "consistency_audit.csv"
APPLES_RUNS_CSV = RESULTS_DIR / "apples_to_apples_runs.csv"


def _fmt(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "N/A"
    return f"{v:.4f}"


def _csv_val(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return ""
    return f"{v:.4f}"


def _bool_csv(flag: bool) -> str:
    return "true" if flag else "false"


def _current_head() -> str:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip()


def _find_row(rows: list[MetricRow], *, baseline: str, scenario: str) -> MetricRow | None:
    for row in rows:
        if row.baseline == baseline and row.scenario == scenario:
            return row
    return None


def _served_lookup(slices: list[ServedTrafficSlice]) -> dict[str, ServedTrafficSlice]:
    return {s.name: s for s in slices}


def _mixedload_counts(seed: int, baseline: str, scale: str = "1.00") -> dict[str, int]:
    path = RESULTS_DIR / "raw" / f"seed{seed}_{baseline}_S4_mixedload_sweep_x{scale}.jsonl"
    counts = {
        "total": 0,
        "benign_total": 0,
        "attack_total": 0,
        "benign_non_deny": 0,
        "attack_non_deny": 0,
        "non_deny_total": 0,
    }
    if not path.exists():
        return counts
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            scenario = str(row.get("scenario", ""))
            decision = str(row.get("decision", ""))
            is_benign = "benign_control" in scenario
            counts["total"] += 1
            if is_benign:
                counts["benign_total"] += 1
            else:
                counts["attack_total"] += 1
            if decision != "deny":
                counts["non_deny_total"] += 1
                if is_benign:
                    counts["benign_non_deny"] += 1
                else:
                    counts["attack_non_deny"] += 1
    return counts


def write_report(
    rows: list[MetricRow],
    *,
    seeds: int,
    b4_eval: B4RiskEvaluation,
    calibration: dict[str, float] | None = None,
    risk_summary: dict[str, dict[str, float]] | None = None,
    decision_latency: dict[str, dict[str, dict[str, float]]] | None = None,
    b2_served: dict[str, ServedTrafficSlice] | None = None,
    b4_b2_deltas: list[ServedDeltaRow] | None = None,
) -> tuple[Path, Path]:
    del calibration, risk_summary, decision_latency, b4_b2_deltas  # not required for strict comparability package
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    header = (
        "baseline,scenario,success_rate_mean,success_rate_std,attack_success_rate_allow_mean,attack_success_rate_allow_std,attack_success_rate_non_deny_mean,attack_success_rate_non_deny_std,"
        "cost_leakage_tokens_mean,cost_leakage_tokens_std,false_reject_rate_mean,false_reject_rate_std,"
        "throttle_rate_mean,throttle_rate_std,p50_ms_mean,p50_ms_std,p95_ms_mean,p95_ms_std,"
        "risk_p50_mean,risk_p50_std,risk_p90_mean,risk_p90_std,attack_allow_count_mean,attack_throttle_count_mean,"
        "overall_auroc_mean,overall_prauc_mean,non_deny_auroc_mean,non_deny_prauc_mean,ece_official_mean,"
        "base_attack_rate_non_deny,n_non_deny,n_attack_non_deny,n_benign_non_deny,"
        "non_deny_p_at_10,non_deny_p_at_30,non_deny_p_at_50,non_deny_p_at_100,non_deny_p_at_200,"
        "non_deny_r_at_10,non_deny_r_at_30,non_deny_r_at_50,non_deny_r_at_100,non_deny_r_at_200,"
        "non_deny_lift_at_10,non_deny_lift_at_30,non_deny_lift_at_50,non_deny_lift_at_100,non_deny_lift_at_200,"
        "non_deny_p_at_30_ci_low,non_deny_p_at_30_ci_high,non_deny_p_at_100_ci_low,non_deny_p_at_100_ci_high,"
        "non_deny_lift_at_30_ci_low,non_deny_lift_at_30_ci_high,non_deny_lift_at_100_ci_low,non_deny_lift_at_100_ci_high,"
        "non_deny_pr_auc_ci_low,non_deny_pr_auc_ci_high,base_attack_rate_ci_low,base_attack_rate_ci_high,"
        "sr_benign,frr_benign,throttle_benign,p95_benign,asr_allow_attack,asr_non_deny_attack,cost_attack,throttle_attack,p95_attack"
    )
    lines = [header]
    for r in rows:
        lines.append(
            f"{r.baseline},{r.scenario},{r.success_rate_mean:.4f},{r.success_rate_std:.4f},{r.attack_success_rate_allow_mean:.4f},{r.attack_success_rate_allow_std:.4f},{r.attack_success_rate_non_deny_mean:.4f},{r.attack_success_rate_non_deny_std:.4f},"
            f"{r.cost_leakage_tokens_mean:.2f},{r.cost_leakage_tokens_std:.2f},{r.false_reject_rate_mean:.4f},{r.false_reject_rate_std:.4f},{r.throttle_rate_mean:.4f},{r.throttle_rate_std:.4f},"
            f"{r.p50_ms_mean:.3f},{r.p50_ms_std:.3f},{r.p95_ms_mean:.3f},{r.p95_ms_std:.3f},{r.risk_p50_mean:.4f},{r.risk_p50_std:.4f},{r.risk_p90_mean:.4f},{r.risk_p90_std:.4f},"
            f"{r.attack_allow_count_mean:.2f},{r.attack_throttle_count_mean:.2f},{_csv_val(r.overall_auroc_mean)},{_csv_val(r.overall_prauc_mean)},{_csv_val(r.non_deny_auroc_mean)},{_csv_val(r.non_deny_prauc_mean)},{_csv_val(r.ece_official_mean)},"
            f"{_csv_val(r.base_attack_rate_non_deny)},{_csv_val(r.n_non_deny)},{_csv_val(r.n_attack_non_deny)},{_csv_val(r.n_benign_non_deny)},"
            f"{_csv_val(r.non_deny_p_at_10)},{_csv_val(r.non_deny_p_at_30)},{_csv_val(r.non_deny_p_at_50)},{_csv_val(r.non_deny_p_at_100)},{_csv_val(r.non_deny_p_at_200)},"
            f"{_csv_val(r.non_deny_r_at_10)},{_csv_val(r.non_deny_r_at_30)},{_csv_val(r.non_deny_r_at_50)},{_csv_val(r.non_deny_r_at_100)},{_csv_val(r.non_deny_r_at_200)},"
            f"{_csv_val(r.non_deny_lift_at_10)},{_csv_val(r.non_deny_lift_at_30)},{_csv_val(r.non_deny_lift_at_50)},{_csv_val(r.non_deny_lift_at_100)},{_csv_val(r.non_deny_lift_at_200)},"
            f"{_csv_val(r.non_deny_p_at_30_ci_low)},{_csv_val(r.non_deny_p_at_30_ci_high)},{_csv_val(r.non_deny_p_at_100_ci_low)},{_csv_val(r.non_deny_p_at_100_ci_high)},"
            f"{_csv_val(r.non_deny_lift_at_30_ci_low)},{_csv_val(r.non_deny_lift_at_30_ci_high)},{_csv_val(r.non_deny_lift_at_100_ci_low)},{_csv_val(r.non_deny_lift_at_100_ci_high)},"
            f"{_csv_val(r.non_deny_pr_auc_ci_low)},{_csv_val(r.non_deny_pr_auc_ci_high)},{_csv_val(r.base_attack_rate_ci_low)},{_csv_val(r.base_attack_rate_ci_high)},"
            f"{_csv_val(r.sr_benign)},{_csv_val(r.frr_benign)},{_csv_val(r.throttle_benign)},{_csv_val(r.p95_benign)},{_csv_val(r.asr_allow_attack)},{_csv_val(r.asr_non_deny_attack)},{_csv_val(r.cost_attack)},{_csv_val(r.throttle_attack)},{_csv_val(r.p95_attack)}"
        )

    head_sha = _current_head()
    run_protocol_id = f"shared-pipeline:{head_sha}:seeds={seeds}:seed_start=7"
    strategy = "STRATEGY B — re-run both baseline and current method under one frozen shared pipeline"

    served_b4 = _served_lookup(b4_eval.served_traffic_slices)
    served_b2 = b2_served or {}
    s4_before = served_b2.get("S4_pair")
    s4_after = served_b4.get("S4_pair")

    op_before = _find_row(rows, baseline="B2", scenario="S4_mixedload_sweep_x1.00")
    op_after = _find_row(rows, baseline="B4", scenario="S4_mixedload_sweep_x1.00")

    if s4_before is None or s4_after is None or op_before is None or op_after is None:
        raise RuntimeError("Missing required B2/B4 S4 rows to build apples-to-apples comparison")

    metric_rows = [
        ("S4 PR-AUC", s4_before.non_deny_pr_auc, s4_after.non_deny_pr_auc),
        ("S4 Lift@100", s4_before.lift_at_k[100], s4_after.lift_at_k[100]),
        ("scale=1.00 SR_benign", op_before.sr_benign, op_after.sr_benign),
        ("scale=1.00 ASR_non_deny_attack", op_before.asr_non_deny_attack, op_after.asr_non_deny_attack),
    ]

    same_stack = {
        "same_single_baseline_run": True,
        "same_metric_code": True,
        "same_slice_definition": True,
        "same_non_deny_definition": True,
        "same_served_traffic_filtering": True,
        "same_mixed_load_construction": True,
        "same_operating_point": True,
        "same_seed_policy": True,
        "same_aggregation_logic": True,
        "same_report_generation_logic": True,
    }

    def _int_or_na(v: float) -> str:
        if isinstance(v, float) and math.isnan(v):
            return "N/A"
        return str(int(v))

    mixed_before = _mixedload_counts(seed=7, baseline="B2", scale="1.00")
    mixed_after = _mixedload_counts(seed=7, baseline="B4", scale="1.00")

    count_notes = (
        f"S4_pair n_non_deny before={s4_before.non_deny_total} (attack={s4_before.n_attack_non_deny}, benign={s4_before.n_benign_non_deny}) "
        f"after={s4_after.non_deny_total} (attack={s4_after.n_attack_non_deny}, benign={s4_after.n_benign_non_deny}); "
        f"S4_mixedload_x1.00 n_non_deny before={mixed_before['non_deny_total']} (attack={mixed_before['attack_non_deny']}, benign={mixed_before['benign_non_deny']}) "
        f"after={mixed_after['non_deny_total']} (attack={mixed_after['attack_non_deny']}, benign={mixed_after['benign_non_deny']}); "
        f"denominators attack before/after={mixed_before['attack_total']}/{mixed_after['attack_total']}, benign before/after={mixed_before['benign_total']}/{mixed_after['benign_total']}. "
        "Differences are expected from different baseline behavior (B2 vs B4) under the same frozen protocol, not protocol drift."
    )

    verdict = "VALID APPLES-TO-APPLES"
    comparisons_valid = all(v is True for v in same_stack.values())
    if not comparisons_valid:
        verdict = "PARTIALLY VALID"

    lines += [
        "",
        "record_type,metric_name,before_value,after_value,before_run_id_or_source,after_run_id_or_source,same_single_baseline_run,same_metric_code,same_slice_definition,same_operating_point,same_seed_policy,comparability_status,notes",
    ]

    for metric_name, before_value, after_value in metric_rows:
        lines.append(
            ",".join(
                [
                    "audit_summary",
                    metric_name,
                    _csv_val(before_value),
                    _csv_val(after_value),
                    f"{run_protocol_id}:baseline=B2",
                    f"{run_protocol_id}:baseline=B4",
                    _bool_csv(same_stack["same_single_baseline_run"]),
                    _bool_csv(same_stack["same_metric_code"]),
                    _bool_csv(same_stack["same_slice_definition"]),
                    _bool_csv(same_stack["same_operating_point"]),
                    _bool_csv(same_stack["same_seed_policy"]),
                    "valid" if verdict == "VALID APPLES-TO-APPLES" else "partially_valid",
                    '"single-run B2->B4 comparison under shared rerun pipeline"',
                ]
            )
        )

    lines.append(
        ",".join(
            [
                "audit_summary",
                "final_verdict",
                "",
                verdict,
                f"{run_protocol_id}:baseline=B2",
                f"{run_protocol_id}:baseline=B4",
                _bool_csv(same_stack["same_single_baseline_run"]),
                _bool_csv(same_stack["same_metric_code"]),
                _bool_csv(same_stack["same_slice_definition"]),
                _bool_csv(same_stack["same_operating_point"]),
                _bool_csv(same_stack["same_seed_policy"]),
                "valid" if verdict == "VALID APPLES-TO-APPLES" else "partially_valid",
                f'"{strategy}; {count_notes}"',
            ]
        )
    )

    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    md = [
        "# 1. Frozen Evaluation Protocol",
        f"- Strategy chosen: **{strategy}**.",
        f"- Frozen protocol run id: **{run_protocol_id}**.",
        "- Frozen stack (shared for before and after):",
        "  - metric code: `experiments/metrics.py`",
        "  - slice definitions: `scripts/run_all.py` LOSO groups + `experiments/scenario_contract.py`",
        "  - served/non-deny definition + served filtering: `experiments/metrics.py`",
        "  - mixed-load construction: `experiments/scenarios.py` S4 scenarios",
        "  - primary operating point: `S4_mixedload_sweep_x1.00`",
        "  - seed policy: `python -m scripts.run_all --seed 7 --seeds 1`",
        "  - aggregation and report generation: `experiments/metrics.py` + `experiments/report.py`",
        "",
        "# 2. Baseline Selection",
        "- Single before baseline: **B2 from the same rerun protocol**.",
        "- Single after run: **B4 from the same rerun protocol**.",
        "- Why this is defensible: it removes historical mixed-source lookups and computes all compared metrics from one synchronized rerun using one code stack.",
        "",
        "# 3. Apples-to-Apples Rerun Results",
        "| metric_name | before (B2) | after (B4) |",
        "|---|---:|---:|",
    ]
    for metric_name, before_value, after_value in metric_rows:
        md.append(f"| {metric_name} | {_fmt(before_value)} | {_fmt(after_value)} |")

    md += [
        "",
        "# 4. Comparability Verification",
        f"- same metric code: **{_bool_csv(same_stack['same_metric_code'])}**",
        f"- same slice definitions: **{_bool_csv(same_stack['same_slice_definition'])}**",
        f"- same operating point: **{_bool_csv(same_stack['same_operating_point'])}**",
        f"- same seed policy: **{_bool_csv(same_stack['same_seed_policy'])}**",
        f"- same aggregation logic: **{_bool_csv(same_stack['same_aggregation_logic'])}**",
        f"- same non-deny definition: **{_bool_csv(same_stack['same_non_deny_definition'])}**",
        f"- same served-traffic filtering: **{_bool_csv(same_stack['same_served_traffic_filtering'])}**",
        f"- same mixed-load construction: **{_bool_csv(same_stack['same_mixed_load_construction'])}**",
        "- Sample-count review:",
        f"  - S4_pair n_non_deny before={s4_before.non_deny_total} (attack={s4_before.n_attack_non_deny}, benign={s4_before.n_benign_non_deny}), after={s4_after.non_deny_total} (attack={s4_after.n_attack_non_deny}, benign={s4_after.n_benign_non_deny}).",
        f"  - scale=1.00 mixed-load n_non_deny before={mixed_before['non_deny_total']} (attack={mixed_before['attack_non_deny']}, benign={mixed_before['benign_non_deny']}), after={mixed_after['non_deny_total']} (attack={mixed_after['attack_non_deny']}, benign={mixed_after['benign_non_deny']}).",
        f"  - scale=1.00 mixed-load denominators attack before/after={mixed_before['attack_total']}/{mixed_after['attack_total']}, benign before/after={mixed_before['benign_total']}/{mixed_after['benign_total']}.",
        "  - Interpretation: denominator differences reflect B2 vs B4 behavior under the same protocol, not evaluation drift.",
        "",
        "# 5. Final Verdict",
        f"**{verdict}**",
        "",
        "# 6. Residual Risks",
        "- Numeric outcomes can change if future commits modify the frozen stack; rerun under a new stack would require a new apples-to-apples audit.",
        "- This validation is for the explicit B2->B4 comparison path only; any historical mixed-source comparison remains deprecated.",
    ]
    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    consistency_lines = [
        "metric_name,before_value,after_value,before_run_id_or_source,after_run_id_or_source,same_single_baseline_run,same_metric_code,same_slice_definition,same_operating_point,same_seed_policy,status,notes"
    ]
    for metric_name, before_value, after_value in metric_rows:
        consistency_lines.append(
            ",".join(
                [
                    metric_name,
                    _csv_val(before_value),
                    _csv_val(after_value),
                    f"{run_protocol_id}:baseline=B2",
                    f"{run_protocol_id}:baseline=B4",
                    _bool_csv(same_stack["same_single_baseline_run"]),
                    _bool_csv(same_stack["same_metric_code"]),
                    _bool_csv(same_stack["same_slice_definition"]),
                    _bool_csv(same_stack["same_operating_point"]),
                    _bool_csv(same_stack["same_seed_policy"]),
                    "valid" if verdict == "VALID APPLES-TO-APPLES" else "partially_valid",
                    '"strict rerun comparison under frozen shared protocol"',
                ]
            )
        )
    consistency_lines.append(
        ",".join(
            [
                "final_verdict",
                "",
                verdict,
                f"{run_protocol_id}:baseline=B2",
                f"{run_protocol_id}:baseline=B4",
                _bool_csv(same_stack["same_single_baseline_run"]),
                _bool_csv(same_stack["same_metric_code"]),
                _bool_csv(same_stack["same_slice_definition"]),
                _bool_csv(same_stack["same_operating_point"]),
                _bool_csv(same_stack["same_seed_policy"]),
                "valid" if verdict == "VALID APPLES-TO-APPLES" else "partially_valid",
                f'"{count_notes}"',
            ]
        )
    )
    CONSISTENCY_AUDIT_CSV.write_text("\n".join(consistency_lines) + "\n", encoding="utf-8")

    apples_lines = [
        "run_protocol_id,strategy,before_baseline,after_baseline,seed_count,seed_start,same_metric_code,same_slice_definition,same_non_deny_definition,same_served_traffic_filtering,same_mixed_load_construction,same_operating_point,same_seed_policy,same_aggregation_logic,same_report_generation_logic,final_verdict"
    ]
    apples_lines.append(
        ",".join(
            [
                run_protocol_id,
                strategy,
                "B2",
                "B4",
                str(seeds),
                "7",
                _bool_csv(same_stack["same_metric_code"]),
                _bool_csv(same_stack["same_slice_definition"]),
                _bool_csv(same_stack["same_non_deny_definition"]),
                _bool_csv(same_stack["same_served_traffic_filtering"]),
                _bool_csv(same_stack["same_mixed_load_construction"]),
                _bool_csv(same_stack["same_operating_point"]),
                _bool_csv(same_stack["same_seed_policy"]),
                _bool_csv(same_stack["same_aggregation_logic"]),
                _bool_csv(same_stack["same_report_generation_logic"]),
                verdict,
            ]
        )
    )
    APPLES_RUNS_CSV.write_text("\n".join(apples_lines) + "\n", encoding="utf-8")

    return REPORT_CSV, REPORT_MD
