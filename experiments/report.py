"""Report generation for CSV and Markdown outputs."""

from __future__ import annotations

import math
from pathlib import Path

from experiments.metrics import B4RiskEvaluation, K_VALUES, MetricRow, ServedDeltaRow, ServedTrafficSlice
from experiments.scenario_contract import PAIRED_CONTROLS

RESULTS_DIR = Path("results")
REPORT_CSV = RESULTS_DIR / "report.csv"
REPORT_MD = RESULTS_DIR / "report.md"


def _pm(mean: float, std: float, digits: int = 4) -> str:
    return f"{mean:.{digits}f}±{std:.{digits}f}"


def _fmt(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "N/A"
    return f"{v:.4f}"


def _csv_val(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return ""
    return f"{v:.4f}"


def write_report(rows: list[MetricRow], *, seeds: int, b4_eval: B4RiskEvaluation, calibration: dict[str, float] | None = None, risk_summary: dict[str, dict[str, float]] | None = None, decision_latency: dict[str, dict[str, dict[str, float]]] | None = None, b2_served: dict[str, ServedTrafficSlice] | None = None, b4_b2_deltas: list[ServedDeltaRow] | None = None) -> tuple[Path, Path]:
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
    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    md = ["# Results Report", "", f"Aggregated over **{seeds} seed(s)** with mean±std summary.", "", "## Paired Controls"]
    for atk, ctrl in PAIRED_CONTROLS.items():
        md.append(f"- {atk} ↔ {ctrl}")

    md += ["", "## B4 risk quality", f"- Overall AUROC: **{_fmt(b4_eval.overall_auroc)}**", f"- Overall PR-AUC: **{_fmt(b4_eval.overall_pr_auc)}**", f"- Non-deny (allow+throttle) AUROC: **{_fmt(b4_eval.non_deny_auroc)}**", f"- Non-deny (allow+throttle) PR-AUC: **{_fmt(b4_eval.non_deny_pr_auc)}**"]

    md += ["", "## Served-traffic ranking quality", ""]
    md += ["| slice | n_non_deny | n_attack_non_deny | n_benign_non_deny | base_attack_rate_non_deny | P@30 | lift@30 |", "|---|---:|---:|---:|---:|---:|---:|"]
    for s in b4_eval.served_traffic_slices:
        md.append(f"| {s.name} | {s.non_deny_total} | {s.n_attack_non_deny} | {s.n_benign_non_deny} | {_fmt(s.base_attack_rate_non_deny)} | {_fmt(s.p_at_k[30])} | {_fmt(s.lift_at_k[30])} |")

    md += ["", "## Bootstrap served-traffic ranking (B4)"]
    for pair_name in ["S1_pair", "S2_pair", "S3_pair"]:
        sp = next((s for s in b4_eval.served_traffic_slices if s.name == pair_name), None)
        if sp is None:
            continue
        md += ["", f"### {pair_name}", f"- counts: n_non_deny={sp.non_deny_total}, n_attack_non_deny={sp.n_attack_non_deny}, n_benign_non_deny={sp.n_benign_non_deny}", "", "| K | P@K (95% CI) | lift@K (95% CI) |", "|---:|---:|---:|"]
        for k in [10, 30, 100, 200]:
            p_lo, p_hi = sp.p_ci[k]
            l_lo, l_hi = sp.lift_ci[k]
            md.append(f"| {k} | {_fmt(sp.p_at_k[k])} [{_fmt(p_lo)}, {_fmt(p_hi)}] | {_fmt(sp.lift_at_k[k])} [{_fmt(l_lo)}, {_fmt(l_hi)}] |")
        md += [f"- non-deny PR-AUC: **{_fmt(sp.non_deny_pr_auc)}** [{_fmt(sp.non_deny_pr_auc_ci_low)}, {_fmt(sp.non_deny_pr_auc_ci_high)}]", f"- base attack rate non-deny: **{_fmt(sp.base_attack_rate_non_deny)}** [{_fmt(sp.base_attack_rate_ci_low)}, {_fmt(sp.base_attack_rate_ci_high)}]"]


    if b2_served:
        md += ["", "## B4 vs B2 served-traffic comparison", "", "| slice | B4 P@30 [CI] | B2 P@30 [CI] | ΔPR-AUC [CI] | ΔLift@30 [CI] | ΔLift@100 [CI] |", "|---|---:|---:|---:|---:|---:|"]
        delta_lookup = {d.slice_name: d for d in (b4_b2_deltas or [])}
        for pair_name in ["S1_pair", "S2_pair", "S3_pair", "overall"]:
            b4s = next((s for s in b4_eval.served_traffic_slices if s.name == pair_name), None)
            b2s = b2_served.get(pair_name)
            d = delta_lookup.get(pair_name)
            if b4s is None or b2s is None or d is None:
                continue
            md.append(
                f"| {pair_name} | {_fmt(b4s.p_at_k[30])} [{_fmt(b4s.p_ci[30][0])}, {_fmt(b4s.p_ci[30][1])}] | "
                f"{_fmt(b2s.p_at_k[30])} [{_fmt(b2s.p_ci[30][0])}, {_fmt(b2s.p_ci[30][1])}] | "
                f"{_fmt(d.delta_pr_auc)} [{_fmt(d.delta_pr_auc_ci_low)}, {_fmt(d.delta_pr_auc_ci_high)}] | "
                f"{_fmt(d.delta_lift_at_30)} [{_fmt(d.delta_lift_at_30_ci_low)}, {_fmt(d.delta_lift_at_30_ci_high)}] | "
                f"{_fmt(d.delta_lift_at_100)} [{_fmt(d.delta_lift_at_100_ci_low)}, {_fmt(d.delta_lift_at_100_ci_high)}] |"
            )

    md += ["", "## LOSO evaluation", "", "| heldout_group | non-deny PR-AUC | n_non_deny | n_attack_non_deny | n_benign_non_deny |", "|---|---:|---:|---:|---:|"]
    for r in b4_eval.loso_rows:
        md.append(f"| {r.heldout_scenario} | {_fmt(r.non_deny_pr_auc)} | {r.n_non_deny} | {r.n_attack_non_deny} | {r.n_benign_non_deny} |")

    sweep_rows = [r for r in rows if r.baseline == "B4" and r.scenario.startswith("S4_mixedload_sweep_x")]
    if sweep_rows:
        md += ["", "## Mixed-load contention sweep", "", "Label-split metrics are reported under shared queue/budget pressure so benign and attack traffic contend for the same limiter state.", "", "### Attack panel", "", "| scale | ASR_allow_attack | ASR_non_deny_attack | cost_attack | throttle_attack | p95_attack |", "|---:|---:|---:|---:|---:|---:|"]
        for r in sorted(sweep_rows, key=lambda x: x.scenario, reverse=True):
            sc = r.scenario.split("_x")[-1]
            md.append(f"| {sc} | {r.asr_allow_attack:.4f} | {r.asr_non_deny_attack:.4f} | {r.cost_attack:.2f} | {r.throttle_attack:.4f} | {r.p95_attack:.3f} |")
        md += ["", "### Benign panel", "", "| scale | SR_benign | FRR_benign | throttle_benign | p95_benign |", "|---:|---:|---:|---:|---:|"]
        for r in sorted(sweep_rows, key=lambda x: x.scenario, reverse=True):
            sc = r.scenario.split("_x")[-1]
            md.append(f"| {sc} | {r.sr_benign:.4f} | {r.frr_benign:.4f} | {r.throttle_benign:.4f} | {r.p95_benign:.3f} |")

    md += ["", "## Metric definitions", "- SR (success_rate): 2xx + reason=ok over all requests.", "- ASR_allow: decision=allow and 2xx + reason=ok over all requests.", "- ASR_non_deny: decision in {allow, throttle} and 2xx + reason=ok over all requests."]

    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    return REPORT_CSV, REPORT_MD
