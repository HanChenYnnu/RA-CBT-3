"""Report generation for CSV and Markdown outputs."""

from __future__ import annotations

import math
from pathlib import Path

from experiments.metrics import B4RiskEvaluation, MetricRow
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


def write_report(rows: list[MetricRow], *, seeds: int, b4_eval: B4RiskEvaluation, calibration: dict[str, float] | None = None, risk_summary: dict[str, dict[str, float]] | None = None, decision_latency: dict[str, dict[str, dict[str, float]]] | None = None) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    header = (
        "baseline,scenario,attack_success_rate_mean,attack_success_rate_std,"
        "cost_leakage_tokens_mean,cost_leakage_tokens_std,false_reject_rate_mean,false_reject_rate_std,"
        "throttle_rate_mean,throttle_rate_std,p50_ms_mean,p50_ms_std,p95_ms_mean,p95_ms_std,"
        "risk_p50_mean,risk_p50_std,risk_p90_mean,risk_p90_std,"
        "attack_allow_count_mean,attack_throttle_count_mean,overall_auroc_mean,overall_prauc_mean,"
        "non_deny_auroc_mean,non_deny_prauc_mean,ece_official_mean"
    )
    lines = [header]
    for r in rows:
        lines.append(
            f"{r.baseline},{r.scenario},{r.attack_success_rate_mean:.4f},{r.attack_success_rate_std:.4f},"
            f"{r.cost_leakage_tokens_mean:.2f},{r.cost_leakage_tokens_std:.2f},{r.false_reject_rate_mean:.4f},{r.false_reject_rate_std:.4f},"
            f"{r.throttle_rate_mean:.4f},{r.throttle_rate_std:.4f},{r.p50_ms_mean:.3f},{r.p50_ms_std:.3f},{r.p95_ms_mean:.3f},{r.p95_ms_std:.3f},"
            f"{r.risk_p50_mean:.4f},{r.risk_p50_std:.4f},{r.risk_p90_mean:.4f},{r.risk_p90_std:.4f},"
            f"{r.attack_allow_count_mean:.2f},{r.attack_throttle_count_mean:.2f},{_csv_val(r.overall_auroc_mean)},"
            f"{_csv_val(r.overall_prauc_mean)},{_csv_val(r.non_deny_auroc_mean)},{_csv_val(r.non_deny_prauc_mean)},{_csv_val(r.ece_official_mean)}"
        )
    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    md = [
        "# Results Report", "", f"Aggregated over **{seeds} seed(s)** with mean±std summary.", "",
        "## Paired Controls",
    ]
    for atk, ctrl in PAIRED_CONTROLS.items():
        md.append(f"- {atk} ↔ {ctrl}")

    md += [
        "", "## B4 risk quality",
        f"- Overall AUROC: **{_fmt(b4_eval.overall_auroc)}**",
        f"- Overall PR-AUC: **{_fmt(b4_eval.overall_pr_auc)}**",
        f"- Non-deny (allow+throttle) AUROC: **{_fmt(b4_eval.non_deny_auroc)}**",
        f"- Non-deny (allow+throttle) PR-AUC: **{_fmt(b4_eval.non_deny_pr_auc)}**",
        f"- Macro over attack families (excludes N/A): AUROC **{_fmt(b4_eval.macro_family_auroc)}**, PR-AUC **{_fmt(b4_eval.macro_family_pr_auc)}**",
        "- Macro metrics definition: average only scenarios/families with both labels; single-class AUROC/PR-AUC are N/A and excluded. Non-deny metrics require MIN_NON_DENY samples.",
        f"- Official Brier/ECE: **{b4_eval.brier_official:.4f} / {b4_eval.ece_official:.4f}**",
        f"- Calibrated Brier/ECE: **{b4_eval.brier_calibrated:.4f} / {b4_eval.ece_calibrated:.4f}**",
        f"- Raw Brier/ECE: **{b4_eval.brier_raw:.4f} / {b4_eval.ece_raw:.4f}**",
    ]
    if b4_eval.calibration_fallback_used:
        md.append("- Calibration fallback used (calibrated worsened).")

    md += [
        "", "## Confusion matrix @ ~1% benign FPR operating point",
        f"- Threshold: **{b4_eval.operating_point_threshold:.4f}**",
        f"- TP/FP/TN/FN: **{b4_eval.confusion_tp}/{b4_eval.confusion_fp}/{b4_eval.confusion_tn}/{b4_eval.confusion_fn}**",
        "", "## LOSO evaluation", "", "| heldout_group | AUROC | PR-AUC | non-deny AUROC | non-deny PR-AUC | n_total | n_non_deny | n_attack_non_deny | n_benign_non_deny | ECE | Brier |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in b4_eval.loso_rows:
        md.append(f"| {r.heldout_scenario} | {_fmt(r.auroc)} | {_fmt(r.pr_auc)} | {_fmt(r.non_deny_auroc)} | {_fmt(r.non_deny_pr_auc)} | {r.n_total} | {r.n_non_deny} | {r.n_attack_non_deny} | {r.n_benign_non_deny} | {r.ece:.4f} | {r.brier:.4f} |")

    if calibration:
        md += ["", "## B4 calibration thresholds", f"- tau_allow={calibration.get('tau_allow', 0.0):.4f}, tau_deny={calibration.get('tau_deny', 0.0):.4f}"]


    if decision_latency:
        md += ["", "## Latency by decision"]
        for baseline, table in decision_latency.items():
            md.append(f"- **{baseline}**")
            for decision, stats in table.items():
                md.append(f"  - {decision}: n={int(stats['n'])}, mean={stats['mean']:.3f}ms, p95={stats['p95']:.3f}ms")

    if risk_summary:
        md += ["", "## B4 risk distribution (group-wise)", "", "| group | n | p50 | p90 |", "|---|---:|---:|---:|"]
        for group, stats in risk_summary.items():
            md.append(f"| {group} | {int(stats['n'])} | {stats['p50']:.4f} | {stats['p90']:.4f} |")

    md += ["", "| baseline | scenario | ASR (mean±std) | cost (mean±std) | FRR (mean±std) | throttle (mean±std) | p95 ms (mean±std) | attack allow | attack throttle |", "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        md.append(f"| {r.baseline} | {r.scenario} | {_pm(r.attack_success_rate_mean, r.attack_success_rate_std)} | {_pm(r.cost_leakage_tokens_mean, r.cost_leakage_tokens_std, 2)} | {_pm(r.false_reject_rate_mean, r.false_reject_rate_std)} | {_pm(r.throttle_rate_mean, r.throttle_rate_std)} | {_pm(r.p95_ms_mean, r.p95_ms_std, 3)} | {r.attack_allow_count_mean:.2f} | {r.attack_throttle_count_mean:.2f} |")

    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    return REPORT_CSV, REPORT_MD
