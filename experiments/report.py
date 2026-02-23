"""Report generation for CSV and Markdown outputs."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import B4RiskEvaluation, MetricRow

RESULTS_DIR = Path("results")
REPORT_CSV = RESULTS_DIR / "report.csv"
REPORT_MD = RESULTS_DIR / "report.md"


def _pm(mean: float, std: float, digits: int = 4) -> str:
    return f"{mean:.{digits}f}±{std:.{digits}f}"


def write_report(
    rows: list[MetricRow],
    *,
    seeds: int,
    b4_eval: B4RiskEvaluation,
    calibration: dict[str, float] | None = None,
    risk_summary: dict[str, dict[str, float]] | None = None,
) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    header = (
        "baseline,scenario,attack_success_rate_mean,attack_success_rate_std,"
        "cost_leakage_tokens_mean,cost_leakage_tokens_std,false_reject_rate_mean,false_reject_rate_std,"
        "throttle_rate_mean,throttle_rate_std,p50_ms_mean,p50_ms_std,p95_ms_mean,p95_ms_std,"
        "risk_p50_mean,risk_p50_std,risk_p90_mean,risk_p90_std,"
        "attack_allow_count_mean,attack_throttle_count_mean,overall_auroc_mean,overall_prauc_mean,"
        "allowed_only_auroc_mean,allowed_only_prauc_mean,ece_calibrated_mean"
    )
    lines = [header]
    for row in rows:
        lines.append(
            f"{row.baseline},{row.scenario},{row.attack_success_rate_mean:.4f},{row.attack_success_rate_std:.4f},"
            f"{row.cost_leakage_tokens_mean:.2f},{row.cost_leakage_tokens_std:.2f},"
            f"{row.false_reject_rate_mean:.4f},{row.false_reject_rate_std:.4f},"
            f"{row.throttle_rate_mean:.4f},{row.throttle_rate_std:.4f},"
            f"{row.p50_ms_mean:.3f},{row.p50_ms_std:.3f},{row.p95_ms_mean:.3f},{row.p95_ms_std:.3f},"
            f"{row.risk_p50_mean:.4f},{row.risk_p50_std:.4f},{row.risk_p90_mean:.4f},{row.risk_p90_std:.4f},"
            f"{row.attack_allow_count_mean:.2f},{row.attack_throttle_count_mean:.2f},"
            f"{row.overall_auroc_mean:.4f},{row.overall_prauc_mean:.4f},"
            f"{row.allowed_only_auroc_mean:.4f},{row.allowed_only_prauc_mean:.4f},{row.ece_calibrated_mean:.4f}"
        )
    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    md = [
        "# Results Report",
        "",
        f"Aggregated over **{seeds} seed(s)** with mean±std summary.",
        "",
        "## B4 risk quality",
        f"- Overall AUROC: **{b4_eval.overall_auroc:.4f}**",
        f"- Overall PR-AUC: **{b4_eval.overall_pr_auc:.4f}**",
        f"- Allowed-only AUROC: **{b4_eval.allowed_only_auroc:.4f}**",
        f"- Allowed-only PR-AUC: **{b4_eval.allowed_only_pr_auc:.4f}**",
        f"- Scenario-macro AUROC: **{b4_eval.macro_scenario_auroc:.4f}**",
        f"- Scenario-macro PR-AUC: **{b4_eval.macro_scenario_pr_auc:.4f}**",
        f"- Calibrated Brier/ECE: **{b4_eval.brier_calibrated:.4f} / {b4_eval.ece_calibrated:.4f}**",
        f"- Raw Brier/ECE: **{b4_eval.brier_raw:.4f} / {b4_eval.ece_raw:.4f}**",
        "",
        "## Confusion matrix @ ~1% benign FPR operating point",
        f"- Threshold: **{b4_eval.operating_point_threshold:.4f}**",
        f"- TP/FP/TN/FN: **{b4_eval.confusion_tp}/{b4_eval.confusion_fp}/{b4_eval.confusion_tn}/{b4_eval.confusion_fn}**",
        "",
        "## Why AUROC is not tautological",
        "- Risk is computed from request/auth/context features before allow/throttle/deny decisioning.",
        "- Risk computation does not read scenario labels, attack/benign tags, or benchmark-only flags.",
        "- Anti-leakage tests enforce code-path scan and scenario-tag invariance.",
    ]

    if calibration:
        md.extend(
            [
                "",
                "## B4 calibration thresholds",
                f"- tau_allow={calibration.get('tau_allow', 0.0):.4f}, tau_deny={calibration.get('tau_deny', 0.0):.4f}",
                f"- tau_allow_exchange={calibration.get('tau_allow_exchange', 0.0):.4f}, tau_deny_exchange={calibration.get('tau_deny_exchange', 0.0):.4f}",
            ]
        )

    md.extend(["", "## LOSO evaluation", "", "| heldout_scenario | AUROC | PR-AUC | allowed-only PR-AUC | ECE | Brier |", "|---|---:|---:|---:|---:|---:|"])
    for r in b4_eval.loso_rows:
        md.append(f"| {r.heldout_scenario} | {r.auroc:.4f} | {r.pr_auc:.4f} | {r.allowed_only_pr_auc:.4f} | {r.ece:.4f} | {r.brier:.4f} |")

    if risk_summary:
        md.extend(["", "## B4 risk distribution (group-wise)", "", "| group | n | p50 | p90 |", "|---|---:|---:|---:|"])
        for group, stats in risk_summary.items():
            md.append(f"| {group} | {int(stats['n'])} | {stats['p50']:.4f} | {stats['p90']:.4f} |")

    md.extend(
        [
            "",
            "| baseline | scenario | ASR (mean±std) | cost (mean±std) | FRR (mean±std) | throttle (mean±std) | p95 ms (mean±std) | attack allow | attack throttle |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in rows:
        md.append(
            f"| {row.baseline} | {row.scenario} | {_pm(row.attack_success_rate_mean, row.attack_success_rate_std)} | "
            f"{_pm(row.cost_leakage_tokens_mean, row.cost_leakage_tokens_std, 2)} | "
            f"{_pm(row.false_reject_rate_mean, row.false_reject_rate_std)} | "
            f"{_pm(row.throttle_rate_mean, row.throttle_rate_std)} | "
            f"{_pm(row.p95_ms_mean, row.p95_ms_std, 3)} | "
            f"{row.attack_allow_count_mean:.2f} | {row.attack_throttle_count_mean:.2f} |"
        )

    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    return REPORT_CSV, REPORT_MD
