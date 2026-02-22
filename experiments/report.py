"""Report generation for CSV and Markdown outputs."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import MetricRow, ReliabilityBin

RESULTS_DIR = Path("results")
REPORT_CSV = RESULTS_DIR / "report.csv"
REPORT_MD = RESULTS_DIR / "report.md"


def _pm(mean: float, std: float, digits: int = 4) -> str:
    return f"{mean:.{digits}f}±{std:.{digits}f}"


def write_report(
    rows: list[MetricRow],
    *,
    seeds: int,
    calibration: dict[str, float] | None = None,
    b4_auroc: float = 0.0,
    b4_brier: float = 0.0,
    b4_ece: float = 0.0,
    reliability_bins: list[ReliabilityBin] | None = None,
    risk_summary: dict[str, dict[str, float]] | None = None,
) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    header = (
        "baseline,scenario,attack_success_rate_mean,attack_success_rate_std,"
        "cost_leakage_tokens_mean,cost_leakage_tokens_std,false_reject_rate_mean,false_reject_rate_std,"
        "throttle_rate_mean,throttle_rate_std,p50_ms_mean,p50_ms_std,p95_ms_mean,p95_ms_std,"
        "risk_p50_mean,risk_p50_std,risk_p90_mean,risk_p90_std"
    )
    lines = [header]
    for row in rows:
        lines.append(
            f"{row.baseline},{row.scenario},{row.attack_success_rate_mean:.4f},{row.attack_success_rate_std:.4f},"
            f"{row.cost_leakage_tokens_mean:.2f},{row.cost_leakage_tokens_std:.2f},"
            f"{row.false_reject_rate_mean:.4f},{row.false_reject_rate_std:.4f},"
            f"{row.throttle_rate_mean:.4f},{row.throttle_rate_std:.4f},"
            f"{row.p50_ms_mean:.3f},{row.p50_ms_std:.3f},{row.p95_ms_mean:.3f},{row.p95_ms_std:.3f},"
            f"{row.risk_p50_mean:.4f},{row.risk_p50_std:.4f},{row.risk_p90_mean:.4f},{row.risk_p90_std:.4f}"
        )
    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    markdown = [
        "# Results Report",
        "",
        f"Aggregated over **{seeds} seed(s)** with mean±std summary.",
        "",
        f"B4 risk AUROC: **{b4_auroc:.4f}**, Brier: **{b4_brier:.4f}**, ECE(10): **{b4_ece:.4f}**.",
        "",
        "## Risk statistics note",
        "- Risk is computed pre-decision in B4 request handling.",
        "- Samples with risk=-1 are excluded from AUROC/calibration/percentiles.",
        "- Higher risk means more attack-like behavior; attack is positive label.",
    ]
    if calibration:
        markdown.extend(
            [
                "",
                "## B4 calibration",
                f"- tau_allow={calibration.get('tau_allow', 0.0):.4f}, tau_deny={calibration.get('tau_deny', 0.0):.4f}",
                f"- tau_allow_exchange={calibration.get('tau_allow_exchange', 0.0):.4f}, tau_deny_exchange={calibration.get('tau_deny_exchange', 0.0):.4f}",
            ]
        )

    if risk_summary:
        markdown.extend(["", "## B4 risk distribution (group-wise)", "", "| group | n | p50 | p90 |", "|---|---:|---:|---:|"])
        for group, stats in risk_summary.items():
            markdown.append(f"| {group} | {int(stats['n'])} | {stats['p50']:.4f} | {stats['p90']:.4f} |")

    if reliability_bins:
        markdown.extend(["", "## Reliability table (10 bins)", "", "| bin | mean_pred | empirical_attack_rate | count |", "|---|---:|---:|---:|"])
        for b in reliability_bins:
            markdown.append(
                f"| [{b.bin_lo:.1f},{b.bin_hi:.1f}) | {b.mean_pred:.4f} | {b.empirical_attack_rate:.4f} | {b.count} |"
            )

    markdown.extend(
        [
            "",
            "| baseline | scenario | ASR (mean±std) | cost (mean±std) | FRR (mean±std) | throttle (mean±std) | p95 ms (mean±std) | risk p50 |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in rows:
        markdown.append(
            f"| {row.baseline} | {row.scenario} | {_pm(row.attack_success_rate_mean, row.attack_success_rate_std)} | "
            f"{_pm(row.cost_leakage_tokens_mean, row.cost_leakage_tokens_std, 2)} | "
            f"{_pm(row.false_reject_rate_mean, row.false_reject_rate_std)} | "
            f"{_pm(row.throttle_rate_mean, row.throttle_rate_std)} | "
            f"{_pm(row.p95_ms_mean, row.p95_ms_std, 3)} | "
            f"{row.risk_p50_mean:.4f} |"
        )

    REPORT_MD.write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return REPORT_CSV, REPORT_MD
