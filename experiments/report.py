"""Report generation for CSV and Markdown outputs."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import MetricRow

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
) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    header = (
        "baseline,scenario,attack_success_rate_mean,attack_success_rate_std,"
        "cost_leakage_tokens_mean,cost_leakage_tokens_std,false_reject_rate_mean,false_reject_rate_std,"
        "throttle_rate_mean,throttle_rate_std,p50_ms_mean,p50_ms_std,p95_ms_mean,p95_ms_std"
    )
    lines = [header]
    for row in rows:
        lines.append(
            f"{row.baseline},{row.scenario},{row.attack_success_rate_mean:.4f},{row.attack_success_rate_std:.4f},"
            f"{row.cost_leakage_tokens_mean:.2f},{row.cost_leakage_tokens_std:.2f},"
            f"{row.false_reject_rate_mean:.4f},{row.false_reject_rate_std:.4f},"
            f"{row.throttle_rate_mean:.4f},{row.throttle_rate_std:.4f},"
            f"{row.p50_ms_mean:.2f},{row.p50_ms_std:.2f},{row.p95_ms_mean:.2f},{row.p95_ms_std:.2f}"
        )
    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    markdown = [
        "# Results Report",
        "",
        f"Aggregated over **{seeds} seed(s)** with mean±std summary.",
        "",
        f"B4 risk AUROC: **{b4_auroc:.4f}**.",
    ]
    if calibration:
        markdown.extend(
            [
                "",
                "## B4 calibration",
                f"- tau_allow={calibration.get('tau_allow', 0.0):.4f}, tau_deny={calibration.get('tau_deny', 0.0):.4f}",
                f"- tau_allow_exchange={calibration.get('tau_allow_exchange', 0.0):.4f}, "
                f"tau_deny_exchange={calibration.get('tau_deny_exchange', 0.0):.4f}",
                f"- benign_risk_p50={calibration.get('benign_risk_p50', 0.0):.4f}, "
                f"attack_risk_p50={calibration.get('attack_risk_p50', 0.0):.4f}",
            ]
        )

    markdown.extend(
        [
            "",
            "| baseline | scenario | ASR (mean±std) | cost (mean±std) | FRR (mean±std) | throttle (mean±std) | p95 ms (mean±std) |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in rows:
        markdown.append(
            f"| {row.baseline} | {row.scenario} | {_pm(row.attack_success_rate_mean, row.attack_success_rate_std)} | "
            f"{_pm(row.cost_leakage_tokens_mean, row.cost_leakage_tokens_std, 2)} | "
            f"{_pm(row.false_reject_rate_mean, row.false_reject_rate_std)} | "
            f"{_pm(row.throttle_rate_mean, row.throttle_rate_std)} | "
            f"{_pm(row.p95_ms_mean, row.p95_ms_std, 2)} |"
        )

    REPORT_MD.write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return REPORT_CSV, REPORT_MD
