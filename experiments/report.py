"""Report generation for CSV and Markdown outputs."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import MetricRow

RESULTS_DIR = Path("results")
REPORT_CSV = RESULTS_DIR / "report.csv"
REPORT_MD = RESULTS_DIR / "report.md"


def write_report(rows: list[MetricRow]) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    header = (
        "baseline,scenario,attack_success_rate,cost_leakage_tokens,"
        "false_reject_rate,throttle_rate,p50_ms,p95_ms"
    )
    lines = [header]
    for row in rows:
        lines.append(
            f"{row.baseline},{row.scenario},{row.attack_success_rate:.4f},{row.cost_leakage_tokens},"
            f"{row.false_reject_rate:.4f},{row.throttle_rate:.4f},{row.p50_ms:.1f},{row.p95_ms:.1f}"
        )
    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    markdown = [
        "# Results Report",
        "",
        f"Generated {len(rows)} baseline/scenario metric rows from deterministic synthetic events.",
        "",
        "| baseline | scenario | attack_success_rate | cost_leakage_tokens | p50_ms | p95_ms |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        markdown.append(
            f"| {row.baseline} | {row.scenario} | {row.attack_success_rate:.4f} | "
            f"{row.cost_leakage_tokens} | {row.p50_ms:.1f} | {row.p95_ms:.1f} |"
        )
    REPORT_MD.write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return REPORT_CSV, REPORT_MD
