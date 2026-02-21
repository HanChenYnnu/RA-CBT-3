"""SVG-only plots (no external plotting dependency)."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import MetricRow, RiskPoint

PLOTS_DIR = Path("results/plots")


def _bars_svg(rows: list[MetricRow], value_attr: str, title: str) -> str:
    width = 1200
    height = 420
    margin = 40
    bar_w = max(6, int((width - 2 * margin) / max(1, len(rows))))
    values = [float(getattr(r, value_attr)) for r in rows]
    vmax = max(values) if values else 1.0
    if vmax <= 0:
        vmax = 1.0
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        f'<text x="20" y="20" font-size="16">{title}</text>',
        f'<line x1="{margin}" y1="{height-40}" x2="{width-margin}" y2="{height-40}" stroke="black"/>',
    ]
    for i, row in enumerate(rows):
        v = values[i]
        h = int((height - 90) * (v / vmax))
        x = margin + i * bar_w
        y = (height - 40) - h
        parts.append(f'<rect x="{x}" y="{y}" width="{max(2, bar_w-1)}" height="{h}" fill="#4682b4"/>')
        if i % max(1, len(rows)//10) == 0:
            parts.append(f'<text x="{x}" y="{height-25}" font-size="8" transform="rotate(60 {x},{height-25})">{row.baseline}-{row.scenario}</text>')
    parts.append('</svg>')
    return "\n".join(parts)


def _roc_svg(points: list[RiskPoint]) -> str:
    width = 420
    height = 420
    margin = 40
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<text x="20" y="20" font-size="16">B4 Risk ROC</text>',
        f'<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="black"/>',
        f'<line x1="{margin}" y1="{height-margin}" x2="{margin}" y2="{margin}" stroke="black"/>',
        f'<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{margin}" stroke="#999" stroke-dasharray="4 4"/>',
    ]
    if points:
        coords = []
        for p in points:
            x = margin + int((width - 2 * margin) * p.fpr)
            y = (height - margin) - int((height - 2 * margin) * p.tpr)
            coords.append(f"{x},{y}")
        parts.append(f'<polyline fill="none" stroke="#d62728" stroke-width="2" points="{" ".join(coords)}"/>')
    parts.append('</svg>')
    return "\n".join(parts)


def generate_plots(rows: list[MetricRow], *, roc_points: list[RiskPoint]) -> list[Path]:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    paths = [
        PLOTS_DIR / "attack_success.svg",
        PLOTS_DIR / "cost_leakage.svg",
        PLOTS_DIR / "latency_p95.svg",
        PLOTS_DIR / "b4_risk_roc.svg",
    ]
    paths[0].write_text(_bars_svg(rows, "attack_success_rate_mean", "Attack Success Rate (mean)"), encoding="utf-8")
    paths[1].write_text(_bars_svg(rows, "cost_leakage_tokens_mean", "Cost Leakage Tokens (mean)"), encoding="utf-8")
    paths[2].write_text(_bars_svg(rows, "p95_ms_mean", "Latency p95 (mean ms)"), encoding="utf-8")
    paths[3].write_text(_roc_svg(roc_points), encoding="utf-8")
    return paths
