"""SVG-only plot generation for deterministic metric rows."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import MetricRow

PLOTS_DIR = Path("results/plots")


def _bars_svg(title: str, labels: list[str], values: list[float], ymax: float) -> str:
    width = 640
    height = 300
    left = 40
    base_y = 240
    step = max(80, int((width - 2 * left) / max(1, len(values))))
    max_height = 160

    pieces = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}'>",
        "<rect width='100%' height='100%' fill='white'/>",
        f"<text x='20' y='30' font-size='20'>{title}</text>",
        f"<line x1='{left}' y1='{base_y}' x2='{width-left}' y2='{base_y}' stroke='black'/>",
    ]
    for idx, value in enumerate(values):
        x = left + idx * step + 12
        bar_h = 0 if ymax <= 0 else int((value / ymax) * max_height)
        y = base_y - bar_h
        pieces.append(f"<rect x='{x}' y='{y}' width='36' height='{bar_h}' fill='#4f46e5'/>")
        pieces.append(f"<text x='{x-2}' y='{base_y+16}' font-size='11'>{labels[idx][:10]}</text>")
    pieces.append("</svg>")
    return "".join(pieces)


def generate_plots(rows: list[MetricRow]) -> list[Path]:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    labels = [f"{row.baseline}-{row.scenario}" for row in rows]

    attack_vals = [row.attack_success_rate for row in rows]
    cost_vals = [float(row.cost_leakage_tokens) for row in rows]
    p95_vals = [row.p95_ms for row in rows]

    plots = [
        (
            PLOTS_DIR / "attack_success.svg",
            _bars_svg("Attack Success Rate", labels, attack_vals, 1.0),
        ),
        (
            PLOTS_DIR / "cost_leakage.svg",
            _bars_svg("Cost Leakage Tokens", labels, cost_vals, max(cost_vals or [1.0])),
        ),
        (
            PLOTS_DIR / "latency_p95.svg",
            _bars_svg("Latency P95 (ms)", labels, p95_vals, max(p95_vals or [1.0])),
        ),
    ]

    written: list[Path] = []
    for path, svg in plots:
        path.write_text(svg, encoding="utf-8")
        written.append(path)
    return written
