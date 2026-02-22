"""SVG-only plots."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import MetricRow, ReliabilityBin, RiskPoint

PLOTS_DIR = Path("results/plots")


def _line_svg(title: str, series: dict[str, list[tuple[float, float]]], xlabel: str, ylabel: str, path: Path) -> Path:
    w, h, m = 640, 420, 50
    xs = [x for pts in series.values() for x, _ in pts] or [0.0, 1.0]
    ys = [y for pts in series.values() for _, y in pts] or [0.0, 1.0]
    minx, maxx = min(xs), max(xs)
    miny, maxy = min(ys), max(ys)
    if maxx == minx:
        maxx = minx + 1.0
    if maxy == miny:
        maxy = miny + 1.0

    colors = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e"]
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">']
    parts += [f'<text x="20" y="24" font-size="16">{title}</text>']
    parts += [f'<line x1="{m}" y1="{h-m}" x2="{w-m}" y2="{h-m}" stroke="black"/>']
    parts += [f'<line x1="{m}" y1="{h-m}" x2="{m}" y2="{m}" stroke="black"/>']
    parts += [f'<text x="{w//2}" y="{h-10}" font-size="12">{xlabel}</text>']
    parts += [f'<text x="10" y="{h//2}" font-size="12" transform="rotate(-90 10,{h//2})">{ylabel}</text>']

    for idx, (name, pts) in enumerate(series.items()):
        col = colors[idx % len(colors)]
        coords = []
        for x, y in pts:
            sx = m + (x - minx) / (maxx - minx) * (w - 2 * m)
            sy = (h - m) - (y - miny) / (maxy - miny) * (h - 2 * m)
            coords.append(f"{sx:.1f},{sy:.1f}")
        if coords:
            parts += [f'<polyline fill="none" stroke="{col}" stroke-width="2" points="{" ".join(coords)}"/>']
            lx = w - m - 130
            ly = 35 + idx * 16
            parts += [f'<line x1="{lx}" y1="{ly}" x2="{lx+20}" y2="{ly}" stroke="{col}" stroke-width="2"/>']
            parts += [f'<text x="{lx+24}" y="{ly+4}" font-size="11">{name}</text>']
    parts += ["</svg>"]
    path.write_text("\n".join(parts), encoding="utf-8")
    return path


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
        if i % max(1, len(rows) // 10) == 0:
            parts.append(
                f'<text x="{x}" y="{height-25}" font-size="8" transform="rotate(60 {x},{height-25})">{row.baseline}-{row.scenario}</text>'
            )
    parts.append("</svg>")
    return "\n".join(parts)


def generate_plots(
    rows: list[MetricRow],
    *,
    roc_points: list[RiskPoint],
    reliability_bins: list[ReliabilityBin],
) -> list[Path]:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    out.append(PLOTS_DIR / "attack_success.svg")
    out[-1].write_text(_bars_svg(rows, "attack_success_rate_mean", "Attack Success Rate (mean)"), encoding="utf-8")
    out.append(PLOTS_DIR / "cost_leakage.svg")
    out[-1].write_text(_bars_svg(rows, "cost_leakage_tokens_mean", "Cost Leakage Tokens (mean)"), encoding="utf-8")
    out.append(PLOTS_DIR / "latency_p95.svg")
    out[-1].write_text(_bars_svg(rows, "p95_ms_mean", "Latency p95 (mean ms)"), encoding="utf-8")

    roc_series = {"B4 ROC": [(p.fpr, p.tpr) for p in roc_points], "Random": [(0.0, 0.0), (1.0, 1.0)]}
    out.append(_line_svg("B4 Risk ROC", roc_series, "FPR", "TPR", PLOTS_DIR / "b4_risk_roc.svg"))

    rel_series = {
        "Calibration": [(b.mean_pred, b.empirical_attack_rate) for b in reliability_bins],
        "Perfect": [(0.0, 0.0), (1.0, 1.0)],
    }
    out.append(_line_svg("B4 Reliability Diagram", rel_series, "Mean predicted risk", "Empirical attack rate", PLOTS_DIR / "b4_reliability.svg"))

    def _pick(b: str, s: str, attr: str) -> float:
        for r in rows:
            if r.baseline == b and r.scenario == s:
                return float(getattr(r, attr))
        return 0.0

    levels = ["S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4"]
    x = [1.0, 2.0, 3.0, 4.0]
    cost_series = {
        "B0": list(zip(x, [_pick("B0", s, "cost_leakage_tokens_mean") for s in levels])),
        "B4": list(zip(x, [_pick("B4", s, "cost_leakage_tokens_mean") for s in levels])),
    }
    out.append(_line_svg("Burst Cost vs Load Level", cost_series, "Load level", "Cost tokens", PLOTS_DIR / "burst_cost_curve.svg"))

    asr_series = {
        "B0": list(zip(x, [_pick("B0", s, "attack_success_rate_mean") for s in levels])),
        "B4": list(zip(x, [_pick("B4", s, "attack_success_rate_mean") for s in levels])),
    }
    out.append(_line_svg("Burst ASR vs Load Level", asr_series, "Load level", "ASR", PLOTS_DIR / "burst_asr_curve.svg"))

    thr_series = {"B4 throttle": list(zip(x, [_pick("B4", s, "throttle_rate_mean") for s in levels]))}
    out.append(_line_svg("Burst Throttle vs Load Level", thr_series, "Load level", "Throttle rate", PLOTS_DIR / "burst_throttle_curve.svg"))

    risk_cdf_points = []
    for bucket in ["benign", "attack"]:
        vals = sorted([r.risk_p50_mean for r in rows if r.baseline == "B4" and r.risk_p50_mean >= 0 and ((bucket == "attack" and "S" in r.scenario and r.scenario not in {"S5_slowdrip", "S6_drift", "S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4", "S4_burst"}) or (bucket=="benign" and r.scenario in {"S5_slowdrip","S6_drift","S4_burst_L1","S4_burst_L2","S4_burst_L3","S4_burst_L4","S4_burst"}))])
        pts=[(v,(i+1)/max(1,len(vals))) for i,v in enumerate(vals)]
        risk_cdf_points.append((bucket,pts))
    out.append(_line_svg("B4 Risk CDF (scenario-level)", {k:v for k,v in risk_cdf_points}, "Risk", "CDF", PLOTS_DIR / "b4_risk_cdf.svg"))
    return out
