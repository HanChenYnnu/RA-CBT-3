"""SVG plotting utilities for deterministic experiment outputs."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import B4RiskEvaluation, MetricRow

PLOTS_DIR = Path("results/plots")


def _line_svg(title: str, series: dict[str, list[tuple[float, float]]], xlabel: str, ylabel: str, path: Path, labels: list[tuple[float, float, str]] | None = None) -> Path:
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
            lx = w - m - 140
            ly = 35 + idx * 16
            parts += [f'<line x1="{lx}" y1="{ly}" x2="{lx+20}" y2="{ly}" stroke="{col}" stroke-width="2"/>']
            parts += [f'<text x="{lx+24}" y="{ly+4}" font-size="11">{name}</text>']

    if labels:
        for x, y, text in labels:
            sx = m + (x - minx) / (maxx - minx) * (w - 2 * m)
            sy = (h - m) - (y - miny) / (maxy - miny) * (h - 2 * m)
            parts += [f'<circle cx="{sx:.1f}" cy="{sy:.1f}" r="3" fill="#111"/>', f'<text x="{sx+5:.1f}" y="{sy-5:.1f}" font-size="10">{text}</text>']
    parts += ["</svg>"]
    path.write_text("\n".join(parts), encoding="utf-8")
    return path


def generate_plots(rows: list[MetricRow], *, b4_eval: B4RiskEvaluation) -> list[Path]:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []

    out.append(_line_svg("B4 Risk ROC", {"ROC": [(p.x, p.y) for p in b4_eval.roc_points], "Random": [(0.0, 0.0), (1.0, 1.0)]}, "FPR", "TPR", PLOTS_DIR / "b4_risk_roc.svg"))
    out.append(_line_svg("B4 Precision-Recall", {"PR": [(p.x, p.y) for p in b4_eval.pr_points]}, "Recall", "Precision", PLOTS_DIR / "b4_risk_pr.svg"))
    out.append(_line_svg("B4 Non-deny (allow+throttle) Precision-Recall", {"Non-deny PR": [(p.x, p.y) for p in b4_eval.non_deny_pr_points]}, "Recall", "Precision", PLOTS_DIR / "b4_allowed_pr.svg"))
    out.append(_line_svg("B4 Non-deny Risk CDF", {"attack": [(p.x, p.y) for p in b4_eval.non_deny_attack_cdf_points], "benign": [(p.x, p.y) for p in b4_eval.non_deny_benign_cdf_points]}, "Risk", "CDF", PLOTS_DIR / "b4_risk_cdf.svg"))
    out.append(_line_svg("B4 Reliability Diagram", {"Calibration": [(b.mean_pred, b.empirical_attack_rate) for b in b4_eval.reliability_bins], "Perfect": [(0.0, 0.0), (1.0, 1.0)]}, "Mean predicted risk", "Empirical attack rate", PLOTS_DIR / "b4_reliability.svg"))

    def _pick(b: str, s: str, attr: str) -> float:
        for r in rows:
            if r.baseline == b and r.scenario == s:
                return float(getattr(r, attr))
        return 0.0

    levels = ["S4_burst_L1", "S4_burst_L2", "S4_burst_L3", "S4_burst_L4"]
    x = [1.0, 2.0, 3.0, 4.0]
    out.append(_line_svg("Burst Cost vs Load Level", {
        "B0": list(zip(x, [_pick("B0", s, "cost_leakage_tokens_mean") for s in levels])),
        "B4": list(zip(x, [_pick("B4", s, "cost_leakage_tokens_mean") for s in levels])),
    }, "Load level", "Cost tokens", PLOTS_DIR / "burst_cost_curve.svg"))
    out.append(_line_svg("Burst ASR_allow vs Load Level", {
        "B0": list(zip(x, [_pick("B0", s, "attack_success_rate_allow_mean") for s in levels])),
        "B4": list(zip(x, [_pick("B4", s, "attack_success_rate_allow_mean") for s in levels])),
    }, "Load level", "ASR_allow", PLOTS_DIR / "burst_asr_curve.svg"))
    out.append(_line_svg("Burst Throttle vs Load Level", {
        "B4 throttle": list(zip(x, [_pick("B4", s, "throttle_rate_mean") for s in levels]))
    }, "Load level", "Throttle rate", PLOTS_DIR / "burst_throttle_curve.svg"))
    out.append(_line_svg("B4 Burst Tradeoff (ASR_allow/ASR_non_deny/cost/throttle)", {
        "ASR_allow": list(zip(x, [_pick("B4", s, "attack_success_rate_allow_mean") for s in levels])),
        "ASR_non_deny": list(zip(x, [_pick("B4", s, "attack_success_rate_non_deny_mean") for s in levels])),
        "Throttle": list(zip(x, [_pick("B4", s, "throttle_rate_mean") for s in levels])),
        "Cost/1000": list(zip(x, [_pick("B4", s, "cost_leakage_tokens_mean") / 1000.0 for s in levels])),
    }, "Load level", "Metric value", PLOTS_DIR / "b4_burst_tradeoff.svg"))

    sweep = sorted([r for r in rows if r.baseline == "B4" and r.scenario.startswith("S4_budget_sweep_x")], key=lambda r: r.scenario, reverse=True)
    if sweep:
        labels = [(r.cost_leakage_tokens_mean, r.attack_success_rate_allow_mean, r.scenario.split("_x")[-1]) for r in sweep]
        out.append(_line_svg("B4 Budget Sweep: Cost vs ASR_allow", {"Pareto": [(r.cost_leakage_tokens_mean, r.attack_success_rate_allow_mean) for r in sweep]}, "Cost", "ASR_allow", PLOTS_DIR / "b4_budget_cost_vs_asr_allow.svg", labels=labels))
        labels2 = [(r.cost_leakage_tokens_mean, r.attack_success_rate_non_deny_mean, r.scenario.split("_x")[-1]) for r in sweep]
        out.append(_line_svg("B4 Budget Sweep: Cost vs ASR_non_deny", {"Pareto": [(r.cost_leakage_tokens_mean, r.attack_success_rate_non_deny_mean) for r in sweep]}, "Cost", "ASR_non_deny", PLOTS_DIR / "b4_budget_cost_vs_asr_non_deny.svg", labels=labels2))
        labels3 = [(r.cost_leakage_tokens_mean, r.throttle_rate_mean, r.scenario.split("_x")[-1]) for r in sweep]
        out.append(_line_svg("B4 Budget Sweep: Cost vs throttle_rate", {"Pareto": [(r.cost_leakage_tokens_mean, r.throttle_rate_mean) for r in sweep]}, "Cost", "Throttle rate", PLOTS_DIR / "b4_budget_cost_vs_throttle.svg", labels=labels3))

    return out
