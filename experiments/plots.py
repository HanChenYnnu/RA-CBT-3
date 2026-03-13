"""SVG plotting utilities for deterministic experiment outputs."""

from __future__ import annotations

from pathlib import Path

from experiments.metrics import B4RiskEvaluation, MetricRow, ServedDeltaRow, ServedTrafficSlice

PLOTS_DIR = Path("results/plots")


def _line_svg(title: str, series: dict[str, list[tuple[float, float]]], xlabel: str, ylabel: str, path: Path, labels: list[tuple[float, float, str]] | None = None, bands: list[tuple[list[tuple[float, float]], str]] | None = None) -> Path:
    w, h, m = 640, 420, 50
    xs = [x for pts in series.values() for x, _ in pts] or [0.0, 1.0]
    ys = [y for pts in series.values() for _, y in pts] or [0.0, 1.0]
    if bands:
        xs += [x for pts, _ in bands for x, _ in pts]
        ys += [y for pts, _ in bands for _, y in pts]
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

    def sx(x: float) -> float:
        return m + (x - minx) / (maxx - minx) * (w - 2 * m)

    def sy(y: float) -> float:
        return (h - m) - (y - miny) / (maxy - miny) * (h - 2 * m)

    if bands:
        for pts, col in bands:
            for x, y in pts:
                parts += [f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="2" fill="{col}" opacity="0.2"/>']

    for idx, (name, pts) in enumerate(series.items()):
        col = colors[idx % len(colors)]
        coords = [f"{sx(x):.1f},{sy(y):.1f}" for x, y in pts]
        if coords:
            parts += [f'<polyline fill="none" stroke="{col}" stroke-width="2" points="{" ".join(coords)}"/>']
            lx = w - m - 140
            ly = 35 + idx * 16
            parts += [f'<line x1="{lx}" y1="{ly}" x2="{lx+20}" y2="{ly}" stroke="{col}" stroke-width="2"/>', f'<text x="{lx+24}" y="{ly+4}" font-size="11">{name}</text>']

    if labels:
        for x, y, text in labels:
            parts += [f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="3" fill="#111"/>', f'<text x="{sx(x)+5:.1f}" y="{sy(y)-5:.1f}" font-size="10">{text}</text>']
    parts += ["</svg>"]
    path.write_text("\n".join(parts), encoding="utf-8")
    return path


def generate_plots(rows: list[MetricRow], *, b4_eval: B4RiskEvaluation, b2_served: dict[str, ServedTrafficSlice] | None = None, b4_b2_deltas: list[ServedDeltaRow] | None = None) -> list[Path]:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []

    out.append(_line_svg("B4 Risk ROC", {"ROC": [(p.x, p.y) for p in b4_eval.roc_points], "Random": [(0.0, 0.0), (1.0, 1.0)]}, "FPR", "TPR", PLOTS_DIR / "b4_risk_roc.svg"))
    out.append(_line_svg("B4 Precision-Recall", {"PR": [(p.x, p.y) for p in b4_eval.pr_points]}, "Recall", "Precision", PLOTS_DIR / "b4_risk_pr.svg"))
    out.append(_line_svg("B4 Non-deny (allow+throttle) Precision-Recall", {"Non-deny PR": [(p.x, p.y) for p in b4_eval.non_deny_pr_points]}, "Recall", "Precision", PLOTS_DIR / "b4_allowed_pr.svg"))
    out.append(_line_svg("B4 Non-deny Risk CDF", {"attack": [(p.x, p.y) for p in b4_eval.non_deny_attack_cdf_points], "benign": [(p.x, p.y) for p in b4_eval.non_deny_benign_cdf_points]}, "Risk", "CDF", PLOTS_DIR / "b4_risk_cdf.svg"))

    s3 = next((s for s in b4_eval.served_traffic_slices if s.name == "S3_pair"), None)
    if s3:
        ks = [k for k in [10, 30, 50, 100, 200] if s3.p_at_k[k] is not None]
        out.append(_line_svg("B4 S3_pair Precision@K (Bootstrap CI)", {"P@K": [(float(k), float(s3.p_at_k[k])) for k in ks]}, "K", "Precision", PLOTS_DIR / "b4_s3_precision_at_k_ci.svg", bands=[([(float(k), float(s3.p_ci[k][0])) for k in ks if s3.p_ci[k][0] is not None], "#1f77b4"), ([(float(k), float(s3.p_ci[k][1])) for k in ks if s3.p_ci[k][1] is not None], "#1f77b4")]))
        out.append(_line_svg("B4 S3_pair Lift@K (Bootstrap CI)", {"lift@K": [(float(k), float(s3.lift_at_k[k])) for k in ks]}, "K", "Lift", PLOTS_DIR / "b4_s3_lift_at_k_ci.svg", bands=[([(float(k), float(s3.lift_ci[k][0])) for k in ks if s3.lift_ci[k][0] is not None], "#d62728"), ([(float(k), float(s3.lift_ci[k][1])) for k in ks if s3.lift_ci[k][1] is not None], "#d62728")]))


    if b2_served:
        for pair_name in ["S1_pair", "S2_pair", "S3_pair"]:
            b4s = next((s for s in b4_eval.served_traffic_slices if s.name == pair_name), None)
            b2s = b2_served.get(pair_name)
            if b4s is None or b2s is None:
                continue
            ks = [k for k in [10, 30, 50, 100, 200] if b4s.p_at_k[k] is not None and b2s.p_at_k[k] is not None]
            if ks:
                out.append(_line_svg(f"{pair_name} Precision@K: B4 vs B2", {"B4": [(float(k), float(b4s.p_at_k[k])) for k in ks], "B2": [(float(k), float(b2s.p_at_k[k])) for k in ks]}, "K", "Precision", PLOTS_DIR / f"{pair_name.lower()}_b4_vs_b2_precision_at_k.svg", bands=[([(float(k), float(b4s.p_ci[k][0])) for k in ks if b4s.p_ci[k][0] is not None], "#1f77b4"), ([(float(k), float(b4s.p_ci[k][1])) for k in ks if b4s.p_ci[k][1] is not None], "#1f77b4"), ([(float(k), float(b2s.p_ci[k][0])) for k in ks if b2s.p_ci[k][0] is not None], "#d62728"), ([(float(k), float(b2s.p_ci[k][1])) for k in ks if b2s.p_ci[k][1] is not None], "#d62728")]))
                out.append(_line_svg(f"{pair_name} Lift@K: B4 vs B2", {"B4": [(float(k), float(b4s.lift_at_k[k])) for k in ks], "B2": [(float(k), float(b2s.lift_at_k[k])) for k in ks]}, "K", "Lift", PLOTS_DIR / f"{pair_name.lower()}_b4_vs_b2_lift_at_k.svg", bands=[([(float(k), float(b4s.lift_ci[k][0])) for k in ks if b4s.lift_ci[k][0] is not None], "#1f77b4"), ([(float(k), float(b4s.lift_ci[k][1])) for k in ks if b4s.lift_ci[k][1] is not None], "#1f77b4"), ([(float(k), float(b2s.lift_ci[k][0])) for k in ks if b2s.lift_ci[k][0] is not None], "#d62728"), ([(float(k), float(b2s.lift_ci[k][1])) for k in ks if b2s.lift_ci[k][1] is not None], "#d62728")]))

    if b4_b2_deltas:
        pts = []
        for d in b4_b2_deltas:
            if d.slice_name in {"S1_pair", "S2_pair", "S3_pair"} and d.delta_lift_at_30 is not None:
                x = float(len(pts) + 1)
                pts.append((x, float(d.delta_lift_at_30), d.slice_name))
        if pts:
            out.append(_line_svg("B4-B2 ΔLift@30 by pair", {"delta": [(x, y) for x, y, _ in pts]}, "pair-index", "ΔLift@30", PLOTS_DIR / "b4_vs_b2_delta_lift30.svg", labels=[(x, y, name) for x, y, name in pts]))

    sweep = sorted([r for r in rows if r.baseline == "B4" and r.scenario.startswith("S4_mixedload_sweep_x")], key=lambda r: r.scenario, reverse=True)
    if sweep:
        out.append(_line_svg("B4 Mixed-load Sweep (attack): Cost vs ASR_allow_attack", {"attack": [(r.cost_attack, r.asr_allow_attack) for r in sweep]}, "Cost attack", "ASR_allow_attack", PLOTS_DIR / "b4_budget_attack_cost_vs_asr_allow.svg", labels=[(r.cost_attack, r.asr_allow_attack, r.scenario.split("_x")[-1]) for r in sweep]))
        out.append(_line_svg("B4 Mixed-load Sweep (attack): Cost vs ASR_non_deny_attack", {"attack": [(r.cost_attack, r.asr_non_deny_attack) for r in sweep]}, "Cost attack", "ASR_non_deny_attack", PLOTS_DIR / "b4_budget_cost_vs_asr_non_deny.svg", labels=[(r.cost_attack, r.asr_non_deny_attack, r.scenario.split("_x")[-1]) for r in sweep]))
        out.append(_line_svg("B4 Mixed-load Sweep (benign): SR_benign vs scale", {"SR_benign": [(float(r.scenario.split("_x")[-1]), r.sr_benign) for r in sweep]}, "Scale", "SR_benign", PLOTS_DIR / "b4_budget_benign_sr_vs_scale.svg"))
        out.append(_line_svg("B4 Mixed-load Sweep (benign): throttle_benign vs scale", {"throttle_benign": [(float(r.scenario.split("_x")[-1]), r.throttle_benign) for r in sweep]}, "Scale", "throttle_benign", PLOTS_DIR / "b4_budget_benign_throttle_vs_scale.svg"))
        out.append(_line_svg("B4 Mixed-load Contention Tradeoff (annotated)", {
            "attack ASR_non_deny": [(r.cost_attack, r.asr_non_deny_attack) for r in sweep],
            "benign SR": [(r.cost_attack, r.sr_benign) for r in sweep],
        }, "Cost attack", "Metric", PLOTS_DIR / "b4_budget_tradeoff_annotated.svg", labels=[(r.cost_attack, r.asr_non_deny_attack, f"x{r.scenario.split('_x')[-1]}") for r in sweep]))

    return out
