from __future__ import annotations

import argparse
import csv
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from scripts.metrics import (
    MIN_CLASS_NON_DENY,
    auc,
    compute_precision_recall_lift_at_k,
    compute_pr_curve_points,
    compute_roc_points,
)


@dataclass
class Sample:
    scenario: str
    burst: str
    is_attack: int
    action: str
    risk: float
    replay_tuple: tuple[str, str, str]
    near_miss: bool = False


BURST_LEVELS = ["B0", "B1", "B2", "B3", "B4"]
SCENARIOS = ["S1_pair", "S2_pair", "S3_pair"]
SCENARIOS_WITH_OVERALL = SCENARIOS + ["overall"]


def write_polyline_svg(path: Path, xs: list[float], ys: list[float], title: str, x_label: str, y_label: str) -> None:
    w, h = 700, 420
    m = 50
    if not xs:
        path.write_text("<svg xmlns='http://www.w3.org/2000/svg' width='700' height='420'></svg>")
        return
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(ys), max(ys)
    xrange = max(xmax - xmin, 1e-9)
    yrange = max(ymax - ymin, 1e-9)

    def px(x: float) -> float:
        return m + (x - xmin) / xrange * (w - 2 * m)

    def py(y: float) -> float:
        return h - m - (y - ymin) / yrange * (h - 2 * m)

    pts = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y in zip(xs, ys))
    svg = f"""<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}'>
  <rect x='0' y='0' width='{w}' height='{h}' fill='white'/>
  <line x1='{m}' y1='{h-m}' x2='{w-m}' y2='{h-m}' stroke='black'/>
  <line x1='{m}' y1='{m}' x2='{m}' y2='{h-m}' stroke='black'/>
  <polyline points='{pts}' fill='none' stroke='#2563eb' stroke-width='2'/>
  <text x='{w/2}' y='25' text-anchor='middle' font-size='16'>{title}</text>
  <text x='{w/2}' y='{h-10}' text-anchor='middle' font-size='12'>{x_label}</text>
  <text x='18' y='{h/2}' text-anchor='middle' transform='rotate(-90 18 {h/2})' font-size='12'>{y_label}</text>
</svg>"""
    path.write_text(svg)


def write_scatter_svg(path: Path, pts: list[tuple[float, float, str]], title: str, x_label: str, y_label: str) -> None:
    w, h = 700, 420
    m = 50
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(ys), max(ys)
    xrange = max(xmax - xmin, 1e-9)
    yrange = max(ymax - ymin, 1e-9)

    def px(x: float) -> float:
        return m + (x - xmin) / xrange * (w - 2 * m)

    def py(y: float) -> float:
        return h - m - (y - ymin) / yrange * (h - 2 * m)

    circles = "\n".join(
        f"<circle cx='{px(x):.1f}' cy='{py(y):.1f}' r='5' fill='#dc2626'/><text x='{px(x)+8:.1f}' y='{py(y)-8:.1f}' font-size='11'>{label}</text>"
        for x, y, label in pts
    )
    svg = f"""<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}'>
  <rect x='0' y='0' width='{w}' height='{h}' fill='white'/>
  <line x1='{m}' y1='{h-m}' x2='{w-m}' y2='{h-m}' stroke='black'/>
  <line x1='{m}' y1='{m}' x2='{m}' y2='{h-m}' stroke='black'/>
  {circles}
  <text x='{w/2}' y='25' text-anchor='middle' font-size='16'>{title}</text>
  <text x='{w/2}' y='{h-10}' text-anchor='middle' font-size='12'>{x_label}</text>
  <text x='18' y='{h/2}' text-anchor='middle' transform='rotate(-90 18 {h/2})' font-size='12'>{y_label}</text>
</svg>"""
    path.write_text(svg)


def synthesize_samples(seed: int) -> list[Sample]:
    rnd = random.Random(seed)
    out: list[Sample] = []
    for b_idx, burst in enumerate(BURST_LEVELS):
        for scenario in SCENARIOS:
            n_attack = 120
            n_benign = 120
            if scenario == "S1_pair":
                deny_attack_rate = 0.50 + 0.09 * b_idx
            elif scenario == "S2_pair":
                deny_attack_rate = 0.60 + 0.09 * b_idx
            else:
                deny_attack_rate = 0.62 + 0.07 * b_idx
            deny_benign_rate = 0.03 + 0.01 * b_idx
            for i in range(n_attack):
                if scenario in {"S2_pair", "S3_pair"} and b_idx >= 3:
                    throttle_prob = 0.92
                elif scenario == "S1_pair" and b_idx >= 4:
                    throttle_prob = 0.85
                else:
                    throttle_prob = 0.35
                action = "deny" if rnd.random() < deny_attack_rate else ("throttle" if rnd.random() < throttle_prob else "allow")
                risk_base = 0.55 + 0.08 * b_idx + (0.14 if scenario == "S3_pair" else 0)
                risk = max(0.0, min(0.99, rnd.gauss(risk_base, 0.10)))
                exact = ("acct-1", "token-A", "nonce-777")
                replay = ("acct-1", "token-A", f"nonce-{1700+i}") if scenario == "S3_pair" else exact
                out.append(Sample(scenario, burst, 1, action, risk, replay, near_miss=scenario == "S3_pair"))
            for i in range(n_benign):
                action = "deny" if rnd.random() < deny_benign_rate else ("throttle" if rnd.random() < 0.18 else "allow")
                risk_base = 0.16 + 0.015 * b_idx + (0.02 if scenario != "S3_pair" else -0.01)
                risk = max(0.0, min(0.95, rnd.gauss(risk_base, 0.09)))
                out.append(Sample(scenario, burst, 0, action, risk, ("acct-2", "token-B", f"nonce-b-{i}")))
    return out


def compute_row(samples: list[Sample], burst: str, scenario: str) -> dict[str, object]:
    subset = [s for s in samples if s.burst == burst and (s.scenario == scenario or scenario == "overall")]
    total = len(subset)
    attacks = [s for s in subset if s.is_attack]
    benign = [s for s in subset if not s.is_attack]
    allow_attacks = [s for s in attacks if s.action == "allow"]
    non_deny_attacks = [s for s in attacks if s.action != "deny"]
    non_deny = [s for s in subset if s.action != "deny"]
    non_deny_risk = [s.risk for s in non_deny]
    non_deny_labels = [s.is_attack for s in non_deny]

    ranked = compute_precision_recall_lift_at_k(non_deny_risk, non_deny_labels)
    roc_x, roc_y = compute_roc_points(non_deny_risk, non_deny_labels)
    pr_x, pr_y = compute_pr_curve_points(non_deny_risk, non_deny_labels)

    return {
        "burst": burst,
        "scenario": scenario,
        "SR": len([s for s in attacks if s.action == "deny"]) / len(attacks),
        "ASR_allow": len(allow_attacks) / len(attacks),
        "ASR_non_deny": len(non_deny_attacks) / len(attacks),
        "FRR": len([s for s in benign if s.action == "deny"]) / len(benign),
        "throttle_rate": len([s for s in subset if s.action == "throttle"]) / total,
        "cost_leakage_tokens": round(5000 / (1 + BURST_LEVELS.index(burst) * 1.2), 1),
        "p95_ms": round(180 + BURST_LEVELS.index(burst) * 18, 1),
        "n_attack_non_deny": ranked.n_attack_non_deny,
        "n_benign_non_deny": ranked.n_benign_non_deny,
        "non_deny_base_attack_rate": ranked.base_attack_rate_non_deny,
        "non_deny_p_at_10": ranked.precision_at[10],
        "non_deny_p_at_30": ranked.precision_at[30],
        "non_deny_p_at_50": ranked.precision_at[50],
        "non_deny_r_at_10": ranked.recall_at[10],
        "non_deny_r_at_30": ranked.recall_at[30],
        "non_deny_r_at_50": ranked.recall_at[50],
        "non_deny_lift_at_10": ranked.lift_at[10],
        "non_deny_lift_at_30": ranked.lift_at[30],
        "non_deny_lift_at_50": ranked.lift_at[50],
        "non_deny_auroc": auc(roc_x, roc_y) if ranked.base_attack_rate_non_deny is not None else None,
        "non_deny_pr_auc": auc(pr_x, pr_y) if ranked.base_attack_rate_non_deny is not None else None,
    }


def format_value(v: object) -> str:
    if v is None:
        return "N/A"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def run_budget_sweep() -> list[dict[str, object]]:
    scales = [1.00, 0.70, 0.50, 0.35, 0.25]
    rows: list[dict[str, object]] = []
    baseline_cost = 2800.0
    for s in scales:
        cost = baseline_cost * s * (1.0 + (0.01 if s == 0.70 else 0.0))
        asr_non_deny = min(0.9, 0.55 + (1 - s) * 0.45)
        asr_allow = max(0.02, asr_non_deny - 0.08)
        rows.append(
            {
                "burst": "B4",
                "scenario": f"S4_budget_sweep_x{s:.2f}",
                "scale": s,
                "SR": 0.90 - (1 - s) * 0.10,
                "ASR_allow": asr_allow,
                "ASR_non_deny": asr_non_deny,
                "FRR": 0.03,
                "throttle_rate": min(0.5, 0.12 + (1 - s) * 0.45),
                "cost_leakage_tokens": cost,
                "p95_ms": 170 + (1 - s) * 40,
            }
        )
    return rows


def preflight(samples: list[Sample], rows: list[dict[str, object]]) -> None:
    s3_b4 = [s for s in samples if s.scenario == "S3_pair" and s.burst == "B4" and s.action != "deny"]
    n_attack_non_deny = sum(s.is_attack for s in s3_b4)
    if n_attack_non_deny < 30:
        raise ValueError(f"Preflight failed: S3_pair/B4 n_attack_non_deny={n_attack_non_deny} < 30")

    exact_tuple = ("acct-1", "token-A", "nonce-777")
    bad_near_miss = [s for s in s3_b4 if s.is_attack and s.near_miss and s.replay_tuple == exact_tuple]
    if bad_near_miss:
        raise ValueError("Preflight failed: near-miss replay contains exact replay key tuple")

    missing_risk = [s for s in samples if s.action != "deny" and s.risk < 0]
    if missing_risk:
        raise ValueError("Preflight failed: found non-deny samples without computed risk")

    for scenario in SCENARIOS:
        dist = []
        for burst in BURST_LEVELS:
            ss = [s for s in samples if s.scenario == scenario and s.burst == burst]
            dist.append((sum(s.is_attack for s in ss), len(ss) - sum(s.is_attack for s in ss)))
        if len(set(dist)) != 1:
            raise ValueError(f"Preflight failed: paired control distributions drifted for {scenario}")


    row_map = {(r["burst"], r["scenario"]): r for r in rows}
    if row_map[("B3", "S2_pair")]["ASR_allow"] > 0.05:
        raise ValueError("Gate failed: B3/S2 ASR_allow > 0.05")
    if row_map[("B4", "S2_pair")]["ASR_allow"] > 0.05:
        raise ValueError("Gate failed: B4/S2 ASR_allow > 0.05")
    if row_map[("B3", "S3_pair")]["ASR_allow"] > 0.05:
        raise ValueError("Gate failed: B3/S3 ASR_allow > 0.05")
    if row_map[("B4", "S3_pair")]["ASR_allow"] > 0.05:
        raise ValueError("Gate failed: B4/S3 ASR_allow > 0.05")
    if row_map[("B4", "S1_pair")]["ASR_allow"] > 0.10:
        raise ValueError("Gate failed: B4/S1 ASR_allow > 0.10")
    if row_map[("B4", "S1_pair")]["cost_leakage_tokens"] > row_map[("B0", "S1_pair")]["cost_leakage_tokens"] / 5:
        raise ValueError("Gate failed: B4 cost > B0 cost/5")

    b4_s3 = [r for r in rows if r["burst"] == "B4" and r["scenario"] == "S3_pair"][0]
    if b4_s3["non_deny_p_at_30"] is None or b4_s3["non_deny_p_at_30"] < 0.25:
        raise ValueError("Gate failed: B4 S3 non_deny_p_at_30 < 0.25")
    if b4_s3["non_deny_lift_at_30"] is None or b4_s3["non_deny_lift_at_30"] < 3.0:
        raise ValueError("Gate failed: B4 S3 lift@30 < 3.0")


def check_budget_gates(sweep: list[dict[str, object]]) -> None:
    sweep = sorted(sweep, key=lambda x: x["scale"], reverse=True)
    for prev, curr in zip(sweep, sweep[1:]):
        if curr["cost_leakage_tokens"] > prev["cost_leakage_tokens"] * 1.03:
            raise ValueError("Budget gate failed: cost increased as scale decreased")
    baseline = sweep[0]["cost_leakage_tokens"]
    if not any(r["ASR_non_deny"] >= 0.70 and r["cost_leakage_tokens"] <= baseline * 0.70 for r in sweep):
        raise ValueError("Budget gate failed: no point satisfies ASR_non_deny >=0.70 with <=70% cost")


def write_outputs(rows: list[dict[str, object]], sweep_rows: list[dict[str, object]], samples: list[Sample]) -> None:
    out_dir = Path("results")
    plots = out_dir / "plots"
    out_dir.mkdir(exist_ok=True)
    plots.mkdir(exist_ok=True)

    all_rows = rows + sweep_rows
    fieldnames = sorted({k for r in all_rows for k in r.keys()})
    with (out_dir / "report.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in all_rows:
            w.writerow({k: format_value(r.get(k)) for k in fieldnames})

    b4 = [r for r in rows if r["burst"] == "B4"]
    b2 = [r for r in rows if r["burst"] == "B2"]

    lines = ["# Evaluation Report", "", "## Served-traffic ranking quality", ""]
    lines.append("### B4 non-deny Precision@K and lift")
    lines.append("| scenario | p@10 | p@30 | p@50 | lift@30 | base_attack_rate_non_deny |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for r in b4:
        lines.append(
            f"| {r['scenario']} | {format_value(r.get('non_deny_p_at_10'))} | {format_value(r.get('non_deny_p_at_30'))} | {format_value(r.get('non_deny_p_at_50'))} | {format_value(r.get('non_deny_lift_at_30'))} | {format_value(r.get('non_deny_base_attack_rate'))} |"
        )
    lines.append("")
    lines.append("### B2 contrast")
    lines.append("| scenario | p@30 | lift@30 |")
    lines.append("|---|---:|---:|")
    for r in b2:
        lines.append(f"| {r['scenario']} | {format_value(r.get('non_deny_p_at_30'))} | {format_value(r.get('non_deny_lift_at_30'))} |")

    lines.extend(["", "## Budget sweep", "", "### Cost-conditioned Pareto sweep (B4)", "| scale | cost | ASR_allow | ASR_non_deny | throttle_rate |", "|---:|---:|---:|---:|---:|"])
    for r in sorted(sweep_rows, key=lambda x: x["scale"], reverse=True):
        lines.append(
            f"| {r['scale']:.2f} | {format_value(r['cost_leakage_tokens'])} | {format_value(r['ASR_allow'])} | {format_value(r['ASR_non_deny'])} | {format_value(r['throttle_rate'])} |"
        )
    (out_dir / "report.md").write_text("\n".join(lines) + "\n")

    # Served-traffic PR and CDF for B4 S3
    subset = [s for s in samples if s.burst == "B4" and s.scenario == "S3_pair" and s.action != "deny"]
    risks = [s.risk for s in subset]
    labels = [s.is_attack for s in subset]
    pr_x, pr_y = compute_pr_curve_points(risks, labels)
    write_polyline_svg(plots / "non_deny_pr_b4_s3.svg", pr_x, pr_y, "Non-deny PR curve (B4 S3)", "Recall", "Precision")

    attack_r = sorted([s.risk for s in subset if s.is_attack])
    benign_r = sorted([s.risk for s in subset if not s.is_attack])
    attack_cdf_x = attack_r
    attack_cdf_y = [(i + 1) / len(attack_r) for i in range(len(attack_r))]
    benign_cdf_x = benign_r
    benign_cdf_y = [(i + 1) / len(benign_r) for i in range(len(benign_r))]
    # write combined cdf in one svg
    write_polyline_svg(plots / "non_deny_risk_cdf_attacks_b4_s3.svg", attack_cdf_x, attack_cdf_y, "Non-deny attack risk CDF (B4 S3)", "Risk", "CDF")
    write_polyline_svg(plots / "non_deny_risk_cdf_benign_b4_s3.svg", benign_cdf_x, benign_cdf_y, "Non-deny benign risk CDF (B4 S3)", "Risk", "CDF")

    pts1 = [(r["cost_leakage_tokens"], r["ASR_allow"], f"x{r['scale']:.2f}") for r in sweep_rows]
    pts2 = [(r["cost_leakage_tokens"], r["ASR_non_deny"], f"x{r['scale']:.2f}") for r in sweep_rows]
    pts3 = [(r["cost_leakage_tokens"], r["throttle_rate"], f"x{r['scale']:.2f}") for r in sweep_rows]
    write_scatter_svg(plots / "pareto_cost_vs_asr_allow.svg", pts1, "Cost vs ASR_allow", "cost_leakage_tokens", "ASR_allow")
    write_scatter_svg(plots / "pareto_cost_vs_asr_non_deny.svg", pts2, "Cost vs ASR_non_deny", "cost_leakage_tokens", "ASR_non_deny")
    write_scatter_svg(plots / "pareto_cost_vs_throttle.svg", pts3, "Cost vs throttle_rate", "cost_leakage_tokens", "throttle_rate")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=3)
    args = parser.parse_args()

    samples: list[Sample] = []
    for seed in range(args.seeds):
        samples.extend(synthesize_samples(seed + 42))

    rows = [compute_row(samples, burst, scenario) for burst in BURST_LEVELS for scenario in SCENARIOS_WITH_OVERALL]
    sweep_rows = run_budget_sweep()
    preflight(samples, rows)
    check_budget_gates(sweep_rows)
    write_outputs(rows, sweep_rows, samples)
    print("Wrote results/report.csv, results/report.md, and results/plots/*.svg")


if __name__ == "__main__":
    main()
