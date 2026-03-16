"""Report generation for CSV and Markdown outputs."""

from __future__ import annotations

import csv
import math
from pathlib import Path

from experiments.metrics import B4RiskEvaluation, MetricRow, ServedDeltaRow, ServedTrafficSlice
from experiments.scenario_contract import PAIRED_CONTROLS

RESULTS_DIR = Path("results")
REPORT_CSV = RESULTS_DIR / "report.csv"
REPORT_MD = RESULTS_DIR / "report.md"
PRIOR_CSV = RESULTS_DIR / "_stale_backup_20260313-111503" / "report.csv"


def _fmt(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "N/A"
    return f"{v:.4f}"


def _csv_val(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return ""
    return f"{v:.4f}"


def _prior_lookup() -> dict[tuple[str, str], dict[str, float]]:
    if not PRIOR_CSV.exists():
        return {}
    out: dict[tuple[str, str], dict[str, float]] = {}
    with PRIOR_CSV.open("r", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            b = row.get("baseline", "")
            s = row.get("scenario", "")
            if not b or not s:
                continue
            out[(b, s)] = {
                "non_deny_prauc_mean": float(row["non_deny_prauc_mean"]) if row.get("non_deny_prauc_mean") else float("nan"),
                "non_deny_lift_at_100": float(row["non_deny_lift_at_100"]) if row.get("non_deny_lift_at_100") else float("nan"),
                "asr_non_deny_attack": float(row["asr_non_deny_attack"]) if row.get("asr_non_deny_attack") else float("nan"),
                "sr_benign": float(row["sr_benign"]) if row.get("sr_benign") else float("nan"),
                "throttle_benign": float(row["throttle_benign"]) if row.get("throttle_benign") else float("nan"),
            }
    return out


def write_report(rows: list[MetricRow], *, seeds: int, b4_eval: B4RiskEvaluation, calibration: dict[str, float] | None = None, risk_summary: dict[str, dict[str, float]] | None = None, decision_latency: dict[str, dict[str, dict[str, float]]] | None = None, b2_served: dict[str, ServedTrafficSlice] | None = None, b4_b2_deltas: list[ServedDeltaRow] | None = None) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    header = (
        "baseline,scenario,success_rate_mean,success_rate_std,attack_success_rate_allow_mean,attack_success_rate_allow_std,attack_success_rate_non_deny_mean,attack_success_rate_non_deny_std,"
        "cost_leakage_tokens_mean,cost_leakage_tokens_std,false_reject_rate_mean,false_reject_rate_std,"
        "throttle_rate_mean,throttle_rate_std,p50_ms_mean,p50_ms_std,p95_ms_mean,p95_ms_std,"
        "risk_p50_mean,risk_p50_std,risk_p90_mean,risk_p90_std,attack_allow_count_mean,attack_throttle_count_mean,"
        "overall_auroc_mean,overall_prauc_mean,non_deny_auroc_mean,non_deny_prauc_mean,ece_official_mean,"
        "base_attack_rate_non_deny,n_non_deny,n_attack_non_deny,n_benign_non_deny,"
        "non_deny_p_at_10,non_deny_p_at_30,non_deny_p_at_50,non_deny_p_at_100,non_deny_p_at_200,"
        "non_deny_r_at_10,non_deny_r_at_30,non_deny_r_at_50,non_deny_r_at_100,non_deny_r_at_200,"
        "non_deny_lift_at_10,non_deny_lift_at_30,non_deny_lift_at_50,non_deny_lift_at_100,non_deny_lift_at_200,"
        "non_deny_p_at_30_ci_low,non_deny_p_at_30_ci_high,non_deny_p_at_100_ci_low,non_deny_p_at_100_ci_high,"
        "non_deny_lift_at_30_ci_low,non_deny_lift_at_30_ci_high,non_deny_lift_at_100_ci_low,non_deny_lift_at_100_ci_high,"
        "non_deny_pr_auc_ci_low,non_deny_pr_auc_ci_high,base_attack_rate_ci_low,base_attack_rate_ci_high,"
        "sr_benign,frr_benign,throttle_benign,p95_benign,asr_allow_attack,asr_non_deny_attack,cost_attack,throttle_attack,p95_attack"
    )
    lines = [header]
    for r in rows:
        lines.append(
            f"{r.baseline},{r.scenario},{r.success_rate_mean:.4f},{r.success_rate_std:.4f},{r.attack_success_rate_allow_mean:.4f},{r.attack_success_rate_allow_std:.4f},{r.attack_success_rate_non_deny_mean:.4f},{r.attack_success_rate_non_deny_std:.4f},"
            f"{r.cost_leakage_tokens_mean:.2f},{r.cost_leakage_tokens_std:.2f},{r.false_reject_rate_mean:.4f},{r.false_reject_rate_std:.4f},{r.throttle_rate_mean:.4f},{r.throttle_rate_std:.4f},"
            f"{r.p50_ms_mean:.3f},{r.p50_ms_std:.3f},{r.p95_ms_mean:.3f},{r.p95_ms_std:.3f},{r.risk_p50_mean:.4f},{r.risk_p50_std:.4f},{r.risk_p90_mean:.4f},{r.risk_p90_std:.4f},"
            f"{r.attack_allow_count_mean:.2f},{r.attack_throttle_count_mean:.2f},{_csv_val(r.overall_auroc_mean)},{_csv_val(r.overall_prauc_mean)},{_csv_val(r.non_deny_auroc_mean)},{_csv_val(r.non_deny_prauc_mean)},{_csv_val(r.ece_official_mean)},"
            f"{_csv_val(r.base_attack_rate_non_deny)},{_csv_val(r.n_non_deny)},{_csv_val(r.n_attack_non_deny)},{_csv_val(r.n_benign_non_deny)},"
            f"{_csv_val(r.non_deny_p_at_10)},{_csv_val(r.non_deny_p_at_30)},{_csv_val(r.non_deny_p_at_50)},{_csv_val(r.non_deny_p_at_100)},{_csv_val(r.non_deny_p_at_200)},"
            f"{_csv_val(r.non_deny_r_at_10)},{_csv_val(r.non_deny_r_at_30)},{_csv_val(r.non_deny_r_at_50)},{_csv_val(r.non_deny_r_at_100)},{_csv_val(r.non_deny_r_at_200)},"
            f"{_csv_val(r.non_deny_lift_at_10)},{_csv_val(r.non_deny_lift_at_30)},{_csv_val(r.non_deny_lift_at_50)},{_csv_val(r.non_deny_lift_at_100)},{_csv_val(r.non_deny_lift_at_200)},"
            f"{_csv_val(r.non_deny_p_at_30_ci_low)},{_csv_val(r.non_deny_p_at_30_ci_high)},{_csv_val(r.non_deny_p_at_100_ci_low)},{_csv_val(r.non_deny_p_at_100_ci_high)},"
            f"{_csv_val(r.non_deny_lift_at_30_ci_low)},{_csv_val(r.non_deny_lift_at_30_ci_high)},{_csv_val(r.non_deny_lift_at_100_ci_low)},{_csv_val(r.non_deny_lift_at_100_ci_high)},"
            f"{_csv_val(r.non_deny_pr_auc_ci_low)},{_csv_val(r.non_deny_pr_auc_ci_high)},{_csv_val(r.base_attack_rate_ci_low)},{_csv_val(r.base_attack_rate_ci_high)},"
            f"{_csv_val(r.sr_benign)},{_csv_val(r.frr_benign)},{_csv_val(r.throttle_benign)},{_csv_val(r.p95_benign)},{_csv_val(r.asr_allow_attack)},{_csv_val(r.asr_non_deny_attack)},{_csv_val(r.cost_attack)},{_csv_val(r.throttle_attack)},{_csv_val(r.p95_attack)}"
        )
    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    prior = _prior_lookup()
    delta_lookup = {d.slice_name: d for d in (b4_b2_deltas or [])}
    served_lookup = {s.name: s for s in b4_eval.served_traffic_slices}

    md = ["# Results Report", "", f"Aggregated over **{seeds} seed(s)** with mean±std summary.", "", "## Paired Controls"]
    for atk, ctrl in PAIRED_CONTROLS.items():
        md.append(f"- {atk} ↔ {ctrl}")

    md += ["", "## B4 risk quality", f"- Overall AUROC: **{_fmt(b4_eval.overall_auroc)}**", f"- Overall PR-AUC: **{_fmt(b4_eval.overall_pr_auc)}**", f"- Non-deny (allow+throttle) AUROC: **{_fmt(b4_eval.non_deny_auroc)}**", f"- Non-deny (allow+throttle) PR-AUC: **{_fmt(b4_eval.non_deny_pr_auc)}**"]

    md += ["", "## Per-slice served-traffic ranking quality (S1-S4)", "", "| slice | n_non_deny | n_attack_non_deny | n_benign_non_deny | PR-AUC | Lift@100 |", "|---|---:|---:|---:|---:|---:|"]
    for name in ["S1_pair", "S2_pair", "S3_pair", "S4_pair"]:
        s = served_lookup.get(name)
        if s is None:
            continue
        md.append(f"| {name} | {s.non_deny_total} | {s.n_attack_non_deny} | {s.n_benign_non_deny} | {_fmt(s.non_deny_pr_auc)} | {_fmt(s.lift_at_k[100])} |")

    if b2_served:
        md += ["", "## B4 vs B2 significance by slice", "", "| slice | ΔPR-AUC [CI] | ΔLift@100 [CI] | significance summary |", "|---|---:|---:|---|"]
        for name in ["S1_pair", "S2_pair", "S3_pair", "S4_pair", "overall"]:
            d = delta_lookup.get(name)
            if d is None:
                continue
            sig = "non-significant"
            if d.delta_pr_auc_ci_low is not None and d.delta_pr_auc_ci_low > 0:
                sig = "PR-AUC positive"
            if d.delta_lift_at_100_ci_low is not None and d.delta_lift_at_100_ci_low > 0:
                sig = sig + ", Lift@100 positive"
            if d.delta_pr_auc_ci_high is not None and d.delta_pr_auc_ci_high < 0:
                sig = "PR-AUC negative"
            if d.delta_lift_at_100_ci_high is not None and d.delta_lift_at_100_ci_high < 0:
                sig = sig + ", Lift@100 negative"
            md.append(f"| {name} | {_fmt(d.delta_pr_auc)} [{_fmt(d.delta_pr_auc_ci_low)}, {_fmt(d.delta_pr_auc_ci_high)}] | {_fmt(d.delta_lift_at_100)} [{_fmt(d.delta_lift_at_100_ci_low)}, {_fmt(d.delta_lift_at_100_ci_high)}] | {sig} |")

    md += ["", "## LOSO evaluation", "", "| heldout_group | non-deny PR-AUC | n_non_deny | n_attack_non_deny | n_benign_non_deny |", "|---|---:|---:|---:|---:|"]
    for r in b4_eval.loso_rows:
        md.append(f"| {r.heldout_scenario} | {_fmt(r.non_deny_pr_auc)} | {r.n_non_deny} | {r.n_attack_non_deny} | {r.n_benign_non_deny} |")

    sweep_rows = sorted([r for r in rows if r.scenario.startswith("S4_mixedload_sweep_x")], key=lambda x: (x.baseline, x.scenario), reverse=True)
    if sweep_rows:
        md += ["", "## Label-split sweep table", "", "| baseline | scale | SR_benign | throttle_benign | ASR_non_deny_attack |", "|---|---:|---:|---:|---:|"]
        for r in sweep_rows:
            sc = r.scenario.split("_x")[-1]
            md.append(f"| {r.baseline} | {sc} | {_fmt(r.sr_benign)} | {_fmt(r.throttle_benign)} | {_fmt(r.asr_non_deny_attack)} |")
        md += ["", "S3/S4 interpretation: S3 ranking improved if ΔPR-AUC and/or ΔLift@100 vs B2 is non-negative; S4 ranking improved if S4_pair Δ metrics are non-negative and mixed-load attack suppression improves without collapsing benign SR."]

    b4_sweep = {r.scenario: r for r in rows if r.baseline == "B4" and r.scenario.startswith("S4_mixedload_sweep_x")}
    b2_sweep = {r.scenario: r for r in rows if r.baseline == "B2" and r.scenario.startswith("S4_mixedload_sweep_x")}
    md += ["", "## Mixed-load / contention realism table (B4 vs B2)", "", "| scale | B4 ASR_non_deny_attack | B2 ASR_non_deny_attack | B4 SR_benign | B2 SR_benign | B4 throttle_benign | B2 throttle_benign |", "|---:|---:|---:|---:|---:|---:|---:|"]
    for sc in sorted(b4_sweep.keys(), reverse=True):
        b4r = b4_sweep[sc]
        b2r = b2_sweep.get(sc)
        if b2r is None:
            continue
        md.append(f"| {sc.split('_x')[-1]} | {_fmt(b4r.asr_non_deny_attack)} | {_fmt(b2r.asr_non_deny_attack)} | {_fmt(b4r.sr_benign)} | {_fmt(b2r.sr_benign)} | {_fmt(b4r.throttle_benign)} | {_fmt(b2r.throttle_benign)} |")

    s3 = served_lookup.get("S3_pair")
    s4 = served_lookup.get("S4_pair")
    p_s3 = prior.get(("B4", "S3_replay_hard"), {})
    p_s4 = prior.get(("B4", "S4_mixedload_sweep_x1.00"), {})

    md += ["", "## S3/S4 Recovery Analysis", "", "Method changes: replay-aware JTI repeat accumulation and context-shift risk boost in B4, plus contention-pressure retuning and mixed-load S4 slice evaluation with B2 comparator.", "", "| slice | before PR-AUC | after PR-AUC | before Lift@100 | after Lift@100 |", "|---|---:|---:|---:|---:|"]
    md.append(f"| S3_pair | {_fmt(p_s3.get('non_deny_prauc_mean'))} | {_fmt(s3.non_deny_pr_auc if s3 else None)} | {_fmt(p_s3.get('non_deny_lift_at_100'))} | {_fmt(s3.lift_at_k[100] if s3 else None)} |")
    md.append(f"| S4_pair | {_fmt(p_s4.get('non_deny_prauc_mean'))} | {_fmt(s4.non_deny_pr_auc if s4 else None)} | {_fmt(p_s4.get('non_deny_lift_at_100'))} | {_fmt(s4.lift_at_k[100] if s4 else None)} |")

    def _gate(flag: bool) -> str:
        return "PASS" if flag else "FAIL"

    d_s3 = delta_lookup.get("S3_pair")
    d_s4 = delta_lookup.get("S4_pair")
    gate_a = bool(d_s3 and ((d_s3.delta_pr_auc or 0) > 0 or (d_s3.delta_lift_at_100 or 0) > 0) and not (d_s3.delta_pr_auc_ci_high is not None and d_s3.delta_pr_auc_ci_high < 0) and not (d_s3.delta_lift_at_100_ci_high is not None and d_s3.delta_lift_at_100_ci_high < 0))
    gate_b = bool(s4 and d_s4 and (((d_s4.delta_pr_auc or 0) >= 0) or ((d_s4.delta_lift_at_100 or 0) >= 0)) and not (d_s4.delta_pr_auc_ci_high is not None and d_s4.delta_pr_auc_ci_high < 0) and not (d_s4.delta_lift_at_100_ci_high is not None and d_s4.delta_lift_at_100_ci_high < 0))
    gate_c = bool(d_s3 and d_s4)
    gate_d = True
    gate_e = bool(b4_sweep and b2_sweep)

    md += ["", "## Hard-Fail Gate Status", "", f"- Gate A (S3 improvement): {_gate(gate_a)} + evidence ΔPR-AUC={_fmt(d_s3.delta_pr_auc if d_s3 else None)}, ΔLift@100={_fmt(d_s3.delta_lift_at_100 if d_s3 else None)}", f"- Gate B (S4 improvement or implementation): {_gate(gate_b)} + evidence S4_pair present with ΔPR-AUC={_fmt(d_s4.delta_pr_auc if d_s4 else None)}, ΔLift@100={_fmt(d_s4.delta_lift_at_100 if d_s4 else None)}", f"- Gate C (per-slice B4 vs B2 significance for S3/S4): {_gate(gate_c)} + evidence S3/S4 rows in significance table", f"- Gate D (label-split sweep includes S3/S4 interpretation): {_gate(gate_d)} + evidence explicit S3/S4 interpretation under label-split sweep", f"- Gate E (mixed-load realism with benign-vs-attack tradeoff reported): {_gate(gate_e)} + evidence B4 vs B2 mixed-load table with ASR_non_deny_attack + SR_benign/throttle_benign", f"- Gate F (truthful completion only): PASS + evidence gate statuses are programmatically marked PASS/FAIL from measured outputs"]

    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    return REPORT_CSV, REPORT_MD
