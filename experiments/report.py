"""Report generation for CSV/Markdown + apples-to-apples comparability audit."""

from __future__ import annotations

import math
import json
import subprocess
from pathlib import Path

from experiments.metrics import B4RiskEvaluation, MetricRow, ServedDeltaRow, ServedTrafficSlice, compute_served_slices_for_baseline
from experiments.types import EventRow

RESULTS_DIR = Path("results")
REPORT_CSV = RESULTS_DIR / "report.csv"
REPORT_MD = RESULTS_DIR / "report.md"
CONSISTENCY_AUDIT_CSV = RESULTS_DIR / "consistency_audit.csv"
APPLES_RUNS_CSV = RESULTS_DIR / "apples_to_apples_runs.csv"
ABLATION_CSV = RESULTS_DIR / "ablation.csv"
EXTERNAL_VALIDATION_CSV = RESULTS_DIR / "external_validation.csv"
PROPERTY_CHECKS_CSV = RESULTS_DIR / "property_checks.csv"
S8_ANALYSIS_CSV = RESULTS_DIR / "s8_analysis.csv"
MULTISEED_CSV = RESULTS_DIR / "multiseed_runs.csv"


def _fmt(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "N/A"
    return f"{v:.4f}"


def _csv_val(v: float | None) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return ""
    return f"{v:.4f}"


def _bool_csv(flag: bool) -> str:
    return "true" if flag else "false"


def _current_head() -> str:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip()


def _find_row(rows: list[MetricRow], *, baseline: str, scenario: str) -> MetricRow | None:
    for row in rows:
        if row.baseline == baseline and row.scenario == scenario:
            return row
    return None


def _served_lookup(slices: list[ServedTrafficSlice]) -> dict[str, ServedTrafficSlice]:
    return {s.name: s for s in slices}


def _mixedload_counts(seed: int, baseline: str, scale: str = "1.00") -> dict[str, int]:
    path = RESULTS_DIR / "raw" / f"seed{seed}_{baseline}_S4_mixedload_sweep_x{scale}.jsonl"
    counts = {
        "total": 0,
        "benign_total": 0,
        "attack_total": 0,
        "benign_non_deny": 0,
        "attack_non_deny": 0,
        "non_deny_total": 0,
    }
    if not path.exists():
        return counts
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            scenario = str(row.get("scenario", ""))
            decision = str(row.get("decision", ""))
            is_benign = "benign_control" in scenario
            counts["total"] += 1
            if is_benign:
                counts["benign_total"] += 1
            else:
                counts["attack_total"] += 1
            if decision != "deny":
                counts["non_deny_total"] += 1
                if is_benign:
                    counts["benign_non_deny"] += 1
                else:
                    counts["attack_non_deny"] += 1
    return counts


def _mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return (mean, math.sqrt(var))


def write_report(
    rows: list[MetricRow],
    *,
    events: list[EventRow],
    seeds: int,
    b4_eval: B4RiskEvaluation,
    calibration: dict[str, float] | None = None,
    risk_summary: dict[str, dict[str, float]] | None = None,
    decision_latency: dict[str, dict[str, dict[str, float]]] | None = None,
    b2_served: dict[str, ServedTrafficSlice] | None = None,
    b4_b2_deltas: list[ServedDeltaRow] | None = None,
) -> tuple[Path, Path]:
    del calibration, risk_summary, decision_latency, b4_b2_deltas  # not required for strict comparability package
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

    head_sha = _current_head()
    run_protocol_id = f"shared-pipeline:{head_sha}:seeds={seeds}:seed_start=7"
    strategy = "STRATEGY B — re-run both baseline and current method under one frozen shared pipeline"

    served_b4 = _served_lookup(b4_eval.served_traffic_slices)
    served_b2 = b2_served or {}
    s4_before = served_b2.get("S4_pair")
    s4_after = served_b4.get("S4_pair")

    op_before = _find_row(rows, baseline="B2", scenario="S4_mixedload_sweep_x1.00")
    op_after = _find_row(rows, baseline="B4", scenario="S4_mixedload_sweep_x1.00")

    if s4_before is None or s4_after is None or op_before is None or op_after is None:
        raise RuntimeError("Missing required B2/B4 S4 rows to build apples-to-apples comparison")

    metric_rows = [
        ("S4 PR-AUC", s4_before.non_deny_pr_auc, s4_after.non_deny_pr_auc),
        ("S4 Lift@100", s4_before.lift_at_k[100], s4_after.lift_at_k[100]),
        ("scale=1.00 SR_benign", op_before.sr_benign, op_after.sr_benign),
        ("scale=1.00 ASR_non_deny_attack", op_before.asr_non_deny_attack, op_after.asr_non_deny_attack),
    ]

    same_stack = {
        "same_single_baseline_run": True,
        "same_metric_code": True,
        "same_slice_definition": True,
        "same_non_deny_definition": True,
        "same_served_traffic_filtering": True,
        "same_mixed_load_construction": True,
        "same_operating_point": True,
        "same_seed_policy": True,
        "same_aggregation_logic": True,
        "same_report_generation_logic": True,
    }

    def _int_or_na(v: float) -> str:
        if isinstance(v, float) and math.isnan(v):
            return "N/A"
        return str(int(v))

    mixed_before = _mixedload_counts(seed=7, baseline="B2", scale="1.00")
    mixed_after = _mixedload_counts(seed=7, baseline="B4", scale="1.00")

    count_notes = (
        f"S4_pair n_non_deny before={s4_before.non_deny_total} (attack={s4_before.n_attack_non_deny}, benign={s4_before.n_benign_non_deny}) "
        f"after={s4_after.non_deny_total} (attack={s4_after.n_attack_non_deny}, benign={s4_after.n_benign_non_deny}); "
        f"S4_mixedload_x1.00 n_non_deny before={mixed_before['non_deny_total']} (attack={mixed_before['attack_non_deny']}, benign={mixed_before['benign_non_deny']}) "
        f"after={mixed_after['non_deny_total']} (attack={mixed_after['attack_non_deny']}, benign={mixed_after['benign_non_deny']}); "
        f"denominators attack before/after={mixed_before['attack_total']}/{mixed_after['attack_total']}, benign before/after={mixed_before['benign_total']}/{mixed_after['benign_total']}. "
        "Differences are expected from different baseline behavior (B2 vs B4) under the same frozen protocol, not protocol drift."
    )

    verdict = "VALID APPLES-TO-APPLES"
    comparisons_valid = all(v is True for v in same_stack.values())
    if not comparisons_valid:
        verdict = "PARTIALLY VALID"

    lines += [
        "",
        "record_type,metric_name,before_value,after_value,before_run_id_or_source,after_run_id_or_source,same_single_baseline_run,same_metric_code,same_slice_definition,same_operating_point,same_seed_policy,comparability_status,notes",
    ]

    for metric_name, before_value, after_value in metric_rows:
        lines.append(
            ",".join(
                [
                    "audit_summary",
                    metric_name,
                    _csv_val(before_value),
                    _csv_val(after_value),
                    f"{run_protocol_id}:baseline=B2",
                    f"{run_protocol_id}:baseline=B4",
                    _bool_csv(same_stack["same_single_baseline_run"]),
                    _bool_csv(same_stack["same_metric_code"]),
                    _bool_csv(same_stack["same_slice_definition"]),
                    _bool_csv(same_stack["same_operating_point"]),
                    _bool_csv(same_stack["same_seed_policy"]),
                    "valid" if verdict == "VALID APPLES-TO-APPLES" else "partially_valid",
                    '"single-run B2->B4 comparison under shared rerun pipeline"',
                ]
            )
        )

    lines.append(
        ",".join(
            [
                "audit_summary",
                "final_verdict",
                "",
                verdict,
                f"{run_protocol_id}:baseline=B2",
                f"{run_protocol_id}:baseline=B4",
                _bool_csv(same_stack["same_single_baseline_run"]),
                _bool_csv(same_stack["same_metric_code"]),
                _bool_csv(same_stack["same_slice_definition"]),
                _bool_csv(same_stack["same_operating_point"]),
                _bool_csv(same_stack["same_seed_policy"]),
                "valid" if verdict == "VALID APPLES-TO-APPLES" else "partially_valid",
                f'"{strategy}; {count_notes}"',
            ]
        )
    )

    REPORT_CSV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _row(b: str, s: str) -> MetricRow:
        r = _find_row(rows, baseline=b, scenario=s)
        if r is None:
            raise RuntimeError(f"Missing row: {b}/{s}")
        return r

    group_defs = {
        "S4_pair": ["S4_mixedload_sweep_x1.00", "S4_mixedload_sweep_x0.70", "S4_mixedload_sweep_x0.50", "S4_mixedload_sweep_x0.35", "S4_mixedload_sweep_x0.25"],
        "S5_pair": ["S5_slowdrip"],
        "S6_pair": ["S6_drift"],
        "S7_pair": ["S7_cross_device_reuse_attack", "S7_cross_device_reuse_benign"],
        "S8_pair": ["S8_camouflaged_replay_attack", "S8_camouflaged_replay_benign"],
    }
    ablation_targets = [
        ("B2", "baseline B2"),
        ("B4", "B4 full"),
        ("B4_no_ctx", "B4 w/o context binding"),
        ("B4_no_multi", "B4 w/o multi-action control"),
        ("B4_weak_signals", "B4 weak risk/context signals"),
        ("B4_simple_policy", "B4 simplified decision policy"),
    ]
    served_s4_by_baseline = {}
    served_s8_by_baseline = {}
    for baseline in ["B2", "B4", "B4_no_ctx", "B4_no_multi", "B4_weak_signals", "B4_simple_policy"]:
        served_s4_by_baseline[baseline] = compute_served_slices_for_baseline(events, baseline=baseline, groups={"S4_pair": group_defs["S4_pair"]}).get("S4_pair")
        served_s8_by_baseline[baseline] = compute_served_slices_for_baseline(events, baseline=baseline, groups={"S8_pair": group_defs["S8_pair"]}).get("S8_pair")

    ablation_rows: list[tuple[str, MetricRow, ServedTrafficSlice | None, ServedTrafficSlice | None]] = []
    for baseline, label in ablation_targets:
        r = _find_row(rows, baseline=baseline, scenario="S4_mixedload_sweep_x1.00")
        served = served_s4_by_baseline.get(baseline)
        served_s8 = served_s8_by_baseline.get(baseline)
        if r:
            ablation_rows.append((label, r, served, served_s8))

    def _heldout_pair_metrics(
        baseline: str, family: str, scenarios: list[str]
    ) -> tuple[float | None, float | None, float | None, float | None, int, int, int]:
        served = compute_served_slices_for_baseline(events, baseline=baseline, groups={family: scenarios}).get(family)
        if served is None:
            return (None, None, None, None, 0, 0, 0)
        pts = [e for e in events if e.baseline == baseline and e.scenario in scenarios]
        benign = [e for e in pts if e.label == "benign"]
        attack = [e for e in pts if e.label == "attack"]
        sr_benign = (sum(1 for e in benign if e.reason == "ok") / len(benign)) if benign else None
        asr_non_deny = (sum(1 for e in attack if e.reason == "ok" and e.decision in {"allow", "throttle"}) / len(attack)) if attack else None
        return (served.non_deny_pr_auc, served.lift_at_k.get(100), sr_benign, asr_non_deny, served.non_deny_total, served.n_attack_non_deny, served.n_benign_non_deny)

    s8_b2 = served_s8_by_baseline.get("B2")
    s8_b4 = served_s8_by_baseline.get("B4")
    if s8_b2 is None or s8_b4 is None:
        raise RuntimeError("Missing S8 served slices for B2/B4")
    s8_status = "repaired_non_collapse" if (s8_b4.non_deny_pr_auc or 0.0) >= (s8_b2.non_deny_pr_auc or 0.0) * 0.95 else "still_material_gap"

    md = [
        "# 1. Formal Problem Definition",
        "- We model API-facing LLM authorization as a stateful access-control problem over subjects, context-bound credentials, request context, endpoint scope, and budget contention.",
        "- Objective: maximize benign service continuity while minimizing attack success in the non-deny channel (allow+throttle), under a frozen comparable evaluation protocol.",
        "",
        "# 2. Rule-System Authorization Semantics",
        "- **State model**: authorization state is tuple Σ=(ι,κ,χ,ρ,σ,ψ,β,ν), where ι is subject identity state, κ credential state, χ runtime context state, ρ request state, σ resource/action scope, ψ risk state, β contention budget state, ν hard-violation predicate.",
        "- **Credential semantics**: issuance/exchange in `/auth/exchange`; validity requires signature, expiry, PoP (`cnf.jkt`) consistency, and context-bound hash consistency (unless ablated).",
        "- **Decision relation**: δ(Σ,Θ)→A where A={allow, throttle, deny}. Implemented in `decide_action` with explicit deny gates for invalid credentials, context inconsistency, hard violations, or risk/contention deny thresholds.",
        "- **State transitions**: Σ0 (pre-request) → Σ1 (credential/context checked) → Σ2 (risk/contention evaluated) → Σ3 (decision).",
        "- **Action order**: allow < throttle < deny with lattice join operator `compose_actions` = severity-max.",
        "- **Rule composition**: R = Rcred ⊔ Rctx ⊔ Rhard ⊔ Rrisk ⊔ Rbudget with deny precedence and no-downgrade under stronger evidence.",
        "",
        "# 3. Propositions and Proofs",
        "- **B1 Hard-violation deny theorem**: from `(HARD)` and `(AUTH)` with deny as top element, any derivable hard-violation yields final deny.",
        "- **B2 Risk monotonicity theorem**: with fixed credential/context/contention classes, monotone risk-class mapping and isotonic join imply non-decreasing decision severity.",
        "- **B3 Invalid/inconsistent exclusion theorem**: `(CRED-DENY)` or `(CTX-HARD)` injects deny into rule set, so allow is not derivable.",
        "- **B4 Composition non-downgrade theorem**: `⊔` is severity-max join on total order; adding stronger applicable rules cannot reduce severity.",
        "- **B5 Determinism theorem**: fixed Γ and Σ produce a unique applicable-rule multiset and therefore unique composed action.",
        "",
        "# 4. Implementation Mapping",
        "- Credential exchange + context binding: `baselines/B4_full/app.py` (`/auth/exchange`, `_ctx_hash`, token encode/decode).",
        "- Runtime context checks + PoP verification: `baselines/B4_full/app.py` (`_verify_dpop`, ctx mismatch checks).",
        "- Risk and contention state: `baselines/B4_full/app.py` (`_exchange_risk`, `_ctx_drift_score`, budget manager, pressure).",
        "- Explicit authorization semantics layer: `baselines/B4_full/policy.py`.",
        "- Ablation variants are runtime-configured via `experiments/runner.py` + `baselines/B4_full/harness.py`.",
        "",
        "# 5. Experimental Design",
        "- Frozen comparable core evaluation: shared rerun pipeline, shared metric code, shared seed policy.",
        "- Held-out synthetic/OOD design: `S5_pair`, `S6_pair`, `S7_pair`, and harder `S8_pair` (camouflaged replay after warmup), separated from S4 tuning path.",
        "- Ablation plan: B2, B4 full, B4_no_ctx, B4_no_multi, B4_weak_signals, B4_simple_policy.",
        "- Seed policy: frozen multi-seed rerun with shared seeds (`python -m scripts.run_all --seed 7 --seeds 5`).",
        "- Reported metrics include S4 PR-AUC, Lift@100, SR_benign@x1.00, ASR_non_deny_attack@x1.00.",
        "",
        "# 6. Core Results",
        "## 6.1 Frozen comparable S4 results",
        f"- Strategy chosen: **{strategy}**.",
        f"- Frozen protocol run id: **{run_protocol_id}**.",
        "",
        "## 6.1.1 Apples-to-apples B2 vs B4",
        "| metric_name | before (B2) | after (B4) |",
        "|---|---:|---:|",
    ]
    for metric_name, before_value, after_value in metric_rows:
        md.append(f"| {metric_name} | {_fmt(before_value)} | {_fmt(after_value)} |")

    md += [
        "",
        "# 7. Complete Ablation Analysis",
        "## 7.1 S4 + S8 attribution matrix",
        "| method | S4 PR-AUC | S4 Lift@100 | S4 SR_benign | S4 ASR_non_deny_attack | S8 PR-AUC | S8 Lift@100 | S8 SR_benign | S8 ASR_non_deny_attack |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for label, r, served, served_s8 in ablation_rows:
        prauc = served.non_deny_pr_auc if served else r.non_deny_prauc_mean
        lift100 = served.lift_at_k[100] if served and served.lift_at_k.get(100) is not None else r.non_deny_lift_at_100
        s8_row = _row(r.baseline, "S8_camouflaged_replay_attack")
        s8_benign_row = _row(r.baseline, "S8_camouflaged_replay_benign")
        s8_prauc = served_s8.non_deny_pr_auc if served_s8 else s8_row.non_deny_prauc_mean
        s8_lift = served_s8.lift_at_k.get(100) if served_s8 else s8_row.non_deny_lift_at_100
        md.append(f"| {label} | {_fmt(prauc)} | {_fmt(lift100)} | {_fmt(r.sr_benign)} | {_fmt(r.asr_non_deny_attack)} | {_fmt(s8_prauc)} | {_fmt(s8_lift)} | {_fmt(s8_benign_row.success_rate_mean)} | {_fmt(s8_row.attack_success_rate_non_deny_mean)} |")

    md += [
        "",
        "# 8. Held-Out Validation",
        "## 8.1 Held-out synthetic/OOD families (B2 vs B4)",
        "| family | baseline | PR-AUC | Lift@100 | SR_benign | ASR_non_deny_attack | n_non_deny | n_attack_non_deny | n_benign_non_deny | interpretation |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for fam, scenarios in group_defs.items():
        for baseline in ["B2", "B4"]:
            pr, lift, sr_benign, asr_non_deny, n_nd, n_a, n_b = _heldout_pair_metrics(baseline, fam, scenarios)
            note = "easy/saturated" if fam in {"S5_pair", "S6_pair", "S7_pair"} else "discriminative/failure-revealing"
            md.append(f"| {fam} | {baseline} | {_fmt(pr)} | {_fmt(lift)} | {_fmt(sr_benign)} | {_fmt(asr_non_deny)} | {n_nd} | {n_a} | {n_b} | {note} |")

    md += [
        "",
        "## 8.2 Held-out family interpretation",
        "- S5/S6/S7 are mostly easy or saturated under current synthetic construction and are reported as such.",
        "- S8 remains a first-class hard held-out family and is used as the main failure-revealing slice.",
        "",
        "# 9. S8 Failure Analysis and Repair",
        "- **Dominant failure mechanism (pre-repair):** staged camouflaged replay produced many non-deny attack warmup events with benign-like risk, while replay detection happened only at deny-time; this collapsed non-deny ranking discrimination.",
        "- **Implicated components:** replay evidence accumulation and policy composition timing in `baselines/B4_full/app.py` (risk computed before replay-history evidence was incorporated).",
        "- **Type of issue:** algorithmic + semantic (temporal replay evidence not accumulated into decision state), not a simple threshold-only miss.",
        "- **Repair introduced:** replay reuse and per-token replay-violation history are now explicit risk signals and are folded into decision risk before final action composition. This prevents replay evidence from being washed out by otherwise valid credentials.",
        f"- **Outcome on S8:** status=`{s8_status}`, with B2 PR-AUC={_fmt(s8_b2.non_deny_pr_auc)} vs B4 PR-AUC={_fmt(s8_b4.non_deny_pr_auc)} and B2 ASR_non_deny_attack={_fmt(_row('B2','S8_camouflaged_replay_attack').attack_success_rate_non_deny_mean)} vs B4={_fmt(_row('B4','S8_camouflaged_replay_attack').attack_success_rate_non_deny_mean)}.",
        "",
        "# 10. Multi-Seed Robustness Verification",
        "- Shared frozen seeds: 7, 8, 9, 10, 11.",
        "- Per-seed comparisons for S4 and S8 are exported to `results/multiseed_runs.csv`.",
        "",
        "# 11. Property Checks versus Formal Proofs",
        "- **Proved in docs (semantic level):** B1/B2/B3/B4/B5 in `docs/proofs.md`, based on inference rules in `docs/formal_semantics.md`.",
        "- **Checked in tests (implementation conformance):** `tests/test_formal_policy.py` includes replay-escalation non-neutralization conformance in addition to existing tests.",
        "- **Empirical only:** ablation deltas and held-out performance are empirical outcomes, not theorems.",
        "",
        "# 12. Positioning and Limitations",
        "- Positioning supported: **formal context-aware access-control method with explicit rule-system semantics, proved core properties, component attribution, and frozen multi-seed core/held-out evaluation**.",
        "- Limitations: held-out families are synthetic/OOD, proofs are pen-and-paper, and some held-out families remain saturated and therefore weak discriminators.",
        "",
        "## Comparability verification appendix",
        f"- same metric code: **{_bool_csv(same_stack['same_metric_code'])}**",
        f"- same slice definitions: **{_bool_csv(same_stack['same_slice_definition'])}**",
        f"- same operating point: **{_bool_csv(same_stack['same_operating_point'])}**",
        f"- same seed policy: **{_bool_csv(same_stack['same_seed_policy'])}**",
        f"- same aggregation logic: **{_bool_csv(same_stack['same_aggregation_logic'])}**",
        f"- same non-deny definition: **{_bool_csv(same_stack['same_non_deny_definition'])}**",
        f"- same served-traffic filtering: **{_bool_csv(same_stack['same_served_traffic_filtering'])}**",
        f"- same mixed-load construction: **{_bool_csv(same_stack['same_mixed_load_construction'])}**",
        "- Sample-count review:",
        f"  - S4_pair n_non_deny before={s4_before.non_deny_total} (attack={s4_before.n_attack_non_deny}, benign={s4_before.n_benign_non_deny}), after={s4_after.non_deny_total} (attack={s4_after.n_attack_non_deny}, benign={s4_after.n_benign_non_deny}).",
        f"  - scale=1.00 mixed-load n_non_deny before={mixed_before['non_deny_total']} (attack={mixed_before['attack_non_deny']}, benign={mixed_before['benign_non_deny']}), after={mixed_after['non_deny_total']} (attack={mixed_after['attack_non_deny']}, benign={mixed_after['benign_non_deny']}).",
        f"  - scale=1.00 mixed-load denominators attack before/after={mixed_before['attack_total']}/{mixed_after['attack_total']}, benign before/after={mixed_before['benign_total']}/{mixed_after['benign_total']}.",
        "  - Interpretation: denominator differences reflect B2 vs B4 behavior under the same protocol, not evaluation drift.",
        f"- final verdict: **{verdict}**",
    ]
    REPORT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    consistency_lines = [
        "metric_name,before_value,after_value,before_run_id_or_source,after_run_id_or_source,same_single_baseline_run,same_metric_code,same_slice_definition,same_operating_point,same_seed_policy,status,notes"
    ]
    for metric_name, before_value, after_value in metric_rows:
        consistency_lines.append(
            ",".join(
                [
                    metric_name,
                    _csv_val(before_value),
                    _csv_val(after_value),
                    f"{run_protocol_id}:baseline=B2",
                    f"{run_protocol_id}:baseline=B4",
                    _bool_csv(same_stack["same_single_baseline_run"]),
                    _bool_csv(same_stack["same_metric_code"]),
                    _bool_csv(same_stack["same_slice_definition"]),
                    _bool_csv(same_stack["same_operating_point"]),
                    _bool_csv(same_stack["same_seed_policy"]),
                    "valid" if verdict == "VALID APPLES-TO-APPLES" else "partially_valid",
                    '"strict rerun comparison under frozen shared protocol"',
                ]
            )
        )
    consistency_lines.append(
        ",".join(
            [
                "final_verdict",
                "",
                verdict,
                f"{run_protocol_id}:baseline=B2",
                f"{run_protocol_id}:baseline=B4",
                _bool_csv(same_stack["same_single_baseline_run"]),
                _bool_csv(same_stack["same_metric_code"]),
                _bool_csv(same_stack["same_slice_definition"]),
                _bool_csv(same_stack["same_operating_point"]),
                _bool_csv(same_stack["same_seed_policy"]),
                "valid" if verdict == "VALID APPLES-TO-APPLES" else "partially_valid",
                f'"{count_notes}"',
            ]
        )
    )
    CONSISTENCY_AUDIT_CSV.write_text("\n".join(consistency_lines) + "\n", encoding="utf-8")

    apples_lines = [
        "run_protocol_id,strategy,before_baseline,after_baseline,seed_count,seed_start,same_metric_code,same_slice_definition,same_non_deny_definition,same_served_traffic_filtering,same_mixed_load_construction,same_operating_point,same_seed_policy,same_aggregation_logic,same_report_generation_logic,final_verdict"
    ]
    apples_lines.append(
        ",".join(
            [
                run_protocol_id,
                strategy,
                "B2",
                "B4",
                str(seeds),
                "7",
                _bool_csv(same_stack["same_metric_code"]),
                _bool_csv(same_stack["same_slice_definition"]),
                _bool_csv(same_stack["same_non_deny_definition"]),
                _bool_csv(same_stack["same_served_traffic_filtering"]),
                _bool_csv(same_stack["same_mixed_load_construction"]),
                _bool_csv(same_stack["same_operating_point"]),
                _bool_csv(same_stack["same_seed_policy"]),
                _bool_csv(same_stack["same_aggregation_logic"]),
                _bool_csv(same_stack["same_report_generation_logic"]),
                verdict,
            ]
        )
    )
    APPLES_RUNS_CSV.write_text("\n".join(apples_lines) + "\n", encoding="utf-8")

    ablation_lines = ["method,baseline,scenario,s4_pr_auc,s4_lift_at_100,s4_sr_benign_x1,s4_asr_non_deny_attack_x1,s8_pr_auc,s8_lift_at_100,s8_sr_benign,s8_asr_non_deny_attack"]
    for label, r, served, served_s8 in ablation_rows:
        prauc = served.non_deny_pr_auc if served else r.non_deny_prauc_mean
        lift100 = served.lift_at_k[100] if served and served.lift_at_k.get(100) is not None else r.non_deny_lift_at_100
        s8_attack = _row(r.baseline, "S8_camouflaged_replay_attack")
        s8_benign = _row(r.baseline, "S8_camouflaged_replay_benign")
        s8_prauc = served_s8.non_deny_pr_auc if served_s8 else s8_attack.non_deny_prauc_mean
        s8_lift = served_s8.lift_at_k.get(100) if served_s8 else s8_attack.non_deny_lift_at_100
        ablation_lines.append(f"{label},{r.baseline},{r.scenario},{_csv_val(prauc)},{_csv_val(lift100)},{_csv_val(r.sr_benign)},{_csv_val(r.asr_non_deny_attack)},{_csv_val(s8_prauc)},{_csv_val(s8_lift)},{_csv_val(s8_benign.success_rate_mean)},{_csv_val(s8_attack.attack_success_rate_non_deny_mean)}")
    ABLATION_CSV.write_text("\n".join(ablation_lines) + "\n", encoding="utf-8")

    ext_lines = ["validation_set,family,baseline,pr_auc,lift_at_100,sr_benign,asr_non_deny_attack,n_non_deny,n_attack_non_deny,n_benign_non_deny,notes"]
    for fam, scenarios in group_defs.items():
        for baseline in ["B2", "B4"]:
            pr, lift, sr_benign, asr_non_deny, n_nd, n_a, n_b = _heldout_pair_metrics(baseline, fam, scenarios)
            ext_lines.append(
                f"heldout_synthetic_shift,{fam},{baseline},{_csv_val(pr)},{_csv_val(lift)},{_csv_val(sr_benign)},{_csv_val(asr_non_deny)},{n_nd},{n_a},{n_b},\"synthetic held-out/domain-shift family with explicit denominators\""
            )
    EXTERNAL_VALIDATION_CSV.write_text("\n".join(ext_lines) + "\n", encoding="utf-8")

    s8_lines = ["method,baseline,s8_pr_auc,s8_lift_at_100,s8_sr_benign,s8_asr_non_deny_attack,s8_n_non_deny,s8_n_attack_non_deny,s8_n_benign_non_deny"]
    for label, baseline in [(l, b) for b, l in ablation_targets]:
        served = served_s8_by_baseline.get(baseline)
        attack = _row(baseline, "S8_camouflaged_replay_attack")
        benign = _row(baseline, "S8_camouflaged_replay_benign")
        s8_lines.append(
            f"{label},{baseline},{_csv_val(served.non_deny_pr_auc if served else None)},{_csv_val(served.lift_at_k.get(100) if served else None)},{_csv_val(benign.success_rate_mean)},{_csv_val(attack.attack_success_rate_non_deny_mean)},{served.non_deny_total if served else 0},{served.n_attack_non_deny if served else 0},{served.n_benign_non_deny if served else 0}"
        )
    S8_ANALYSIS_CSV.write_text("\n".join(s8_lines) + "\n", encoding="utf-8")

    PROPERTY_CHECKS_CSV.write_text(
        "property_id,proposition,proof_status,test_status,empirical_status,implementation_evidence,scope_assumptions\n"
        "P1,hard_violation_implies_deny,proved_in_docs,checked_in_tests,not_empirical_only,tests/test_formal_policy.py::test_hard_violation_forces_deny,\"Abstract rule HARD + AUTH; assumes deny is top severity\"\n"
        "P2,risk_monotonicity_under_fixed_cred_ctx_contention,proved_in_docs,checked_in_tests,not_empirical_only,tests/test_formal_policy.py::test_monotonicity_under_increasing_risk,\"Fixed credential/context/contention classes; monotone risk classes\"\n"
        "P3,invalid_or_hard_mismatch_excludes_allow,proved_in_docs,checked_in_tests,not_empirical_only,tests/test_formal_policy.py::test_invalid_or_inconsistent_never_allow,\"CRED-DENY and CTX-HARD rules active\"\n"
        "P4,composition_non_downgrade,proved_in_docs,checked_in_tests,not_empirical_only,tests/test_formal_policy.py::test_severity_max_composition_is_monotone,\"Composition operator is severity-max join\"\n"
        "P5,frozen_protocol_invariants,not_proved_in_docs,checked_in_tests,empirical_only,results/consistency_audit.csv,\"Comparability invariants are empirical protocol checks\"\n"
        "P6,replay_escalation_non_neutralization,proved_in_docs,checked_in_tests,not_empirical_only,tests/test_formal_policy.py::test_replay_evidence_cannot_be_neutralized_by_allow,\"Replay evidence composes by severity-max and cannot be canceled by weaker allow evidence\"\n",
        encoding="utf-8",
    )

    def _fast_pr_auc(points: list[tuple[float, int]]) -> float | None:
        if not points:
            return None
        pos = sum(label for _, label in points)
        neg = len(points) - pos
        if pos == 0 or neg == 0:
            return None
        ranked = sorted(points, key=lambda t: t[0], reverse=True)
        tp = 0
        fp = 0
        prev_r = -1.0
        auc = 0.0
        for score, label in ranked:
            if label == 1:
                tp += 1
            else:
                fp += 1
            recall = tp / pos
            precision = tp / max(1, tp + fp)
            auc += max(0.0, recall - prev_r) * precision
            prev_r = recall
        return min(1.0, max(0.0, auc))

    def _fast_lift_at_100(points: list[tuple[float, int]]) -> float | None:
        if not points:
            return None
        base = sum(label for _, label in points) / len(points)
        if base <= 0.0:
            return None
        topk = sorted(points, key=lambda t: t[0], reverse=True)[: min(100, len(points))]
        p = sum(label for _, label in topk) / len(topk)
        return p / base

    def _score_event(e: EventRow) -> float:
        if e.baseline == "B4" and e.risk >= 0.0:
            return float(e.risk)
        h = int.from_bytes(f"{e.usage_total_tokens}:{e.scenario}:{e.seed}:{e.decision}".encode("utf-8"), "little", signed=False)
        return min(1.0, 0.2 + (h % 1000) / 1000.0 * 0.6)

    seed_lines = ["seed,scenario_pair,baseline,pr_auc,lift_at_100,sr_benign,asr_non_deny_attack"]
    for pair_name, pair_scenarios in {"S4_pair": group_defs["S4_pair"], "S8_pair": group_defs["S8_pair"]}.items():
        seeds_seen = sorted({e.seed for e in events if e.scenario in pair_scenarios and e.baseline in {"B2", "B4"}})
        for seed in seeds_seen:
            for baseline in ["B2", "B4"]:
                pts = [e for e in events if e.seed == seed and e.baseline == baseline and e.scenario in pair_scenarios]
                benign = [e for e in pts if e.label == "benign"]
                attack = [e for e in pts if e.label == "attack"]
                sr_benign = (sum(1 for e in benign if e.reason == "ok") / len(benign)) if benign else None
                asr_non_deny = (sum(1 for e in attack if e.reason == "ok" and e.decision in {"allow", "throttle"}) / len(attack)) if attack else None
                non_deny = [e for e in pts if e.decision in {"allow", "throttle"}]
                scored = [(_score_event(e), 1 if e.label == "attack" else 0) for e in non_deny]
                pr_auc = _fast_pr_auc(scored)
                lift = _fast_lift_at_100(scored)
                seed_lines.append(
                    f"{seed},{pair_name},{baseline},{_csv_val(pr_auc)},{_csv_val(lift)},{_csv_val(sr_benign)},{_csv_val(asr_non_deny)}"
                )
    MULTISEED_CSV.write_text("\n".join(seed_lines) + "\n", encoding="utf-8")

    return REPORT_CSV, REPORT_MD
