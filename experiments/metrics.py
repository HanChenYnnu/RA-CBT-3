"""Metrics computation with multi-seed aggregation, risk quality, and defensibility slices."""

from __future__ import annotations

from dataclasses import dataclass
import math

from experiments.types import EventRow


@dataclass(frozen=True)
class MetricRow:
    baseline: str
    scenario: str
    attack_success_rate_mean: float
    attack_success_rate_std: float
    cost_leakage_tokens_mean: float
    cost_leakage_tokens_std: float
    false_reject_rate_mean: float
    false_reject_rate_std: float
    throttle_rate_mean: float
    throttle_rate_std: float
    p50_ms_mean: float
    p50_ms_std: float
    p95_ms_mean: float
    p95_ms_std: float
    risk_p50_mean: float
    risk_p50_std: float
    risk_p90_mean: float
    risk_p90_std: float
    attack_allow_count_mean: float
    attack_throttle_count_mean: float
    overall_auroc_mean: float
    overall_prauc_mean: float
    allowed_only_auroc_mean: float
    allowed_only_prauc_mean: float
    ece_calibrated_mean: float


@dataclass(frozen=True)
class RiskPoint:
    x: float
    y: float


@dataclass(frozen=True)
class ReliabilityBin:
    bin_lo: float
    bin_hi: float
    mean_pred: float
    empirical_attack_rate: float
    count: int


@dataclass(frozen=True)
class LosoRow:
    heldout_scenario: str
    auroc: float
    pr_auc: float
    allowed_only_pr_auc: float
    ece: float
    brier: float


@dataclass(frozen=True)
class B4RiskEvaluation:
    overall_auroc: float
    overall_pr_auc: float
    allowed_only_auroc: float
    allowed_only_pr_auc: float
    macro_scenario_auroc: float
    macro_scenario_pr_auc: float
    brier_calibrated: float
    ece_calibrated: float
    brier_raw: float
    ece_raw: float
    roc_points: list[RiskPoint]
    pr_points: list[RiskPoint]
    allowed_pr_points: list[RiskPoint]
    reliability_bins: list[ReliabilityBin]
    loso_rows: list[LosoRow]
    loso_mean_pr_auc: float
    operating_point_threshold: float
    confusion_tp: int
    confusion_fp: int
    confusion_tn: int
    confusion_fn: int


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * percentile))
    return float(ordered[index])


def _mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    m = sum(values) / len(values)
    v = sum((x - m) ** 2 for x in values) / len(values)
    return (m, math.sqrt(v))


def _mean_std_ignore_negative(values: list[float]) -> tuple[float, float]:
    kept = [v for v in values if v >= 0.0]
    return _mean_std(kept) if kept else (-1.0, 0.0)


def _safe_logit(p: float) -> float:
    q = min(1.0 - 1e-6, max(1e-6, p))
    return math.log(q / (1.0 - q))


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _calibrate_temperature(train_scores: list[float], train_labels: list[int]) -> float:
    if not train_scores:
        return 1.0
    best_t, best_loss = 1.0, float("inf")
    for i in range(10, 301):
        t = i / 100.0
        loss = 0.0
        for s, y in zip(train_scores, train_labels):
            p = _sigmoid(_safe_logit(s) / t)
            p = min(1.0 - 1e-8, max(1e-8, p))
            loss += -(y * math.log(p) + (1 - y) * math.log(1 - p))
        if loss < best_loss:
            best_loss, best_t = loss, t
    return best_t


def _apply_temp(scores: list[float], t: float) -> list[float]:
    return [_sigmoid(_safe_logit(s) / t) for s in scores]


def _sample_thresholds(scores: list[float], *, descending: bool = False) -> list[float]:
    vals = sorted(set(scores), reverse=descending)
    if len(vals) <= 200:
        return vals
    step = max(1, len(vals) // 200)
    return vals[::step]


def _roc(labels: list[int], scores: list[float]) -> tuple[float, list[RiskPoint]]:
    if not labels:
        return (0.0, [])
    thresholds = sorted({0.0, 1.0, *_sample_thresholds(scores)})
    points: list[RiskPoint] = []
    pos = sum(labels)
    neg = len(labels) - pos
    for t in thresholds:
        tp = sum(1 for y, s in zip(labels, scores) if y == 1 and s >= t)
        fp = sum(1 for y, s in zip(labels, scores) if y == 0 and s >= t)
        tpr = tp / max(1, pos)
        fpr = fp / max(1, neg)
        points.append(RiskPoint(fpr, tpr))
    points = sorted(points, key=lambda p: p.x)
    area = 0.0
    for i in range(1, len(points)):
        x0, y0 = points[i - 1].x, points[i - 1].y
        x1, y1 = points[i].x, points[i].y
        area += (x1 - x0) * (y0 + y1) / 2.0
    return (max(0.0, min(1.0, area)), points)


def _pr(labels: list[int], scores: list[float]) -> tuple[float, list[RiskPoint]]:
    if not labels:
        return (0.0, [])
    thresholds = _sample_thresholds(scores, descending=True)
    if not thresholds:
        return (0.0, [])
    points: list[RiskPoint] = []
    pos = sum(labels)
    for t in [1.0001, *thresholds, -0.0001]:
        tp = sum(1 for y, s in zip(labels, scores) if y == 1 and s >= t)
        fp = sum(1 for y, s in zip(labels, scores) if y == 0 and s >= t)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, pos)
        points.append(RiskPoint(recall, precision))
    points = sorted(points, key=lambda p: p.x)
    area = 0.0
    for i in range(1, len(points)):
        x0, y0 = points[i - 1].x, points[i - 1].y
        x1, y1 = points[i].x, points[i].y
        area += (x1 - x0) * ((y0 + y1) / 2.0)
    return (max(0.0, min(1.0, area)), points)


def _brier_ece(labels: list[int], scores: list[float]) -> tuple[float, float, list[ReliabilityBin]]:
    if not labels:
        return (0.0, 0.0, [])
    brier = sum((s - y) ** 2 for s, y in zip(scores, labels)) / len(scores)
    bins: list[ReliabilityBin] = []
    ece = 0.0
    for i in range(10):
        lo, hi = i / 10.0, (i + 1) / 10.0
        bucket = [(s, y) for s, y in zip(scores, labels) if (lo <= s < hi) or (i == 9 and s == 1.0)]
        if not bucket:
            continue
        mean_pred = sum(s for s, _ in bucket) / len(bucket)
        emp = sum(y for _, y in bucket) / len(bucket)
        count = len(bucket)
        ece += abs(mean_pred - emp) * (count / len(scores))
        bins.append(ReliabilityBin(lo, hi, mean_pred, emp, count))
    return (brier, ece, bins)


def _seed_metric(bucket: list[EventRow]) -> tuple[float, float, float, float, float, float, float, float, float, float]:
    total = len(bucket)
    success_ok = sum(1 for row in bucket if 200 <= row.status_code < 300 and row.reason == "ok")
    asr = 0.0 if total == 0 else success_ok / total
    cost = float(sum(row.usage_total_tokens for row in bucket if row.usage_total_tokens > 0))
    benign = [row for row in bucket if row.benign]
    benign_den = max(1, len(benign))
    frr = sum(1 for row in benign if row.decision == "deny") / benign_den

    throttle_bucket = benign if benign else bucket
    throttle_den = max(1, len(throttle_bucket))
    throttle = sum(1 for row in throttle_bucket if row.decision == "throttle") / throttle_den

    latencies = [float(row.latency_ms) for row in bucket]
    risks = [float(row.risk) for row in bucket if row.risk >= 0.0]
    risk_p50 = _percentile(risks, 0.50) if risks else -1.0
    risk_p90 = _percentile(risks, 0.90) if risks else -1.0
    attack_allow = float(sum(1 for row in bucket if row.label == "attack" and row.decision == "allow"))
    attack_throttle = float(sum(1 for row in bucket if row.label == "attack" and row.decision == "throttle"))
    return (asr, cost, frr, throttle, _percentile(latencies, 0.5), _percentile(latencies, 0.95), risk_p50, risk_p90, attack_allow, attack_throttle)


def compute_b4_risk_evaluation(events: list[EventRow], *, loso_scenarios: list[str]) -> B4RiskEvaluation:
    pts = [e for e in events if e.baseline == "B4" and e.risk >= 0.0]
    labels = [1 if e.label == "attack" else 0 for e in pts]
    raw_scores = [e.risk for e in pts]
    if not pts:
        return B4RiskEvaluation(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, [], [], [], [], [], 0.0, 0.5, 0, 0, 0, 0)

    t_global = _calibrate_temperature(raw_scores, labels)
    cal_scores = _apply_temp(raw_scores, t_global)

    overall_auroc, roc_points = _roc(labels, cal_scores)
    overall_prauc, pr_points = _pr(labels, cal_scores)

    allowed = [e for e in pts if e.decision in {"allow", "throttle"}]
    al_labels = [1 if e.label == "attack" else 0 for e in allowed]
    al_scores = _apply_temp([e.risk for e in allowed], t_global)
    allowed_auroc, _ = _roc(al_labels, al_scores)
    allowed_prauc, allowed_pr_points = _pr(al_labels, al_scores)

    by_scn: dict[str, tuple[list[int], list[float]]] = {}
    for e in pts:
        l, s = by_scn.setdefault(e.scenario, ([], []))
        l.append(1 if e.label == "attack" else 0)
        s.append(e.risk)
    scn_aurocs, scn_praucs = [], []
    for l, s in by_scn.values():
        t = _calibrate_temperature(s, l)
        cs = _apply_temp(s, t)
        scn_aurocs.append(_roc(l, cs)[0])
        scn_praucs.append(_pr(l, cs)[0])

    brier_raw, ece_raw, _ = _brier_ece(labels, raw_scores)
    brier_cal, ece_cal, rel_bins = _brier_ece(labels, cal_scores)

    benign_scores = [s for y, s in zip(labels, cal_scores) if y == 0]
    target = _percentile(benign_scores, 0.99) if benign_scores else 0.5
    tp = sum(1 for y, s in zip(labels, cal_scores) if y == 1 and s >= target)
    fp = sum(1 for y, s in zip(labels, cal_scores) if y == 0 and s >= target)
    tn = sum(1 for y, s in zip(labels, cal_scores) if y == 0 and s < target)
    fn = sum(1 for y, s in zip(labels, cal_scores) if y == 1 and s < target)

    loso_rows: list[LosoRow] = []
    for held in loso_scenarios:
        train = [e for e in pts if not e.scenario.startswith(f"{held}_") and e.scenario != held]
        test = [e for e in pts if e.scenario.startswith(f"{held}_") or e.scenario == held]
        t = _calibrate_temperature([e.risk for e in train], [1 if e.label == "attack" else 0 for e in train])
        test_labels = [1 if e.label == "attack" else 0 for e in test]
        test_scores = _apply_temp([e.risk for e in test], t)
        auroc = _roc(test_labels, test_scores)[0]
        prauc = _pr(test_labels, test_scores)[0]
        test_allowed = [e for e in test if e.decision in {"allow", "throttle"}]
        ta_labels = [1 if e.label == "attack" else 0 for e in test_allowed]
        ta_scores = _apply_temp([e.risk for e in test_allowed], t)
        allowed_pr = _pr(ta_labels, ta_scores)[0] if ta_labels else 0.0
        brier, ece, _ = _brier_ece(test_labels, test_scores)
        loso_rows.append(LosoRow(held, auroc, prauc, allowed_pr, ece, brier))

    loso_mean_pr = sum(r.pr_auc for r in loso_rows) / max(1, len(loso_rows))
    return B4RiskEvaluation(
        overall_auroc,
        overall_prauc,
        allowed_auroc,
        allowed_prauc,
        sum(scn_aurocs) / max(1, len(scn_aurocs)),
        sum(scn_praucs) / max(1, len(scn_praucs)),
        brier_cal,
        ece_cal,
        brier_raw,
        ece_raw,
        roc_points,
        pr_points,
        allowed_pr_points,
        rel_bins,
        loso_rows,
        loso_mean_pr,
        target,
        tp,
        fp,
        tn,
        fn,
    )


def compute_metrics(events: list[EventRow], b4_eval: B4RiskEvaluation | None = None) -> list[MetricRow]:
    grouped: dict[tuple[str, str], dict[int, list[EventRow]]] = {}
    for event in events:
        grouped.setdefault((event.baseline, event.scenario), {}).setdefault(event.seed, []).append(event)

    rows: list[MetricRow] = []
    for (baseline, scenario), by_seed in sorted(grouped.items()):
        asr_vals: list[float] = []
        cost_vals: list[float] = []
        frr_vals: list[float] = []
        thr_vals: list[float] = []
        p50_vals: list[float] = []
        p95_vals: list[float] = []
        risk_p50_vals: list[float] = []
        risk_p90_vals: list[float] = []
        attack_allow_vals: list[float] = []
        attack_throttle_vals: list[float] = []
        for seed_bucket in by_seed.values():
            asr, cost, frr, thr, p50, p95, risk_p50, risk_p90, attack_allow, attack_throttle = _seed_metric(seed_bucket)
            asr_vals.append(asr)
            cost_vals.append(cost)
            frr_vals.append(frr)
            thr_vals.append(thr)
            p50_vals.append(p50)
            p95_vals.append(p95)
            risk_p50_vals.append(risk_p50)
            risk_p90_vals.append(risk_p90)
            attack_allow_vals.append(attack_allow)
            attack_throttle_vals.append(attack_throttle)

        is_b4 = baseline == "B4" and b4_eval is not None
        rows.append(
            MetricRow(
                baseline=baseline,
                scenario=scenario,
                attack_success_rate_mean=_mean_std(asr_vals)[0],
                attack_success_rate_std=_mean_std(asr_vals)[1],
                cost_leakage_tokens_mean=_mean_std(cost_vals)[0],
                cost_leakage_tokens_std=_mean_std(cost_vals)[1],
                false_reject_rate_mean=_mean_std(frr_vals)[0],
                false_reject_rate_std=_mean_std(frr_vals)[1],
                throttle_rate_mean=_mean_std(thr_vals)[0],
                throttle_rate_std=_mean_std(thr_vals)[1],
                p50_ms_mean=_mean_std(p50_vals)[0],
                p50_ms_std=_mean_std(p50_vals)[1],
                p95_ms_mean=_mean_std(p95_vals)[0],
                p95_ms_std=_mean_std(p95_vals)[1],
                risk_p50_mean=_mean_std_ignore_negative(risk_p50_vals)[0],
                risk_p50_std=_mean_std_ignore_negative(risk_p50_vals)[1],
                risk_p90_mean=_mean_std_ignore_negative(risk_p90_vals)[0],
                risk_p90_std=_mean_std_ignore_negative(risk_p90_vals)[1],
                attack_allow_count_mean=_mean_std(attack_allow_vals)[0],
                attack_throttle_count_mean=_mean_std(attack_throttle_vals)[0],
                overall_auroc_mean=b4_eval.overall_auroc if is_b4 else -1.0,
                overall_prauc_mean=b4_eval.overall_pr_auc if is_b4 else -1.0,
                allowed_only_auroc_mean=b4_eval.allowed_only_auroc if is_b4 else -1.0,
                allowed_only_prauc_mean=b4_eval.allowed_only_pr_auc if is_b4 else -1.0,
                ece_calibrated_mean=b4_eval.ece_calibrated if is_b4 else -1.0,
            )
        )
    return rows


def compute_b4_risk_summary(events: list[EventRow]) -> dict[str, dict[str, float]]:
    pts = [e for e in events if e.baseline == "B4" and e.risk >= 0.0]
    groups: dict[str, list[float]] = {}
    for e in pts:
        groups.setdefault(f"{e.label}_overall", []).append(e.risk)
        groups.setdefault(f"{e.label}_{e.decision}", []).append(e.risk)

    summary: dict[str, dict[str, float]] = {}
    for k, vals in sorted(groups.items()):
        summary[k] = {"n": float(len(vals)), "p50": _percentile(vals, 0.50), "p90": _percentile(vals, 0.90)}
    return summary
