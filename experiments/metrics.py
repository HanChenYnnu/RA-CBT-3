"""Metrics computation with multi-seed aggregation, risk quality, and defensibility slices."""

from __future__ import annotations

from dataclasses import dataclass
import math

from experiments.scenario_contract import PAIRED_CONTROLS
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
    ece_official_mean: float


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
    auroc: float | None
    pr_auc: float | None
    allowed_only_pr_auc: float | None
    ece: float
    brier: float


@dataclass(frozen=True)
class B4RiskEvaluation:
    overall_auroc: float | None
    overall_pr_auc: float | None
    allowed_only_auroc: float | None
    allowed_only_pr_auc: float | None
    macro_family_auroc: float | None
    macro_family_pr_auc: float | None
    brier_official: float
    ece_official: float
    brier_calibrated: float
    ece_calibrated: float
    brier_raw: float
    ece_raw: float
    calibration_fallback_used: bool
    roc_points: list[RiskPoint]
    pr_points: list[RiskPoint]
    allowed_pr_points: list[RiskPoint]
    reliability_bins: list[ReliabilityBin]
    loso_rows: list[LosoRow]
    loso_mean_pr_auc: float | None
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


def _mean_defined(values: list[float | None]) -> float | None:
    keep = [v for v in values if v is not None]
    return (sum(keep) / len(keep)) if keep else None


def _safe_logit(p: float) -> float:
    q = min(1.0 - 1e-6, max(1e-6, p))
    return math.log(q / (1.0 - q))


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _calibrate_temperature(scores: list[float], labels: list[int]) -> float:
    if not scores:
        return 1.0
    best_t, best_loss = 1.0, float("inf")
    for i in range(10, 301):
        t = i / 100.0
        loss = 0.0
        for s, y in zip(scores, labels):
            p = min(1.0 - 1e-8, max(1e-8, _sigmoid(_safe_logit(s) / t)))
            loss += -(y * math.log(p) + (1 - y) * math.log(1 - p))
        if loss < best_loss:
            best_t, best_loss = t, loss
    return best_t


def _apply_temp(scores: list[float], t: float) -> list[float]:
    return [_sigmoid(_safe_logit(s) / t) for s in scores]


def _sample_thresholds(scores: list[float], descending: bool = False) -> list[float]:
    vals = sorted(set(scores), reverse=descending)
    if len(vals) <= 200:
        return vals
    return vals[:: max(1, len(vals) // 200)]


def _roc(labels: list[int], scores: list[float]) -> tuple[float | None, list[RiskPoint]]:
    if not labels or len(set(labels)) < 2:
        return (None, [])
    thresholds = sorted({0.0, 1.0, *_sample_thresholds(scores)})
    pts: list[RiskPoint] = []
    pos = sum(labels)
    neg = len(labels) - pos
    for t in thresholds:
        tp = sum(1 for y, s in zip(labels, scores) if y == 1 and s >= t)
        fp = sum(1 for y, s in zip(labels, scores) if y == 0 and s >= t)
        pts.append(RiskPoint(fp / max(1, neg), tp / max(1, pos)))
    pts = sorted(pts, key=lambda p: p.x)
    area = 0.0
    for i in range(1, len(pts)):
        x0, y0 = pts[i - 1].x, pts[i - 1].y
        x1, y1 = pts[i].x, pts[i].y
        area += (x1 - x0) * (y0 + y1) / 2.0
    return (max(0.0, min(1.0, area)), pts)


def _pr(labels: list[int], scores: list[float]) -> tuple[float | None, list[RiskPoint]]:
    if not labels or len(set(labels)) < 2:
        return (None, [])
    thresholds = _sample_thresholds(scores, descending=True)
    pts: list[RiskPoint] = []
    pos = sum(labels)
    for t in [1.0001, *thresholds, -0.0001]:
        tp = sum(1 for y, s in zip(labels, scores) if y == 1 and s >= t)
        fp = sum(1 for y, s in zip(labels, scores) if y == 0 and s >= t)
        pts.append(RiskPoint(tp / max(1, pos), tp / max(1, tp + fp)))
    pts = sorted(pts, key=lambda p: p.x)
    area = 0.0
    for i in range(1, len(pts)):
        x0, y0 = pts[i - 1].x, pts[i - 1].y
        x1, y1 = pts[i].x, pts[i].y
        area += (x1 - x0) * ((y0 + y1) / 2.0)
    return (max(0.0, min(1.0, area)), pts)


def _brier_ece(labels: list[int], scores: list[float]) -> tuple[float, float, list[ReliabilityBin]]:
    if not labels:
        return (0.0, 0.0, [])
    brier = sum((s - y) ** 2 for s, y in zip(scores, labels)) / len(scores)
    bins: list[ReliabilityBin] = []
    ece = 0.0
    for i in range(10):
        lo, hi = i / 10.0, (i + 1) / 10.0
        b = [(s, y) for s, y in zip(scores, labels) if (lo <= s < hi) or (i == 9 and s == 1.0)]
        if not b:
            continue
        mean_pred = sum(s for s, _ in b) / len(b)
        emp = sum(y for _, y in b) / len(b)
        ece += abs(mean_pred - emp) * (len(b) / len(scores))
        bins.append(ReliabilityBin(lo, hi, mean_pred, emp, len(b)))
    return (brier, ece, bins)


def _seed_metric(bucket: list[EventRow]) -> tuple[float, float, float, float, float, float, float, float, float, float]:
    total = len(bucket)
    ok = sum(1 for r in bucket if 200 <= r.status_code < 300 and r.reason == "ok")
    asr = ok / total if total else 0.0
    cost = float(sum(r.usage_total_tokens for r in bucket if r.usage_total_tokens > 0))
    benign = [r for r in bucket if r.benign]
    frr = sum(1 for r in benign if r.decision == "deny") / max(1, len(benign))
    throttle_on = benign if benign else bucket
    thr = sum(1 for r in throttle_on if r.decision == "throttle") / max(1, len(throttle_on))
    lat = [float(r.latency_ms) for r in bucket]
    risks = [float(r.risk) for r in bucket if r.risk >= 0.0]
    aa = float(sum(1 for r in bucket if r.label == "attack" and r.decision == "allow"))
    at = float(sum(1 for r in bucket if r.label == "attack" and r.decision == "throttle"))
    return (asr, cost, frr, thr, _percentile(lat, 0.5), _percentile(lat, 0.95), _percentile(risks, 0.5) if risks else -1.0, _percentile(risks, 0.9) if risks else -1.0, aa, at)


def _family_rows() -> dict[str, list[str]]:
    return {
        "S1": ["S1_key_leak_hard", "S1_benign_control_hard"],
        "S2": ["S2_token_leak_hard", "S2_benign_control_hard"],
        "S3": ["S3_replay_hard", "S3_benign_control_hard"],
    }


def compute_b4_risk_evaluation(events: list[EventRow], *, loso_groups: dict[str, list[str]] | None = None) -> B4RiskEvaluation:
    pts = [e for e in events if e.baseline == "B4" and e.risk >= 0.0]
    labels = [1 if e.label == "attack" else 0 for e in pts]
    raw = [e.risk for e in pts]
    if not pts:
        return B4RiskEvaluation(None, None, None, None, None, None, 0, 0, 0, 0, False, [], [], [], [], [], None, 0.5, 0, 0, 0, 0)

    t = _calibrate_temperature(raw, labels)
    cal = _apply_temp(raw, t)

    overall_auroc, roc_pts = _roc(labels, cal)
    overall_pr, pr_pts = _pr(labels, cal)

    allowed = [e for e in pts if e.decision in {"allow", "throttle"}]
    al_labels = [1 if e.label == "attack" else 0 for e in allowed]
    al_scores = _apply_temp([e.risk for e in allowed], t)
    al_auroc, _ = _roc(al_labels, al_scores)
    al_pr, al_pr_pts = _pr(al_labels, al_scores)

    fam_au, fam_pr = [], []
    for scenarios in _family_rows().values():
        subset = [e for e in pts if e.scenario in scenarios]
        ll = [1 if e.label == "attack" else 0 for e in subset]
        ss = _apply_temp([e.risk for e in subset], t)
        fam_au.append(_roc(ll, ss)[0])
        fam_pr.append(_pr(ll, ss)[0])

    brier_raw, ece_raw, _ = _brier_ece(labels, raw)
    brier_cal, ece_cal, rel_cal = _brier_ece(labels, cal)
    fallback = ece_cal > ece_raw + 0.02 or brier_cal > brier_raw + 0.01
    official_scores = raw if fallback else cal
    brier_off, ece_off, rel_off = _brier_ece(labels, official_scores)

    benign_scores = [s for y, s in zip(labels, official_scores) if y == 0]
    threshold = _percentile(benign_scores, 0.99) if benign_scores else 0.5
    tp = sum(1 for y, s in zip(labels, official_scores) if y == 1 and s >= threshold)
    fp = sum(1 for y, s in zip(labels, official_scores) if y == 0 and s >= threshold)
    tn = sum(1 for y, s in zip(labels, official_scores) if y == 0 and s < threshold)
    fn = sum(1 for y, s in zip(labels, official_scores) if y == 1 and s < threshold)

    groups = loso_groups or _family_rows()
    loso: list[LosoRow] = []
    for name, held_scenarios in groups.items():
        train = [e for e in pts if e.scenario not in held_scenarios]
        test = [e for e in pts if e.scenario in held_scenarios]
        tt = _calibrate_temperature([e.risk for e in train], [1 if e.label == "attack" else 0 for e in train])
        test_labels = [1 if e.label == "attack" else 0 for e in test]
        test_scores = _apply_temp([e.risk for e in test], tt)
        au = _roc(test_labels, test_scores)[0]
        pr = _pr(test_labels, test_scores)[0]
        test_allowed = [e for e in test if e.decision in {"allow", "throttle"}]
        tapr = _pr([1 if e.label == "attack" else 0 for e in test_allowed], _apply_temp([e.risk for e in test_allowed], tt))[0] if test_allowed else None
        brier, ece, _ = _brier_ece(test_labels, test_scores)
        loso.append(LosoRow(name, au, pr, tapr, ece, brier))

    return B4RiskEvaluation(
        overall_auroc,
        overall_pr,
        al_auroc,
        al_pr,
        _mean_defined(fam_au),
        _mean_defined(fam_pr),
        brier_off,
        ece_off,
        brier_cal,
        ece_cal,
        brier_raw,
        ece_raw,
        fallback,
        roc_pts,
        pr_pts,
        al_pr_pts,
        rel_off,
        loso,
        _mean_defined([r.pr_auc for r in loso]),
        threshold,
        tp,
        fp,
        tn,
        fn,
    )


def compute_metrics(events: list[EventRow], b4_eval: B4RiskEvaluation | None = None) -> list[MetricRow]:
    grouped: dict[tuple[str, str], dict[int, list[EventRow]]] = {}
    for e in events:
        grouped.setdefault((e.baseline, e.scenario), {}).setdefault(e.seed, []).append(e)

    rows: list[MetricRow] = []
    for (baseline, scenario), by_seed in sorted(grouped.items()):
        vals = [ _seed_metric(seed_bucket) for seed_bucket in by_seed.values() ]
        c = list(zip(*vals))
        is_b4 = baseline == "B4" and b4_eval is not None
        rows.append(MetricRow(
            baseline, scenario,
            _mean_std(list(c[0]))[0], _mean_std(list(c[0]))[1],
            _mean_std(list(c[1]))[0], _mean_std(list(c[1]))[1],
            _mean_std(list(c[2]))[0], _mean_std(list(c[2]))[1],
            _mean_std(list(c[3]))[0], _mean_std(list(c[3]))[1],
            _mean_std(list(c[4]))[0], _mean_std(list(c[4]))[1],
            _mean_std(list(c[5]))[0], _mean_std(list(c[5]))[1],
            _mean_std(list(c[6]))[0], _mean_std(list(c[6]))[1],
            _mean_std(list(c[7]))[0], _mean_std(list(c[7]))[1],
            _mean_std(list(c[8]))[0], _mean_std(list(c[9]))[0],
            b4_eval.overall_auroc if is_b4 and b4_eval.overall_auroc is not None else float("nan"),
            b4_eval.overall_pr_auc if is_b4 and b4_eval.overall_pr_auc is not None else float("nan"),
            b4_eval.allowed_only_auroc if is_b4 and b4_eval.allowed_only_auroc is not None else float("nan"),
            b4_eval.allowed_only_pr_auc if is_b4 and b4_eval.allowed_only_pr_auc is not None else float("nan"),
            b4_eval.ece_official if is_b4 else float("nan"),
        ))
    return rows


def compute_b4_risk_summary(events: list[EventRow]) -> dict[str, dict[str, float]]:
    pts = [e for e in events if e.baseline == "B4" and e.risk >= 0.0]
    groups: dict[str, list[float]] = {}
    for e in pts:
        groups.setdefault(f"{e.label}_overall", []).append(e.risk)
        groups.setdefault(f"{e.label}_{e.decision}", []).append(e.risk)
    return {k: {"n": float(len(v)), "p50": _percentile(v, 0.5), "p90": _percentile(v, 0.9)} for k, v in sorted(groups.items())}
