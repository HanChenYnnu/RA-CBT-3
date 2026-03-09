"""Metrics computation with multi-seed aggregation and defensibility slices."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import random

from experiments.types import EventRow

MIN_NON_DENY = 50
MIN_CLASS_NON_DENY = 20
K_VALUES = [10, 30, 50, 100, 200]
BOOTSTRAP_N = 1000


@dataclass(frozen=True)
class MetricRow:
    baseline: str
    scenario: str
    success_rate_mean: float
    success_rate_std: float
    attack_success_rate_allow_mean: float
    attack_success_rate_allow_std: float
    attack_success_rate_non_deny_mean: float
    attack_success_rate_non_deny_std: float
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
    non_deny_auroc_mean: float
    non_deny_prauc_mean: float
    ece_official_mean: float
    base_attack_rate_non_deny: float
    n_non_deny: float
    n_attack_non_deny: float
    n_benign_non_deny: float
    non_deny_p_at_10: float
    non_deny_p_at_30: float
    non_deny_p_at_50: float
    non_deny_p_at_100: float
    non_deny_p_at_200: float
    non_deny_r_at_10: float
    non_deny_r_at_30: float
    non_deny_r_at_50: float
    non_deny_r_at_100: float
    non_deny_r_at_200: float
    non_deny_lift_at_10: float
    non_deny_lift_at_30: float
    non_deny_lift_at_50: float
    non_deny_lift_at_100: float
    non_deny_lift_at_200: float
    non_deny_p_at_30_ci_low: float
    non_deny_p_at_30_ci_high: float
    non_deny_p_at_100_ci_low: float
    non_deny_p_at_100_ci_high: float
    non_deny_lift_at_30_ci_low: float
    non_deny_lift_at_30_ci_high: float
    non_deny_lift_at_100_ci_low: float
    non_deny_lift_at_100_ci_high: float
    non_deny_pr_auc_ci_low: float
    non_deny_pr_auc_ci_high: float
    base_attack_rate_ci_low: float
    base_attack_rate_ci_high: float
    # budget sweep label-split fields
    sr_benign: float
    frr_benign: float
    throttle_benign: float
    p95_benign: float
    asr_allow_attack: float
    asr_non_deny_attack: float
    cost_attack: float
    throttle_attack: float
    p95_attack: float


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
    non_deny_auroc: float | None
    non_deny_pr_auc: float | None
    n_total: int
    n_non_deny: int
    n_attack_non_deny: int
    n_benign_non_deny: int
    ece: float
    brier: float


@dataclass(frozen=True)
class ServedTrafficSlice:
    name: str
    non_deny_total: int
    n_attack_non_deny: int
    n_benign_non_deny: int
    base_attack_rate_non_deny: float | None
    non_deny_pr_auc: float | None
    non_deny_pr_auc_ci_low: float | None
    non_deny_pr_auc_ci_high: float | None
    base_attack_rate_ci_low: float | None
    base_attack_rate_ci_high: float | None
    p_at_k: dict[int, float | None]
    r_at_k: dict[int, float | None]
    lift_at_k: dict[int, float | None]
    p_ci: dict[int, tuple[float | None, float | None]]
    lift_ci: dict[int, tuple[float | None, float | None]]


@dataclass(frozen=True)
class B4RiskEvaluation:
    overall_auroc: float | None
    overall_pr_auc: float | None
    non_deny_auroc: float | None
    non_deny_pr_auc: float | None
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
    non_deny_pr_points: list[RiskPoint]
    non_deny_attack_cdf_points: list[RiskPoint]
    non_deny_benign_cdf_points: list[RiskPoint]
    reliability_bins: list[ReliabilityBin]
    served_traffic_slices: list[ServedTrafficSlice]
    loso_rows: list[LosoRow]
    loso_mean_pr_auc: float | None
    loso_mean_non_deny_pr_auc: float | None
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
    return vals if len(vals) <= 200 else vals[:: max(1, len(vals) // 200)]


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


def _seed_metric(bucket: list[EventRow]) -> tuple[float, float, float, float, float, float, float, float, float, float, float, float]:
    total = len(bucket)
    ok = [r for r in bucket if 200 <= r.status_code < 300 and r.reason == "ok"]
    sr = len(ok) / total if total else 0.0
    asr_allow = sum(1 for r in ok if r.decision == "allow") / total if total else 0.0
    asr_non_deny = sum(1 for r in ok if r.decision in {"allow", "throttle"}) / total if total else 0.0
    cost = float(sum(r.usage_total_tokens for r in bucket if r.usage_total_tokens > 0))
    benign = [r for r in bucket if r.benign]
    frr = sum(1 for r in benign if r.decision == "deny") / max(1, len(benign))
    throttle_on = benign if benign else bucket
    thr = sum(1 for r in throttle_on if r.decision == "throttle") / max(1, len(throttle_on))
    lat = [float(r.latency_ms) for r in bucket]
    risks = [float(r.risk) for r in bucket if r.risk >= 0.0]
    aa = float(sum(1 for r in bucket if r.label == "attack" and r.decision == "allow"))
    at = float(sum(1 for r in bucket if r.label == "attack" and r.decision == "throttle"))
    return (sr, asr_allow, asr_non_deny, cost, frr, thr, _percentile(lat, 0.5), _percentile(lat, 0.95), _percentile(risks, 0.5) if risks else -1.0, _percentile(risks, 0.9) if risks else -1.0, aa, at)


def _family_rows() -> dict[str, list[str]]:
    return {
        "S1_pair": ["S1_key_leak_hard", "S1_benign_control_hard"],
        "S2_pair": ["S2_token_leak_hard", "S2_benign_control_hard"],
        "S3_pair": ["S3_replay_hard", "S3_replay_nearmiss_hard", "S3_benign_control_hard"],
    }


def _non_deny_metrics(labels: list[int], scores: list[float]) -> tuple[float | None, float | None, list[RiskPoint]]:
    attack_count = sum(labels)
    benign_count = len(labels) - attack_count
    if len(labels) < MIN_NON_DENY or attack_count < MIN_CLASS_NON_DENY or benign_count < MIN_CLASS_NON_DENY or len(set(labels)) < 2:
        return (None, None, [])
    au, _ = _roc(labels, scores)
    pr, pts = _pr(labels, scores)
    return (au, pr, pts)


def _risk_cdf(scores: list[float]) -> list[RiskPoint]:
    if not scores:
        return []
    ordered = sorted(scores)
    n = len(ordered)
    return [RiskPoint(v, (i + 1) / n) for i, v in enumerate(ordered)]


def _ci(vals: list[float]) -> tuple[float | None, float | None]:
    if not vals:
        return (None, None)
    return (_percentile(vals, 0.025), _percentile(vals, 0.975))


def _served_topk_metrics(labels: list[int], scores: list[float], name: str, *, bootstrap_seed: int) -> ServedTrafficSlice:
    attack_count = sum(labels)
    benign_count = len(labels) - attack_count
    n = len(labels)
    base_rate = (attack_count / n) if n else None
    defined = n >= MIN_NON_DENY and attack_count >= MIN_CLASS_NON_DENY and benign_count >= MIN_CLASS_NON_DENY and len(set(labels)) == 2

    p_at_k = {k: None for k in K_VALUES}
    r_at_k = {k: None for k in K_VALUES}
    lift_at_k = {k: None for k in K_VALUES}
    p_ci = {k: (None, None) for k in K_VALUES}
    lift_ci = {k: (None, None) for k in K_VALUES}

    if not defined:
        return ServedTrafficSlice(name, n, attack_count, benign_count, base_rate, None, None, None, None, None, p_at_k, r_at_k, lift_at_k, p_ci, lift_ci)

    ranked = sorted(zip(scores, labels), key=lambda x: x[0], reverse=True)

    def _calc(rows: list[tuple[float, int]]) -> tuple[dict[int, float | None], dict[int, float | None], dict[int, float | None], float | None, float | None]:
        rr = sorted(rows, key=lambda x: x[0], reverse=True)
        nn = len(rr)
        aa = sum(lbl for _, lbl in rr)
        br = (aa / nn) if nn else None
        pp: dict[int, float | None] = {k: None for k in K_VALUES}
        rrk: dict[int, float | None] = {k: None for k in K_VALUES}
        ll: dict[int, float | None] = {k: None for k in K_VALUES}
        for k in K_VALUES:
            if k > nn:
                continue
            top = rr[:k]
            prec = sum(lbl for _, lbl in top) / k
            rec = sum(lbl for _, lbl in top) / max(1, aa)
            pp[k] = prec
            rrk[k] = rec
            ll[k] = (prec / br) if br and br > 0 else None
        pr_auc = _pr([lbl for _, lbl in rr], [s for s, _ in rr])[0]
        return (pp, rrk, ll, pr_auc, br)

    p_at_k, r_at_k, lift_at_k, pr_auc, _ = _calc(ranked)

    rng = random.Random(bootstrap_seed)
    p_boot = {k: [] for k in K_VALUES}
    lift_boot = {k: [] for k in K_VALUES}
    pr_boot: list[float] = []
    br_boot: list[float] = []
    for _ in range(BOOTSTRAP_N):
        sample = [ranked[rng.randrange(len(ranked))] for _ in range(len(ranked))]
        pp, _, ll, prb, br = _calc(sample)
        if prb is not None:
            pr_boot.append(prb)
        if br is not None:
            br_boot.append(br)
        for k in K_VALUES:
            if pp[k] is not None:
                p_boot[k].append(pp[k])
            if ll[k] is not None:
                lift_boot[k].append(ll[k])

    for k in K_VALUES:
        p_ci[k] = _ci(p_boot[k])
        lift_ci[k] = _ci(lift_boot[k])
    pr_ci_low, pr_ci_high = _ci(pr_boot)
    br_ci_low, br_ci_high = _ci(br_boot)

    return ServedTrafficSlice(
        name,
        n,
        attack_count,
        benign_count,
        base_rate,
        pr_auc,
        pr_ci_low,
        pr_ci_high,
        br_ci_low,
        br_ci_high,
        p_at_k,
        r_at_k,
        lift_at_k,
        p_ci,
        lift_ci,
    )


def compute_b4_risk_evaluation(events: list[EventRow], *, loso_groups: dict[str, list[str]] | None = None) -> B4RiskEvaluation:
    pts = [e for e in events if e.baseline == "B4" and e.risk >= 0.0]
    labels = [1 if e.label == "attack" else 0 for e in pts]
    raw = [e.risk for e in pts]
    if not pts:
        return B4RiskEvaluation(None, None, None, None, None, None, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, False, [], [], [], [], [], [], [], None, None, 0.5, 0, 0, 0, 0)

    t = _calibrate_temperature(raw, labels)
    cal = _apply_temp(raw, t)

    overall_auroc, roc_pts = _roc(labels, cal)
    overall_pr, pr_pts = _pr(labels, cal)

    non_deny = [e for e in pts if e.decision in {"allow", "throttle"}]
    nd_labels = [1 if e.label == "attack" else 0 for e in non_deny]
    nd_scores = _apply_temp([e.risk for e in non_deny], t)
    nd_auroc, nd_pr, nd_pr_pts = _non_deny_metrics(nd_labels, nd_scores)
    nd_attack_cdf = _risk_cdf([s for y, s in zip(nd_labels, nd_scores) if y == 1])
    nd_benign_cdf = _risk_cdf([s for y, s in zip(nd_labels, nd_scores) if y == 0])

    fam_au, fam_pr = [], []
    for scenarios in _family_rows().values():
        subset = [e for e in pts if e.scenario in scenarios]
        ll = [1 if e.label == "attack" else 0 for e in subset]
        ss = _apply_temp([e.risk for e in subset], t)
        fam_au.append(_roc(ll, ss)[0])
        fam_pr.append(_pr(ll, ss)[0])

    brier_raw, ece_raw, _ = _brier_ece(labels, raw)
    brier_cal, ece_cal, _ = _brier_ece(labels, cal)
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
    loso_rows: list[LosoRow] = []
    for name, held_scenarios in groups.items():
        train = [e for e in pts if e.scenario not in held_scenarios]
        test = [e for e in pts if e.scenario in held_scenarios]
        tt = _calibrate_temperature([e.risk for e in train], [1 if e.label == "attack" else 0 for e in train])
        test_labels = [1 if e.label == "attack" else 0 for e in test]
        test_scores = _apply_temp([e.risk for e in test], tt)
        au = _roc(test_labels, test_scores)[0]
        pr = _pr(test_labels, test_scores)[0]

        test_non_deny = [e for e in test if e.decision in {"allow", "throttle"}]
        nd_fold_labels = [1 if e.label == "attack" else 0 for e in test_non_deny]
        nd_fold_scores = _apply_temp([e.risk for e in test_non_deny], tt)
        nd_au, nd_pr_fold = _non_deny_metrics(nd_fold_labels, nd_fold_scores)[:2]

        brier, ece, _ = _brier_ece(test_labels, test_scores)
        loso_rows.append(
            LosoRow(
                heldout_scenario=name,
                auroc=au,
                pr_auc=pr,
                non_deny_auroc=nd_au,
                non_deny_pr_auc=nd_pr_fold,
                n_total=len(test),
                n_non_deny=len(test_non_deny),
                n_attack_non_deny=sum(nd_fold_labels),
                n_benign_non_deny=len(nd_fold_labels) - sum(nd_fold_labels),
                ece=ece,
                brier=brier,
            )
        )

    official_by_id = {id(e): s for e, s in zip(pts, official_scores)}
    served_slices: list[ServedTrafficSlice] = []
    for name, held_scenarios in groups.items():
        sub = [e for e in non_deny if e.scenario in held_scenarios]
        sub_labels = [1 if e.label == "attack" else 0 for e in sub]
        sub_scores = [official_by_id[id(e)] for e in sub]
        seed_val = int(hashlib.sha256(name.encode()).hexdigest()[:8], 16)
        served_slices.append(_served_topk_metrics(sub_labels, sub_scores, name=name, bootstrap_seed=seed_val))
    served_slices.append(_served_topk_metrics(nd_labels, nd_scores, name="overall", bootstrap_seed=1337))

    return B4RiskEvaluation(
        overall_auroc=overall_auroc,
        overall_pr_auc=overall_pr,
        non_deny_auroc=nd_auroc,
        non_deny_pr_auc=nd_pr,
        macro_family_auroc=_mean_defined(fam_au),
        macro_family_pr_auc=_mean_defined(fam_pr),
        brier_official=brier_off,
        ece_official=ece_off,
        brier_calibrated=brier_cal,
        ece_calibrated=ece_cal,
        brier_raw=brier_raw,
        ece_raw=ece_raw,
        calibration_fallback_used=fallback,
        roc_points=roc_pts,
        pr_points=pr_pts,
        non_deny_pr_points=nd_pr_pts,
        non_deny_attack_cdf_points=nd_attack_cdf,
        non_deny_benign_cdf_points=nd_benign_cdf,
        reliability_bins=rel_off,
        served_traffic_slices=served_slices,
        loso_rows=loso_rows,
        loso_mean_pr_auc=_mean_defined([r.pr_auc for r in loso_rows]),
        loso_mean_non_deny_pr_auc=_mean_defined([r.non_deny_pr_auc for r in loso_rows]),
        operating_point_threshold=threshold,
        confusion_tp=tp,
        confusion_fp=fp,
        confusion_tn=tn,
        confusion_fn=fn,
    )


def _sweep_split(bucket: list[EventRow]) -> tuple[float, float, float, float, float, float, float, float, float]:
    benign = [r for r in bucket if r.label == "benign"]
    attack = [r for r in bucket if r.label == "attack"]
    b_ok = [r for r in benign if 200 <= r.status_code < 300 and r.reason == "ok"]
    a_ok = [r for r in attack if 200 <= r.status_code < 300 and r.reason == "ok"]
    sr_benign = len(b_ok) / max(1, len(benign))
    frr_benign = sum(1 for r in benign if r.decision == "deny") / max(1, len(benign))
    throttle_benign = sum(1 for r in benign if r.decision == "throttle") / max(1, len(benign))
    p95_benign = _percentile([float(r.latency_ms) for r in benign], 0.95) if benign else float("nan")

    asr_allow_attack = sum(1 for r in a_ok if r.decision == "allow") / max(1, len(attack))
    asr_non_deny_attack = sum(1 for r in a_ok if r.decision in {"allow", "throttle"}) / max(1, len(attack))
    cost_attack = float(sum(r.usage_total_tokens for r in attack if r.usage_total_tokens > 0))
    throttle_attack = sum(1 for r in attack if r.decision == "throttle") / max(1, len(attack))
    p95_attack = _percentile([float(r.latency_ms) for r in attack], 0.95) if attack else float("nan")
    return (sr_benign, frr_benign, throttle_benign, p95_benign, asr_allow_attack, asr_non_deny_attack, cost_attack, throttle_attack, p95_attack)


def compute_metrics(events: list[EventRow], b4_eval: B4RiskEvaluation | None = None) -> list[MetricRow]:
    grouped: dict[tuple[str, str], dict[int, list[EventRow]]] = {}
    for e in events:
        grouped.setdefault((e.baseline, e.scenario), {}).setdefault(e.seed, []).append(e)

    served_lookup = {s.name: s for s in (b4_eval.served_traffic_slices if b4_eval is not None else [])}
    rows: list[MetricRow] = []
    for (baseline, scenario), by_seed in sorted(grouped.items()):
        vals = [_seed_metric(bucket) for bucket in by_seed.values()]
        c = list(zip(*vals))
        is_b4 = baseline == "B4" and b4_eval is not None

        served_name = ""
        if scenario in {"S1_key_leak_hard", "S1_benign_control_hard"}:
            served_name = "S1_pair"
        elif scenario in {"S2_token_leak_hard", "S2_benign_control_hard"}:
            served_name = "S2_pair"
        elif scenario in {"S3_replay_hard", "S3_replay_nearmiss_hard", "S3_benign_control_hard"}:
            served_name = "S3_pair"
        elif scenario.startswith("S4_budget_sweep_x"):
            served_name = "overall"
        served = served_lookup.get(served_name) if is_b4 else None

        split_vals = [_sweep_split(bucket) for bucket in by_seed.values()] if scenario.startswith("S4_budget_sweep_x") else []
        s = list(zip(*split_vals)) if split_vals else []

        def _sv(i: int) -> float:
            return _mean_std(list(s[i]))[0] if s else float("nan")

        rows.append(
            MetricRow(
                baseline,
                scenario,
                _mean_std(list(c[0]))[0], _mean_std(list(c[0]))[1],
                _mean_std(list(c[1]))[0], _mean_std(list(c[1]))[1],
                _mean_std(list(c[2]))[0], _mean_std(list(c[2]))[1],
                _mean_std(list(c[3]))[0], _mean_std(list(c[3]))[1],
                _mean_std(list(c[4]))[0], _mean_std(list(c[4]))[1],
                _mean_std(list(c[5]))[0], _mean_std(list(c[5]))[1],
                _mean_std(list(c[6]))[0], _mean_std(list(c[6]))[1],
                _mean_std(list(c[7]))[0], _mean_std(list(c[7]))[1],
                _mean_std(list(c[8]))[0], _mean_std(list(c[8]))[1],
                _mean_std(list(c[9]))[0], _mean_std(list(c[9]))[1],
                _mean_std(list(c[10]))[0], _mean_std(list(c[11]))[0],
                b4_eval.overall_auroc if is_b4 and b4_eval.overall_auroc is not None else float("nan"),
                b4_eval.overall_pr_auc if is_b4 and b4_eval.overall_pr_auc is not None else float("nan"),
                b4_eval.non_deny_auroc if is_b4 and b4_eval.non_deny_auroc is not None else float("nan"),
                b4_eval.non_deny_pr_auc if is_b4 and b4_eval.non_deny_pr_auc is not None else float("nan"),
                b4_eval.ece_official if is_b4 else float("nan"),
                served.base_attack_rate_non_deny if served and served.base_attack_rate_non_deny is not None else float("nan"),
                float(served.non_deny_total) if served else float("nan"),
                float(served.n_attack_non_deny) if served else float("nan"),
                float(served.n_benign_non_deny) if served else float("nan"),
                served.p_at_k[10] if served and served.p_at_k[10] is not None else float("nan"),
                served.p_at_k[30] if served and served.p_at_k[30] is not None else float("nan"),
                served.p_at_k[50] if served and served.p_at_k[50] is not None else float("nan"),
                served.p_at_k[100] if served and served.p_at_k[100] is not None else float("nan"),
                served.p_at_k[200] if served and served.p_at_k[200] is not None else float("nan"),
                served.r_at_k[10] if served and served.r_at_k[10] is not None else float("nan"),
                served.r_at_k[30] if served and served.r_at_k[30] is not None else float("nan"),
                served.r_at_k[50] if served and served.r_at_k[50] is not None else float("nan"),
                served.r_at_k[100] if served and served.r_at_k[100] is not None else float("nan"),
                served.r_at_k[200] if served and served.r_at_k[200] is not None else float("nan"),
                served.lift_at_k[10] if served and served.lift_at_k[10] is not None else float("nan"),
                served.lift_at_k[30] if served and served.lift_at_k[30] is not None else float("nan"),
                served.lift_at_k[50] if served and served.lift_at_k[50] is not None else float("nan"),
                served.lift_at_k[100] if served and served.lift_at_k[100] is not None else float("nan"),
                served.lift_at_k[200] if served and served.lift_at_k[200] is not None else float("nan"),
                served.p_ci[30][0] if served and served.p_ci[30][0] is not None else float("nan"),
                served.p_ci[30][1] if served and served.p_ci[30][1] is not None else float("nan"),
                served.p_ci[100][0] if served and served.p_ci[100][0] is not None else float("nan"),
                served.p_ci[100][1] if served and served.p_ci[100][1] is not None else float("nan"),
                served.lift_ci[30][0] if served and served.lift_ci[30][0] is not None else float("nan"),
                served.lift_ci[30][1] if served and served.lift_ci[30][1] is not None else float("nan"),
                served.lift_ci[100][0] if served and served.lift_ci[100][0] is not None else float("nan"),
                served.lift_ci[100][1] if served and served.lift_ci[100][1] is not None else float("nan"),
                served.non_deny_pr_auc_ci_low if served and served.non_deny_pr_auc_ci_low is not None else float("nan"),
                served.non_deny_pr_auc_ci_high if served and served.non_deny_pr_auc_ci_high is not None else float("nan"),
                served.base_attack_rate_ci_low if served and served.base_attack_rate_ci_low is not None else float("nan"),
                served.base_attack_rate_ci_high if served and served.base_attack_rate_ci_high is not None else float("nan"),
                _sv(0), _sv(1), _sv(2), _sv(3), _sv(4), _sv(5), _sv(6), _sv(7), _sv(8),
            )
        )
    return rows


def compute_b4_risk_summary(events: list[EventRow]) -> dict[str, dict[str, float]]:
    pts = [e for e in events if e.baseline == "B4" and e.risk >= 0.0]
    groups: dict[str, list[float]] = {}
    for e in pts:
        groups.setdefault(f"{e.label}_overall", []).append(e.risk)
        groups.setdefault(f"{e.label}_{e.decision}", []).append(e.risk)
    return {k: {"n": float(len(v)), "p50": _percentile(v, 0.5), "p90": _percentile(v, 0.9)} for k, v in sorted(groups.items())}


def compute_decision_latency_stats(events: list[EventRow], baselines: list[str]) -> dict[str, dict[str, dict[str, float]]]:
    out: dict[str, dict[str, dict[str, float]]] = {}
    for baseline in baselines:
        out[baseline] = {}
        for decision in ["allow", "throttle", "deny"]:
            vals = [e.latency_ms for e in events if e.baseline == baseline and e.decision == decision]
            if not vals:
                continue
            out[baseline][decision] = {"mean": sum(vals) / len(vals), "p95": _percentile([float(v) for v in vals], 0.95), "n": float(len(vals))}
    return out
