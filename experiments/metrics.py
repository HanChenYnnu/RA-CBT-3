"""Metrics computation with multi-seed aggregation and B4 AUROC/risk summaries."""

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


@dataclass(frozen=True)
class RiskPoint:
    fpr: float
    tpr: float


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

def _seed_metric(bucket: list[EventRow]) -> tuple[float, float, float, float, float, float, float, float]:
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
    return (asr, cost, frr, throttle, _percentile(latencies, 0.5), _percentile(latencies, 0.95), risk_p50, risk_p90)


def compute_metrics(events: list[EventRow]) -> list[MetricRow]:
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
        for seed_bucket in by_seed.values():
            asr, cost, frr, thr, p50, p95, risk_p50, risk_p90 = _seed_metric(seed_bucket)
            asr_vals.append(asr)
            cost_vals.append(cost)
            frr_vals.append(frr)
            thr_vals.append(thr)
            p50_vals.append(p50)
            p95_vals.append(p95)
            risk_p50_vals.append(risk_p50)
            risk_p90_vals.append(risk_p90)

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
            )
        )
    return rows


def compute_b4_auroc(events: list[EventRow]) -> tuple[float, list[RiskPoint]]:
    pts = [e for e in events if e.baseline == "B4" and e.risk >= 0.0]
    if not pts:
        return (0.0, [])
    thresholds = sorted({round(e.risk, 4) for e in pts})
    if 1.0 not in thresholds:
        thresholds.append(1.0)
    if 0.0 not in thresholds:
        thresholds.insert(0, 0.0)

    roc: list[RiskPoint] = []
    pos = [e for e in pts if e.label == "attack"]
    neg = [e for e in pts if e.label == "benign"]
    for t in thresholds:
        tp = sum(1 for e in pos if e.risk >= t)
        fn = max(1, len(pos)) - tp
        fp = sum(1 for e in neg if e.risk >= t)
        tn = max(1, len(neg)) - fp
        tpr = tp / max(1, (tp + fn))
        fpr = fp / max(1, (fp + tn))
        roc.append(RiskPoint(fpr=fpr, tpr=tpr))

    roc.append(RiskPoint(fpr=0.0, tpr=0.0))
    roc.append(RiskPoint(fpr=1.0, tpr=1.0))
    roc = sorted(roc, key=lambda p: p.fpr)
    area = 0.0
    for i in range(1, len(roc)):
        x0, y0 = roc[i - 1].fpr, roc[i - 1].tpr
        x1, y1 = roc[i].fpr, roc[i].tpr
        area += (x1 - x0) * (y0 + y1) / 2.0
    return (max(0.0, min(1.0, area)), roc)


def compute_b4_risk_summary(events: list[EventRow]) -> dict[str, dict[str, float]]:
    pts = [e for e in events if e.baseline == "B4" and e.risk >= 0.0]
    groups: dict[str, list[float]] = {}
    for e in pts:
        groups.setdefault(f"{e.label}_overall", []).append(e.risk)
        groups.setdefault(f"{e.label}_{e.decision}", []).append(e.risk)

    summary: dict[str, dict[str, float]] = {}
    for k, vals in sorted(groups.items()):
        summary[k] = {
            "n": float(len(vals)),
            "p50": _percentile(vals, 0.50),
            "p90": _percentile(vals, 0.90),
        }
    return summary
