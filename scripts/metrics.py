from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


MIN_CLASS_NON_DENY = 20


@dataclass
class RankedMetrics:
    precision_at: dict[int, float | None]
    recall_at: dict[int, float | None]
    lift_at: dict[int, float | None]
    base_attack_rate_non_deny: float | None
    n_attack_non_deny: int
    n_benign_non_deny: int


def _safe_div(n: float, d: float) -> float | None:
    if d == 0:
        return None
    return n / d


def compute_precision_recall_lift_at_k(
    risks: Sequence[float], labels_attack: Sequence[int], ks: Iterable[int] = (10, 30, 50)
) -> RankedMetrics:
    if len(risks) != len(labels_attack):
        raise ValueError("risks and labels_attack length mismatch")

    n = len(risks)
    n_attack = sum(labels_attack)
    n_benign = n - n_attack

    precision_at: dict[int, float | None] = {}
    recall_at: dict[int, float | None] = {}
    lift_at: dict[int, float | None] = {}

    if n_attack < MIN_CLASS_NON_DENY or n_benign < MIN_CLASS_NON_DENY:
        for k in ks:
            precision_at[k] = None
            recall_at[k] = None
            lift_at[k] = None
        return RankedMetrics(
            precision_at=precision_at,
            recall_at=recall_at,
            lift_at=lift_at,
            base_attack_rate_non_deny=None,
            n_attack_non_deny=n_attack,
            n_benign_non_deny=n_benign,
        )

    ranked = sorted(zip(risks, labels_attack), key=lambda x: x[0], reverse=True)
    base = n_attack / n
    for k in ks:
        top = ranked[: min(k, n)]
        tp_top = sum(label for _, label in top)
        p = _safe_div(tp_top, len(top))
        r = _safe_div(tp_top, n_attack)
        precision_at[k] = p
        recall_at[k] = r
        lift_at[k] = None if p is None else _safe_div(p, base)

    return RankedMetrics(
        precision_at=precision_at,
        recall_at=recall_at,
        lift_at=lift_at,
        base_attack_rate_non_deny=base,
        n_attack_non_deny=n_attack,
        n_benign_non_deny=n_benign,
    )


def compute_pr_curve_points(risks: Sequence[float], labels_attack: Sequence[int]) -> tuple[list[float], list[float]]:
    ranked = sorted(zip(risks, labels_attack), key=lambda x: x[0], reverse=True)
    total_pos = sum(labels_attack)
    if total_pos == 0:
        return [], []
    tp = 0
    fp = 0
    recalls = []
    precisions = []
    for _, label in ranked:
        if label == 1:
            tp += 1
        else:
            fp += 1
        recalls.append(tp / total_pos)
        precisions.append(tp / (tp + fp))
    return recalls, precisions


def compute_roc_points(risks: Sequence[float], labels_attack: Sequence[int]) -> tuple[list[float], list[float]]:
    ranked = sorted(zip(risks, labels_attack), key=lambda x: x[0], reverse=True)
    pos = sum(labels_attack)
    neg = len(labels_attack) - pos
    if pos == 0 or neg == 0:
        return [], []
    tp = fp = 0
    fprs = [0.0]
    tprs = [0.0]
    for _, label in ranked:
        if label == 1:
            tp += 1
        else:
            fp += 1
        fprs.append(fp / neg)
        tprs.append(tp / pos)
    return fprs, tprs


def auc(xs: Sequence[float], ys: Sequence[float]) -> float | None:
    if len(xs) < 2:
        return None
    area = 0.0
    for i in range(1, len(xs)):
        dx = xs[i] - xs[i - 1]
        area += dx * (ys[i] + ys[i - 1]) / 2
    return area
