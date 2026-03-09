from experiments.metrics import _served_topk_metrics


def test_precision_recall_lift_topk() -> None:
    labels = [1] * 40 + [0] * 260
    scores = [0.999 - i * 0.001 for i in range(300)]
    s = _served_topk_metrics(labels, scores, name="S3_pair", bootstrap_seed=7)
    assert s.p_at_k[10] == 1.0
    assert s.r_at_k[10] == 0.25
    assert s.base_attack_rate_non_deny == (40 / 300)
    assert s.lift_at_k[10] == 1.0 / (40 / 300)
    assert s.p_at_k[200] is not None
    assert s.p_ci[30][0] is not None


def test_topk_undefined_when_min_class_not_met() -> None:
    labels = [1] * 19 + [0] * 90
    scores = [0.9] * len(labels)
    s = _served_topk_metrics(labels, scores, name="S3_pair", bootstrap_seed=7)
    assert s.p_at_k[30] is None
    assert s.lift_at_k[30] is None
