from experiments.metrics import _served_topk_metrics


def test_precision_recall_lift_topk() -> None:
    labels = [1] * 40 + [0] * 60
    scores = [0.99 - i * 0.01 for i in range(100)]
    s = _served_topk_metrics(labels, scores, name="S3_pair")
    assert s.non_deny_p_at_10 == 1.0
    assert s.non_deny_r_at_10 == 0.25
    assert s.base_attack_rate_non_deny == 0.4
    assert s.non_deny_lift_at_10 == 2.5
    assert s.non_deny_p_at_30 == 1.0


def test_topk_undefined_when_min_class_not_met() -> None:
    labels = [1] * 19 + [0] * 90
    scores = [0.9] * len(labels)
    s = _served_topk_metrics(labels, scores, name="S3_pair")
    assert s.non_deny_p_at_30 is None
    assert s.non_deny_lift_at_30 is None
