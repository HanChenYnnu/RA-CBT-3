from scripts.metrics import MIN_CLASS_NON_DENY, compute_precision_recall_lift_at_k


def test_precision_recall_lift_computation():
    risks = [0.95, 0.93, 0.91, 0.89, 0.87] + [0.85] * 20 + [0.1] * 30
    labels = [1, 1, 1, 1, 1] + [1] * 20 + [0] * 30
    m = compute_precision_recall_lift_at_k(risks, labels, ks=(10, 30, 50))
    assert m.n_attack_non_deny >= MIN_CLASS_NON_DENY
    assert m.n_benign_non_deny >= MIN_CLASS_NON_DENY
    assert m.base_attack_rate_non_deny is not None
    assert m.precision_at[10] is not None
    assert m.lift_at[30] is not None
    assert m.lift_at[30] > 1.0


def test_metrics_return_na_below_min_class_non_deny():
    risks = [0.9] * 10 + [0.2] * 50
    labels = [1] * 10 + [0] * 50
    m = compute_precision_recall_lift_at_k(risks, labels)
    assert m.precision_at[10] is None
    assert m.recall_at[30] is None
    assert m.lift_at[50] is None
