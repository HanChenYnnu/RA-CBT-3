from experiments.metrics import _mean_defined, _pr, _roc


def test_single_class_metrics_are_none() -> None:
    labels = [1, 1, 1]
    scores = [0.1, 0.2, 0.3]
    auroc, _ = _roc(labels, scores)
    pr, _ = _pr(labels, scores)
    assert auroc is None
    assert pr is None


def test_macro_excludes_none() -> None:
    assert _mean_defined([0.4, None, 0.6]) == 0.5
