from experiments.metrics import _mean_defined, _pr, _roc


def test_single_class_is_na() -> None:
    labels=[0,0,0]
    scores=[0.1,0.2,0.3]
    assert _roc(labels,scores)[0] is None
    assert _pr(labels,scores)[0] is None


def test_macro_loso_exclude_na() -> None:
    assert _mean_defined([None,0.4,0.6]) == 0.5
