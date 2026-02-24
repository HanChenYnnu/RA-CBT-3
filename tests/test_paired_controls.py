from experiments.scenario_contract import PAIRED_CONTROLS
from experiments.scenarios import BENIGN_SCENARIOS, scenario_requests


def test_pairs_have_same_distribution_and_diff_labels() -> None:
    for attack, control in PAIRED_CONTROLS.items():
        a = scenario_requests(attack, 30, seed=4, baseline="B4")
        b = scenario_requests(control, 30, seed=4, baseline="B4")
        assert sorted(int(x["max_tokens"]) for x in a) == sorted(int(x["max_tokens"]) for x in b)
        assert control in BENIGN_SCENARIOS
        assert attack not in BENIGN_SCENARIOS
