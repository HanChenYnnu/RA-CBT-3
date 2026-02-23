from experiments.scenario_contract import PAIRED_CONTROLS
from experiments.scenarios import BENIGN_SCENARIOS, SCENARIOS, scenario_requests


def test_controls_exist_and_are_benign() -> None:
    for atk, ctrl in PAIRED_CONTROLS.items():
        assert atk in SCENARIOS
        assert ctrl in SCENARIOS
        assert ctrl in BENIGN_SCENARIOS


def test_controls_match_load_shape() -> None:
    seed = 7
    for atk, ctrl in PAIRED_CONTROLS.items():
        a = scenario_requests(atk, 20, seed=seed, baseline="B4")
        b = scenario_requests(ctrl, 20, seed=seed, baseline="B4")
        assert sorted(x["max_tokens"] for x in a) == sorted(x["max_tokens"] for x in b)
