from pathlib import Path

from baselines.B4_full.harness import run_b4_scenario
from experiments.scenario_audit import read_samples, reset_audit


def test_nearmiss_replay_properties(tmp_path: Path) -> None:
    reset_audit()
    run_b4_scenario(scenario="S3_replay_hard", n=12, log_path=tmp_path / "hard.jsonl", seed=7)
    run_b4_scenario(scenario="S3_replay_nearmiss_hard", n=12, log_path=tmp_path / "near.jsonl", seed=7)
    run_b4_scenario(scenario="S3_benign_control_hard", n=12, log_path=tmp_path / "benign.jsonl", seed=7)

    samples = read_samples()
    hard = [s for s in samples if s["scenario"] == "S3_replay_hard" and s["baseline"] == "B4"]
    near = [s for s in samples if s["scenario"] == "S3_replay_nearmiss_hard" and s["baseline"] == "B4"]
    ben = [s for s in samples if s["scenario"] == "S3_benign_control_hard" and s["baseline"] == "B4"]

    assert near
    assert all(s["caps"]["label"] == "attack" for s in near)
    assert len({s["replay_key"] for s in hard}) == 1
    assert len({s["replay_key"] for s in near}) > 1
    assert {(s["asn"], s["country"], s["ua_family"]) for s in near} == {(s["asn"], s["country"], s["ua_family"]) for s in ben}
    assert abs(sum(int(s["max_tokens"]) for s in near) / len(near) - sum(int(s["max_tokens"]) for s in ben) / len(ben)) <= 2
