from experiments.metrics import compute_b4_vs_b2_served_deltas
from experiments.types import EventRow


def _evt(baseline: str, scenario: str, label: str, score: float, seed: int, idx: int) -> EventRow:
    decision = "throttle" if score > 0.55 else "allow"
    return EventRow(baseline, scenario, 200, "ok", decision, 15.0 + score * 4.0, 12 + int(score * 10), label == "benign", score if baseline == "B4" else -1.0, seed, label)


def test_b4_vs_b2_delta_ci_positive() -> None:
    groups = {
        "S1_pair": ["S1_restricted_issuance_hard", "S1_benign_control_hard"],
        "S2_pair": ["S2_delegated_misuse_hard", "S2_benign_control_hard"],
        "S3_pair": ["S3_replay_nearmiss_hard", "S3_replay_blended_hard", "S3_benign_control_hard"],
    }
    events: list[EventRow] = []
    for seed in [7, 8, 9]:
        for pair, scenarios in groups.items():
            attacks = [s for s in scenarios if "benign" not in s]
            benign = [s for s in scenarios if "benign" in s]
            for i in range(120):
                events.append(_evt("B4", attacks[i % len(attacks)], "attack", 0.75 - (i % 20) * 0.01, seed, i))
                events.append(_evt("B4", benign[0], "benign", 0.38 + (i % 20) * 0.01, seed, i))
                events.append(_evt("B2", attacks[i % len(attacks)], "attack", 0.56 - (i % 25) * 0.003, seed, i))
                events.append(_evt("B2", benign[0], "benign", 0.49 + (i % 25) * 0.003, seed, i))

    deltas = compute_b4_vs_b2_served_deltas(events, groups=groups, bootstrap_n=120)
    s1 = next(d for d in deltas if d.slice_name == "S1_pair")
    assert s1.delta_lift_at_30_ci_low is not None and s1.delta_lift_at_30_ci_low > 0
