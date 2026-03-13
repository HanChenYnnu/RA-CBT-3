from experiments.metrics import compute_b4_vs_b2_served_deltas
from experiments.types import EventRow


def _evt(baseline: str, scenario: str, label: str, score: float, seed: int) -> EventRow:
    return EventRow(baseline, scenario, 200, "ok", "throttle" if score > 0.6 else "allow", 10.0, 10, label == "benign", score if baseline == "B4" else -1.0, seed, label)


def test_b4_ci_superiority_smoke() -> None:
    groups = {
        "S1_pair": ["S1_restricted_issuance_hard", "S1_benign_control_hard"],
        "S2_pair": ["S2_delegated_misuse_hard", "S2_benign_control_hard"],
        "S3_pair": ["S3_replay_nearmiss_hard", "S3_replay_blended_hard", "S3_benign_control_hard"],
    }
    events: list[EventRow] = []
    for seed in [7, 8]:
        for i in range(120):
            events.append(_evt("B4", "S1_restricted_issuance_hard", "attack", 0.86 - (i % 30) * 0.005, seed))
            events.append(_evt("B4", "S1_benign_control_hard", "benign", 0.40 + (i % 30) * 0.004, seed))
            events.append(_evt("B4", "S2_delegated_misuse_hard", "attack", 0.83 - (i % 30) * 0.005, seed))
            events.append(_evt("B4", "S2_benign_control_hard", "benign", 0.41 + (i % 30) * 0.004, seed))
            events.append(_evt("B4", "S3_replay_nearmiss_hard", "attack", 0.82 - (i % 30) * 0.005, seed))
            events.append(_evt("B4", "S3_benign_control_hard", "benign", 0.39 + (i % 30) * 0.004, seed))

            events.append(_evt("B2", "S1_restricted_issuance_hard", "attack", 0.56 - (i % 30) * 0.001, seed))
            events.append(_evt("B2", "S1_benign_control_hard", "benign", 0.50 + (i % 30) * 0.001, seed))
            events.append(_evt("B2", "S2_delegated_misuse_hard", "attack", 0.55 - (i % 30) * 0.001, seed))
            events.append(_evt("B2", "S2_benign_control_hard", "benign", 0.50 + (i % 30) * 0.001, seed))
            events.append(_evt("B2", "S3_replay_nearmiss_hard", "attack", 0.55 - (i % 30) * 0.001, seed))
            events.append(_evt("B2", "S3_benign_control_hard", "benign", 0.50 + (i % 30) * 0.001, seed))

    deltas = compute_b4_vs_b2_served_deltas(events, groups=groups, bootstrap_n=120)
    lift_pos = sum(1 for d in deltas if d.slice_name in {"S1_pair", "S2_pair", "S3_pair"} and d.delta_lift_at_30_ci_low is not None and d.delta_lift_at_30_ci_low > 0)
    pr_pos = sum(1 for d in deltas if d.slice_name in {"S1_pair", "S2_pair", "S3_pair"} and d.delta_pr_auc_ci_low is not None and d.delta_pr_auc_ci_low > 0)
    assert lift_pos >= 2
    assert pr_pos >= 1
