import json
from pathlib import Path

from experiments.budget_sweep import _run_mixedload_for_scale


def test_shared_contention_strict_single_log_and_token_pool(tmp_path: Path) -> None:
    _run_mixedload_for_scale(out_dir=tmp_path, seed=11, scale=0.35)
    log_path = tmp_path / "raw" / "seed11_B4_S4_mixedload_sweep_x0.35.jsonl"
    rows = [json.loads(x) for x in log_path.read_text(encoding="utf-8").splitlines()]
    assert rows
    scenarios = {r["scenario"] for r in rows}
    assert any(s.endswith("benign_control_hard") for s in scenarios)
    assert any(s in {"S1_restricted_issuance_hard", "S2_delegated_misuse_hard", "S3_replay_nearmiss_hard", "S3_replay_blended_hard"} for s in scenarios)

    # shared contention evidence: both classes are interleaved in one queue and draw from same budget state.
    benign = [r for r in rows if str(r["scenario"]).endswith("benign_control_hard")]
    attack = [r for r in rows if str(r["scenario"]) in {"S1_restricted_issuance_hard", "S2_delegated_misuse_hard", "S3_replay_nearmiss_hard", "S3_replay_blended_hard"}]
    assert benign and attack
    assert min(r["budget_before"] for r in benign) < max(r["budget_before"] for r in benign)
    assert min(r["budget_before"] for r in attack) < max(r["budget_before"] for r in attack)
    assert max(r["budget_before"] for r in benign) > min(r["budget_before"] for r in attack)
