import json
from pathlib import Path

from experiments.budget_sweep import _run_mixedload_for_scale


def test_shared_contention_uses_single_sweep_log(tmp_path: Path) -> None:
    events = _run_mixedload_for_scale(out_dir=tmp_path, seed=7, scale=0.25)
    assert events
    assert any(e.label == "attack" for e in events)
    assert any(e.label == "benign" for e in events)
    log_path = tmp_path / "raw" / "seed7_B4_S4_mixedload_sweep_x0.25.jsonl"
    rows = [json.loads(x) for x in log_path.read_text(encoding="utf-8").splitlines()]
    assert {r["scenario"] for r in rows if r["scenario"].endswith("benign_control_hard")}
    assert {r["scenario"] for r in rows if r["scenario"] in {"S1_restricted_issuance_hard", "S2_delegated_misuse_hard", "S3_replay_nearmiss_hard", "S3_replay_blended_hard"}}
