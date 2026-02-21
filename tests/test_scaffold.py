import json
import os
from pathlib import Path

from baselines.B0_static.app import REQUIRED_LOG_KEYS
from baselines.B0_static.app import create_app as create_b0_app
from baselines.B2_bearer_short.app import create_app as create_b2_app
from baselines.B3_pop_only.app import create_app as create_b3_app
from baselines.B3_pop_only.app import jwk_thumbprint, make_dpop_proof
from baselines.B4_full.calibrate_quantiles import calibrate
from experiments.metrics import compute_metrics
from experiments.runner import run_b4_calibration_phase, run_selected
from fastapi.testclient import TestClient


def test_b0_contract_log_keys_and_types(tmp_path: Path) -> None:
    log_path = tmp_path / "b0.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    app = create_b0_app()
    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={
                "scenario": "S4_burst",
                "request_id": "req-1",
                "messages": [{"role": "user", "content": "hello world"}],
                "max_tokens": 40,
            },
            headers={"X-Forwarded-For": "10.0.0.10"},
        )
    assert response.status_code == 200
    record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    assert set(record.keys()) == REQUIRED_LOG_KEYS


def test_b2_exchange_call_missing_invalid_and_budget(tmp_path: Path) -> None:
    log_path = tmp_path / "b2.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    os.environ["B2_RPM_LIMIT"] = "2"
    os.environ["B2_TPM_LIMIT"] = "50"
    app = create_b2_app()

    with TestClient(app) as client:
        assert (
            client.post(
                "/v1/chat/completions", json={"scenario": "S2_token_leak", "messages": []}
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/v1/chat/completions",
                json={"scenario": "S2_token_leak", "messages": []},
                headers={"Authorization": "Bearer invalid.token"},
            ).status_code
            == 401
        )

        token = client.post(
            "/auth/exchange",
            json={},
            headers={"Authorization": "Bearer user-key"},
        ).json()["access_token"]
        assert (
            client.post(
                "/v1/chat/completions",
                json={
                    "scenario": "S2_token_leak",
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": 20,
                },
                headers={"Authorization": f"Bearer {token}"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/v1/chat/completions",
                json={
                    "scenario": "S2_token_leak",
                    "messages": [{"role": "user", "content": "hello"}],
                    "max_tokens": 45,
                },
                headers={"Authorization": f"Bearer {token}"},
            ).status_code
            == 429
        )


def test_b3_dpop_missing_jkt_ath_replay(tmp_path: Path) -> None:
    log_path = tmp_path / "b3.jsonl"
    os.environ["LOG_PATH"] = str(log_path)
    app = create_b3_app()

    with TestClient(app) as client:
        token = client.post(
            "/auth/exchange",
            json={"client_jwk": "legit-pub"},
            headers={"Authorization": "Bearer user-key"},
        ).json()["access_token"]
        jkt = jwk_thumbprint("legit-pub")
        assert (
            client.post(
                "/v1/chat/completions",
                json={"scenario": "S2_token_leak", "messages": [{"role": "user", "content": "a"}]},
                headers={"Authorization": f"Bearer {token}"},
            ).status_code
            == 401
        )

        wrong = json.loads(
            make_dpop_proof(
                "wrong-private", "POST", "/v1/chat/completions", token, "j1", "wrong-jkt"
            )
        )
        wrong["private_key_hint"] = "wrong-private"
        assert (
            client.post(
                "/v1/chat/completions",
                json={"scenario": "S2_token_leak", "messages": [{"role": "user", "content": "b"}]},
                headers={"Authorization": f"Bearer {token}", "DPoP": json.dumps(wrong)},
            ).status_code
            == 401
        )

        ath_bad = json.loads(
            make_dpop_proof("legit-private", "POST", "/v1/chat/completions", token, "j2", jkt)
        )
        ath_bad["private_key_hint"] = "legit-private"
        ath_bad["ath"] = "tampered-ath"
        ath_bad["signature"] = "sig-mismatch"
        assert (
            client.post(
                "/v1/chat/completions",
                json={"scenario": "S2_token_leak", "messages": [{"role": "user", "content": "c"}]},
                headers={"Authorization": f"Bearer {token}", "DPoP": json.dumps(ath_bad)},
            ).status_code
            == 401
        )

        first = json.loads(
            make_dpop_proof(
                "legit-private", "POST", "/v1/chat/completions", token, "replay-jti", jkt
            )
        )
        first["private_key_hint"] = "legit-private"
        assert (
            client.post(
                "/v1/chat/completions",
                json={"scenario": "S3_replay", "messages": [{"role": "user", "content": "d"}]},
                headers={"Authorization": f"Bearer {token}", "DPoP": json.dumps(first)},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/v1/chat/completions",
                json={"scenario": "S3_replay", "messages": [{"role": "user", "content": "e"}]},
                headers={"Authorization": f"Bearer {token}", "DPoP": json.dumps(first)},
            ).status_code
            == 401
        )


def test_hard_deltas_b2_b3_b4_and_b0(tmp_path: Path) -> None:
    os.environ["B2_RPM_LIMIT"] = "500"
    os.environ["B2_TPM_LIMIT"] = "50000"
    os.environ["B3_RPM_LIMIT"] = "500"
    os.environ["B3_TPM_LIMIT"] = "50000"
    os.environ["B4_RPM_LIMIT"] = "500"
    os.environ["B4_TPM_LIMIT"] = "50000"

    run_b4_calibration_phase(out_dir=tmp_path, n=120)
    calibrate(
        input_path=tmp_path / "raw" / "B4_calibration.jsonl",
        output_path=Path("baselines/B4_full/calibration.json"),
    )

    events = run_selected(
        baselines=["B0", "B2", "B3", "B4"],
        scenarios=["S2_token_leak", "S3_replay", "S4_burst"],
        out_dir=tmp_path,
    )
    rows = compute_metrics(events)

    def pick(baseline: str, scenario: str):
        return next(r for r in rows if r.baseline == baseline and r.scenario == scenario)

    assert pick("B2", "S2_token_leak").attack_success_rate >= 0.5
    assert pick("B3", "S2_token_leak").attack_success_rate <= 0.05
    assert pick("B4", "S2_token_leak").attack_success_rate <= 0.05

    assert pick("B3", "S3_replay").attack_success_rate < pick("B2", "S3_replay").attack_success_rate
    assert pick("B4", "S3_replay").attack_success_rate < pick("B2", "S3_replay").attack_success_rate

    assert (
        pick("B4", "S4_burst").cost_leakage_tokens <= pick("B0", "S4_burst").cost_leakage_tokens / 5
    )


def test_coverage_gate_detects_missing_combo() -> None:
    from experiments.runner import ensure_coverage

    class Row:
        def __init__(self, baseline: str, scenario: str):
            self.baseline = baseline
            self.scenario = scenario

    rows = [Row("B0", "S1_key_leak")]
    try:
        ensure_coverage(rows, ["B0", "B1"], ["S1_key_leak"])
    except RuntimeError as exc:
        assert "B1/S1_key_leak" in str(exc)
    else:
        raise AssertionError("coverage gate should fail for missing baseline/scenario")


def test_latency_and_drift_and_burst_behaviors(tmp_path: Path) -> None:
    from experiments.runner import ensure_coverage

    os.environ["B2_RPM_LIMIT"] = "1000"
    os.environ["B2_TPM_LIMIT"] = "80000"
    os.environ["B3_RPM_LIMIT"] = "1000"
    os.environ["B3_TPM_LIMIT"] = "80000"
    os.environ["B4_RPM_LIMIT"] = "1000"
    os.environ["B4_TPM_LIMIT"] = "80000"

    run_b4_calibration_phase(out_dir=tmp_path, n=120)
    calibrate(
        input_path=tmp_path / "raw" / "B4_calibration.jsonl",
        output_path=Path("baselines/B4_full/calibration.json"),
    )

    scenarios = ["S4_burst", "S5_slowdrip", "S6_drift", "S2_token_leak", "S3_replay"]
    baselines = ["B0", "B1", "B2", "B3", "B4"]
    events = run_selected(baselines=baselines, scenarios=scenarios, out_dir=tmp_path)
    rows = compute_metrics(events)
    ensure_coverage(rows, baselines, scenarios)

    def pick(baseline: str, scenario: str):
        return next(r for r in rows if r.baseline == baseline and r.scenario == scenario)

    # latency should be measured and non-constant across scenario shapes
    assert pick("B0", "S4_burst").p95_ms != pick("B0", "S5_slowdrip").p95_ms

    # drift behavior
    assert pick("B1", "S6_drift").false_reject_rate > 0.0
    assert pick("B4", "S6_drift").throttle_rate > 0.0
    assert pick("B4", "S6_drift").false_reject_rate < 0.20

    # burst throttle-first: not deny-all, still leakage-controlled
    assert pick("B4", "S4_burst").attack_success_rate > 0.0
    assert pick("B4", "S4_burst").cost_leakage_tokens <= pick("B0", "S4_burst").cost_leakage_tokens / 5
