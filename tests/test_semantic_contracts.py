from experiments.preflight import validate_request_samples
from experiments.scenario_contract import get_capabilities


def test_hard_scenario_caps() -> None:
    s2 = get_capabilities("S2_token_leak_hard")
    assert s2.has_user_key is False and s2.has_access_token is True and s2.has_dpop_private_key is False


def test_validate_request_samples_semantics() -> None:
    samples = [
        {"scenario": "S2_token_leak_hard", "baseline": "B4", "exchange_called": False, "dpop_present": False, "dpop_valid": False, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": ""},
        {"scenario": "S3_replay_hard", "baseline": "B4", "exchange_called": False, "dpop_present": True, "dpop_valid": True, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": "fixed"},
        {"scenario": "S3_replay_hard", "baseline": "B4", "exchange_called": False, "dpop_present": True, "dpop_valid": True, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": "fixed"},
        {"scenario": "S3_replay_nearmiss_hard", "baseline": "B4", "exchange_called": False, "dpop_present": True, "dpop_valid": True, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": "near-1"},
        {"scenario": "S3_replay_nearmiss_hard", "baseline": "B4", "exchange_called": False, "dpop_present": True, "dpop_valid": True, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": "near-2"},
        {"scenario": "S1_key_leak_hard", "baseline": "B4", "exchange_called": True, "dpop_present": True, "dpop_valid": True, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": ""},
        {"scenario": "S1_benign_control_hard", "baseline": "B4", "exchange_called": True, "dpop_present": True, "dpop_valid": True, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": ""},
        {"scenario": "S2_benign_control_hard", "baseline": "B4", "exchange_called": True, "dpop_present": True, "dpop_valid": True, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": ""},
        {"scenario": "S3_benign_control_hard", "baseline": "B4", "exchange_called": True, "dpop_present": True, "dpop_valid": True, "asn": "AS100", "country": "US", "ua_family": "browser", "max_tokens": 16, "replay_key": ""},
    ]
    validate_request_samples(samples)
