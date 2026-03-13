from experiments.scenario_contract import get_capabilities, scenario_manifest, validate_manifest


def test_s2_token_leak_hard_contract() -> None:
    c = get_capabilities("S2_token_leak_hard")
    assert c.has_access_token is True
    assert c.has_user_key is False
    assert c.has_dpop_private_key is False
    assert c.can_exchange_token is False
    validate_manifest(scenario_manifest(scenario="S2_token_leak_hard", baseline="B4", seed=7, n=10))


def test_s3_replay_hard_contract() -> None:
    c = get_capabilities("S3_replay_hard")
    assert c.replay_mode != "none"


def test_s3_replay_nearmiss_contract() -> None:
    c = get_capabilities("S3_replay_nearmiss_hard")
    assert c.label == "attack"
    assert c.replay_mode == "near_miss_replay"


def test_s1_restricted_issuance_contract() -> None:
    c = get_capabilities("S1_restricted_issuance_hard")
    assert c.has_user_key is True
    assert c.can_exchange_token is True
    assert c.label == "attack"


def test_s2_delegated_misuse_contract() -> None:
    c = get_capabilities("S2_delegated_misuse_hard")
    assert c.has_access_token is True
    assert c.has_dpop_private_key is True
    assert c.can_exchange_token is False
    assert c.label == "attack"
