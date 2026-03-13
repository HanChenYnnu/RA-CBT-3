from experiments.scenario_contract import validate_request_semantics


def test_s1_pair_attack_semantics_preserved() -> None:
    validate_request_semantics(
        scenario="S1_restricted_issuance_hard",
        auth_present=True,
        dpop_present=True,
        dpop_valid=True,
        exchange_called=True,
    )


def test_s2_pair_attack_semantics_preserved_no_pop_bypass() -> None:
    validate_request_semantics(
        scenario="S2_delegated_misuse_hard",
        auth_present=True,
        dpop_present=True,
        dpop_valid=True,
        exchange_called=False,
    )
