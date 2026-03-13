"""Fail-fast semantic preflight checks."""

from __future__ import annotations

import hashlib

from experiments.scenario_audit import read_samples
from experiments.scenario_contract import PAIRED_CONTROLS, get_capabilities, scenario_manifest, validate_manifest
from experiments.types import EventRow


HARD_SCENARIOS = ["S1_key_leak_hard", "S1_restricted_issuance_hard", "S2_token_leak_hard", "S2_delegated_misuse_hard", "S3_replay_hard", "S3_replay_nearmiss_hard"]


def validate_contracts_declared(*, baselines: list[str], scenarios: list[str], seed: int, n_by_scenario: dict[str, int]) -> None:
    for baseline in baselines:
        for scenario in scenarios:
            validate_manifest(scenario_manifest(scenario=scenario, baseline=baseline, seed=seed, n=n_by_scenario.get(scenario, 0)))


def _hash_replay_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def validate_request_samples(samples: list[dict[str, object]]) -> None:
    if not samples:
        raise RuntimeError("Preflight failed: no scenario samples captured.")

    for scenario in HARD_SCENARIOS:
        subset = [s for s in samples if s.get("scenario") == scenario and s.get("baseline") == "B4"]
        if not subset:
            raise RuntimeError(f"Preflight failed: missing B4 samples for {scenario}.")

        caps = get_capabilities(scenario)
        for s in subset:
            if caps.ctx_similarity == "hard" and (not s.get("asn") or not s.get("country") or not s.get("ua_family")):
                raise RuntimeError(f"Preflight failed: hard context fields missing for {scenario}.")

        if scenario == "S1_restricted_issuance_hard":
            if any(not bool(s.get("exchange_called")) for s in subset):
                raise RuntimeError("Preflight violation: S1_restricted_issuance_hard must use exchange path.")
            if any(not bool(s.get("dpop_valid")) for s in subset):
                raise RuntimeError("Preflight violation: S1_restricted_issuance_hard must use valid DPoP.")

        if scenario == "S2_delegated_misuse_hard":
            if any(bool(s.get("exchange_called")) for s in subset):
                raise RuntimeError("Preflight violation: S2_delegated_misuse_hard must not call /auth/exchange.")
            if any(not bool(s.get("dpop_valid")) for s in subset):
                raise RuntimeError("Preflight violation: S2_delegated_misuse_hard must use valid DPoP and not PoP bypass.")

        if scenario == "S2_token_leak_hard":
            if any(bool(s.get("exchange_called")) for s in subset):
                raise RuntimeError("Preflight violation: S2_token_leak_hard called /auth/exchange.")
            if any(bool(s.get("dpop_valid")) or bool(s.get("dpop_present")) for s in subset):
                raise RuntimeError("Preflight violation: S2_token_leak_hard includes DPoP despite no private key.")

        if scenario == "S3_replay_hard":
            keys = [str(s.get("replay_key", "")) for s in subset]
            hashed = [_hash_replay_key(k) for k in keys if k]
            if len(set(hashed)) != 1:
                raise RuntimeError("Preflight violation: S3_replay_hard did not reuse replay key tuple exactly.")
        if scenario == "S3_replay_nearmiss_hard":
            keys = [str(s.get("replay_key", "")) for s in subset]
            hashed = [_hash_replay_key(k) for k in keys if k]
            if len(set(hashed)) <= 1:
                raise RuntimeError("Preflight violation: S3_replay_nearmiss_hard reused exact replay key.")

    for attack, control in PAIRED_CONTROLS.items():
        atk = [s for s in samples if s.get("scenario") == attack and s.get("baseline") == "B4"]
        ctr = [s for s in samples if s.get("scenario") == control and s.get("baseline") == "B4"]
        if not atk or not ctr:
            raise RuntimeError(f"Preflight failed: missing paired samples for {attack}/{control}.")
        atk_set = {(s.get("asn"), s.get("country"), s.get("ua_family")) for s in atk}
        ctr_set = {(s.get("asn"), s.get("country"), s.get("ua_family")) for s in ctr}
        if atk_set != ctr_set:
            raise RuntimeError(f"Preflight failed: paired control distribution mismatch for {attack}/{control}.")


def validate_from_audit_file() -> None:
    validate_request_samples(read_samples())


def validate_served_traffic_preflight(events: list[EventRow]) -> None:
    pair_scenarios = {
        "S1_pair": {"S1_key_leak_hard", "S1_restricted_issuance_hard", "S1_benign_control_hard"},
        "S2_pair": {"S2_token_leak_hard", "S2_delegated_misuse_hard", "S2_benign_control_hard"},
        "S3_pair": {"S3_replay_hard", "S3_replay_nearmiss_hard", "S3_benign_control_hard"},
    }
    for name, scenarios in pair_scenarios.items():
        subset = [e for e in events if e.baseline == "B4" and e.scenario in scenarios and e.decision in {"allow", "throttle"}]
        n_attack = sum(1 for e in subset if e.label == "attack")
        if n_attack < 30:
            raise RuntimeError(f"Preflight failed: {name} requires >=30 non-deny attacks for B4; got {n_attack}.")

    bad_risk = [e for e in events if e.baseline == "B4" and e.decision in {"allow", "throttle"} and e.risk < 0.0]
    if bad_risk:
        raise RuntimeError("Preflight failed: non-deny events include undefined risk (<0).")
