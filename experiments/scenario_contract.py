"""Scenario capability contract and preflight validation."""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class ScenarioCapabilities:
    has_user_key: bool
    has_access_token: bool
    has_dpop_private_key: bool
    can_exchange_token: bool
    replay_mode: str
    replay_key_fields: tuple[str, ...]
    ctx_similarity: str
    label: str
    paired_control: str | None


PAIRED_CONTROLS = {
    "S1_key_leak_hard": "S1_benign_control_hard",
    "S2_token_leak_hard": "S2_benign_control_hard",
    "S3_replay_hard": "S3_benign_control_hard",
    "S3_replay_nearmiss_hard": "S3_benign_control_hard",
}


SCENARIO_CAPABILITIES: dict[str, ScenarioCapabilities] = {
    "S1_key_leak": ScenarioCapabilities(True, True, True, True, "none", tuple(), "easy", "attack", None),
    "S1_key_leak_hard": ScenarioCapabilities(True, True, True, True, "none", tuple(), "hard", "attack", "S1_benign_control_hard"),
    "S1_benign_control_hard": ScenarioCapabilities(True, True, True, True, "none", tuple(), "hard", "benign", None),
    "S2_token_leak": ScenarioCapabilities(False, True, False, False, "none", tuple(), "easy", "attack", None),
    "S2_token_leak_hard": ScenarioCapabilities(False, True, False, False, "none", tuple(), "hard", "attack", "S2_benign_control_hard"),
    "S2_benign_control_hard": ScenarioCapabilities(True, True, True, True, "none", tuple(), "hard", "benign", None),
    "S2a_token_leak_missing_dpop": ScenarioCapabilities(False, True, False, False, "none", tuple(), "easy", "attack", None),
    "S2b_token_leak_wrong_key_dpop": ScenarioCapabilities(False, True, False, False, "none", tuple(), "easy", "attack", None),
    "S3_replay": ScenarioCapabilities(False, True, True, False, "exact_replay", ("jti", "ath", "signature"), "easy", "attack", None),
    "S3_replay_hard": ScenarioCapabilities(False, True, True, False, "timing_replay", ("jti", "ath", "signature"), "hard", "attack", "S3_benign_control_hard"),
    "S3_replay_nearmiss_hard": ScenarioCapabilities(False, True, True, False, "near_miss_replay", ("ath", "signature"), "hard", "attack", "S3_benign_control_hard"),
    "S3_benign_control_hard": ScenarioCapabilities(True, True, True, True, "none", tuple(), "hard", "benign", None),
}

DEFAULT_BENIGN = ScenarioCapabilities(True, True, True, True, "none", tuple(), "easy", "benign", None)


def get_capabilities(scenario: str) -> ScenarioCapabilities:
    return SCENARIO_CAPABILITIES.get(scenario, DEFAULT_BENIGN)


def scenario_manifest(*, scenario: str, baseline: str, seed: int, n: int) -> dict[str, object]:
    caps = get_capabilities(scenario)
    manifest = {"scenario": scenario, "baseline": baseline, "seed": seed, "n": n, **asdict(caps)}
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: dict[str, object]) -> None:
    if not manifest["has_user_key"] and manifest["can_exchange_token"]:
        raise ValueError("Manifest invariant failed: cannot exchange token without user_key.")
    if manifest["replay_mode"] not in {"none", "exact_replay", "timing_replay", "near_miss_replay"}:
        raise ValueError("Manifest invariant failed: invalid replay_mode.")
    if manifest["ctx_similarity"] not in {"easy", "hard"}:
        raise ValueError("Manifest invariant failed: invalid ctx_similarity.")
    if manifest["label"] not in {"attack", "benign"}:
        raise ValueError("Manifest invariant failed: invalid label.")


def validate_request_semantics(*, scenario: str, auth_present: bool, dpop_present: bool, dpop_valid: bool, exchange_called: bool) -> None:
    caps = get_capabilities(scenario)
    if caps.has_access_token and not auth_present:
        raise AssertionError(f"Scenario {scenario} expected Authorization header.")
    if not caps.can_exchange_token and exchange_called:
        raise AssertionError(f"Scenario {scenario} must not use exchange path.")
    if not caps.has_dpop_private_key and dpop_valid:
        raise AssertionError(f"Scenario {scenario} must not include valid DPoP.")
    if not caps.has_dpop_private_key and dpop_present and scenario.endswith("_hard"):
        raise AssertionError(f"Scenario {scenario} must not include DPoP when private key is absent.")
