"""Debug sampling for scenario capability audits."""

from __future__ import annotations

import json
from pathlib import Path

_AUDIT_PATH = Path("results/debug/scenario_samples.jsonl")
_COUNTS: dict[tuple[str, str], int] = {}


def reset_audit() -> None:
    _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _AUDIT_PATH.write_text("", encoding="utf-8")
    _COUNTS.clear()


def record_sample(*, scenario: str, baseline: str, caps: dict[str, object], auth_present: bool, dpop_present: bool, dpop_valid: bool, exchange_called: bool, replay_key: str, asn: str = "", country: str = "", ua_family: str = "", max_tokens: int = 0) -> None:
    key = (scenario, baseline)
    n = _COUNTS.get(key, 0)
    if n >= 10:
        return
    _COUNTS[key] = n + 1
    record = {
        "scenario": scenario,
        "baseline": baseline,
        "caps": caps,
        "auth_present": auth_present,
        "dpop_present": dpop_present,
        "dpop_valid": dpop_valid,
        "exchange_called": exchange_called,
        "replay_key": replay_key,
        "asn": asn,
        "country": country,
        "ua_family": ua_family,
        "max_tokens": max_tokens,
    }
    _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def read_samples() -> list[dict[str, object]]:
    if not _AUDIT_PATH.exists():
        return []
    return [json.loads(line) for line in _AUDIT_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
