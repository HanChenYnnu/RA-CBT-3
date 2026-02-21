"""Metrics helpers for stage0 tests."""

from __future__ import annotations


def attack_success_rate(success_ok: int, total: int) -> float:
    return 0.0 if total == 0 else success_ok / total
