"""Deterministic latency helpers."""

from __future__ import annotations

import hashlib
import time


def latency_ms_with_jitter(*, started: float, request_id: str) -> float:
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    jitter_bucket = int(hashlib.sha256(request_id.encode()).hexdigest()[:6], 16) % 7
    jitter_ms = jitter_bucket * 0.13
    return round(elapsed_ms + jitter_ms, 3)
