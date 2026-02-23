"""Deterministic latency helpers."""

from __future__ import annotations

import hashlib
import os
import time


def deterministic_reject_work(*, request_id: str, payload_hint: int) -> None:
    seed = os.environ.get("EXPERIMENT_SEED", "0")
    rounds = 40 + (int(hashlib.sha256(f"{seed}:{request_id}:{payload_hint}".encode()).hexdigest()[:4], 16) % 140)
    data = f"{seed}:{request_id}:{payload_hint}".encode()
    acc = data
    for _ in range(rounds):
        acc = hashlib.sha256(acc).digest()
    _ = acc[0]


def latency_ms_with_jitter(*, started: float, request_id: str) -> float:
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    seed = os.environ.get("EXPERIMENT_SEED", "0")
    jitter_bucket = int(hashlib.sha256(f"{seed}:{request_id}".encode()).hexdigest()[:6], 16) % 11
    jitter_ms = jitter_bucket * 0.07
    return round(elapsed_ms + jitter_ms, 3)
