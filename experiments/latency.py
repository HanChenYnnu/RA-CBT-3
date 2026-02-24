"""Deterministic latency helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
import time


def deterministic_reject_work(*, request_id: str, payload_hint: int) -> None:
    seed = os.environ.get("EXPERIMENT_SEED", "0")
    rounds = 2 + (int(hashlib.sha256(f"{seed}:{request_id}:{payload_hint}".encode()).hexdigest()[:2], 16) % 5)
    acc = f"{seed}:{request_id}:{payload_hint}".encode()
    for i in range(rounds):
        acc = hmac.new(f"k{i}".encode(), acc, hashlib.sha256).digest()
    _ = acc[0]


def latency_ms_with_jitter(*, started: float, request_id: str, decision: str = "allow") -> float:
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    seed = os.environ.get("EXPERIMENT_SEED", "0")
    base_bucket = int(hashlib.sha256(f"{seed}:{request_id}".encode()).hexdigest()[:6], 16) % 17
    jitter_ms = base_bucket * 0.045
    if decision in {"deny", "throttle"}:
        rej_bucket = int(hashlib.sha256(f"rej:{seed}:{request_id}".encode()).hexdigest()[:6], 16) % 15
        seed_bias = (int(hashlib.sha256(seed.encode()).hexdigest()[:2], 16) % 9) * 0.18
        jitter_ms += 0.1 + rej_bucket * 0.11 + seed_bias
        if request_id.startswith("S3"):
            jitter_ms += 0.35
    return elapsed_ms + jitter_ms
