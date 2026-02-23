"""Deterministic network-free OpenAI-like mock upstream with realistic latency."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import time


@dataclass(frozen=True)
class MockUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


def _count_prompt_tokens(messages: list[dict[str, str]]) -> int:
    text = " ".join(message.get("content", "") for message in messages)
    return max(1, len(text) // 4)


def _sleep_ms(total_tokens: int, request_id: str) -> float:
    seed = os.environ.get("EXPERIMENT_SEED", "0")
    payload = f"{seed}:{request_id}:{total_tokens}".encode()
    jitter_unit = int(hashlib.sha256(payload).hexdigest()[:6], 16) % 7
    base_ms = 12.0
    per_token_ms = 0.08
    jitter_ms = float(jitter_unit) * 0.9
    sleep_ms = base_ms + (per_token_ms * total_tokens) + jitter_ms
    time.sleep(sleep_ms / 1000.0)
    return sleep_ms


def chat_completion(
    *,
    model: str,
    messages: list[dict[str, str]],
    max_tokens: int,
    request_id: str,
) -> dict[str, object]:
    prompt_tokens = _count_prompt_tokens(messages)
    completion_tokens = max(1, max_tokens // 2)
    usage = MockUsage(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )
    _sleep_ms(usage.total_tokens, request_id)
    joined = " ".join(message.get("content", "") for message in messages).strip()
    content = f"deterministic:{model}:{joined[:60]}"
    return {
        "id": f"chatcmpl-{request_id}",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
        },
    }
