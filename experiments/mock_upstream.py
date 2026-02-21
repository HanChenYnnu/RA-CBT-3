"""Deterministic network-free OpenAI-like mock upstream."""

from __future__ import annotations

from dataclasses import dataclass
import time


@dataclass(frozen=True)
class MockUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


def _count_prompt_tokens(messages: list[dict[str, str]]) -> int:
    text = " ".join(message.get("content", "") for message in messages)
    # Deterministic token approximation that scales with prompt length.
    return max(1, len(text) // 4)


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
    joined = " ".join(message.get("content", "") for message in messages).strip()
    # deterministic real latency jitter for percentile separation
    time.sleep(((prompt_tokens + max_tokens) % 4) * 0.0005)
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
