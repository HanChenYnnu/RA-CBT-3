# Baseline API Contract (Strict)

Each baseline (B0..B4) MUST expose:

1. `POST /v1/chat/completions` (OpenAI-compatible JSON)
2. Optional `POST /auth/exchange` endpoint (baseline-dependent)

Each request MUST append exactly one JSONL line to `LOG_PATH` with:

- `ts_ms`, `baseline`, `scenario`, `request_id`
- `status_code`
- `decision`: `allow|throttle|deny`
- `reason`: `ok`, `dpop_missing`, `jkt_mismatch`, `ath_mismatch`, `replay`, `token_missing`, `token_invalid`,
  `ctx_mismatch`, `ip_not_allowed`, `budget`, `risk_deny`, `upstream_error`
- `latency_ms` (real measurement)
- `precharge_tokens` (int)
- `usage_total_tokens` (int; `0` if upstream not reached)
- `budget_before`, `budget_after` (int; `-1` if N/A)
- `risk` (float; `-1.0` if N/A)

## Deterministic mock upstream

Baselines and harness MUST use a deterministic, network-free mock upstream.
The mock response is OpenAI-like and `usage.total_tokens` MUST scale with prompt length and `max_tokens`.
