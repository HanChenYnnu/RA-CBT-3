# B0_static

FastAPI static proxy baseline with no auth/PoP/budget controls.

- Endpoint: `POST /v1/chat/completions`
- Forwards directly to deterministic mock upstream.
- Emits per-request JSONL contract logs to `LOG_PATH`.
