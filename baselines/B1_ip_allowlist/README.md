# B1_ip_allowlist

IP-allowlist baseline.

- Reads CIDR allowlist from `config.yaml`.
- Uses `X-Forwarded-For` for allow/deny decision.
- Denies out-of-allowlist traffic with `403`, `reason=ip_not_allowed`, `usage_total_tokens=0`.
