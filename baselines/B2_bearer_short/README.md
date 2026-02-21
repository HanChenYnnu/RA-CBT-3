# B2_bearer_short

Short-lived bearer token baseline with budget controls.

- `POST /auth/exchange` exchanges a user bearer key for short-lived `access_token` (no PoP binding).
- `POST /v1/chat/completions` requires bearer access token.
- Applies rpm/tpm budgets with precharge/refund and logs budget_before/budget_after.
