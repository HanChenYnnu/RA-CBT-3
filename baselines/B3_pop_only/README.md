# B3_pop_only

DPoP proof-of-possession baseline.

- `/auth/exchange` binds `cnf.jkt` from `client_jwk`.
- `/v1/chat/completions` requires valid DPoP and enforces replay/jkt/ath checks.
- Uses budget precharge/refund and contract logs.
