# B4_full

Full baseline with PoP + context tolerance + calibrated risk + adaptive budgets.

- `/auth/exchange`: binds `cnf.jkt` and context hash.
- `/v1/chat/completions`: validates DPoP (including replay/jkt/ath), context tolerance, calibrated risk thresholds, and adaptive throttling.
- `calibrate_quantiles.py`: computes `tau_allow` / `tau_deny` from benign B4 logs.
