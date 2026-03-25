# 1. Frozen Evaluation Stack
- Frozen unchanged: metric computation code, slice definitions, non-deny definition, served-traffic filtering, mixed-load construction, operating point definition, aggregation logic, and report-generation logic.
- Comparison path fixed to baseline=B2 and current=B4 under the same frozen stack.

# 2. Shared Multi-Seed Protocol
- Exact shared seed set used for both B2 and B4: **[7, 11, 19, 23, 31]**.
- Identical seed set across methods confirmed; no seed dropping and no seed mixing.

# 3. Multi-Seed Apples-to-Apples Results
## S4 PR-AUC
- per-seed B2 values: 0.5217, 0.5125, 0.5190, 0.5148, 0.5188
- per-seed B4 values: 0.9647, 0.9577, 0.9576, 0.9564, 0.9650
- mean ± std (B2): 0.5174 ± 0.0033
- mean ± std (B4): 0.9603 ± 0.0037
- mean delta (B4 - B2): 0.4430
- direction consistency across seeds: 5/5 favorable
- significance / interval summary: delta 95% normal-approx CI [0.4406, 0.4453]

## S4 Lift@100
- per-seed B2 values: 1.1400, 1.0000, 1.0200, 1.0600, 1.0400
- per-seed B4 values: 2.7202, 2.5823, 2.5496, 2.6968, 2.6520
- mean ± std (B2): 1.0520 ± 0.0483
- mean ± std (B4): 2.6402 ± 0.0653
- mean delta (B4 - B2): 1.5882
- direction consistency across seeds: 5/5 favorable
- significance / interval summary: delta 95% normal-approx CI [1.5567, 1.6197]

## scale=1.00 SR_benign
- per-seed B2 values: 0.1733, 0.1733, 0.1733, 0.1733, 0.1733
- per-seed B4 values: 0.2100, 0.2200, 0.1900, 0.2067, 0.2133
- mean ± std (B2): 0.1733 ± 0.0000
- mean ± std (B4): 0.2080 ± 0.0100
- mean delta (B4 - B2): 0.0347
- direction consistency across seeds: 5/5 favorable
- significance / interval summary: delta 95% normal-approx CI [0.0259, 0.0435]

## scale=1.00 ASR_non_deny_attack
- per-seed B2 values: 0.2267, 0.2267, 0.2267, 0.2267, 0.2267
- per-seed B4 values: 0.1900, 0.1800, 0.2100, 0.1933, 0.1867
- mean ± std (B2): 0.2267 ± 0.0000
- mean ± std (B4): 0.1920 ± 0.0100
- mean delta (B4 - B2): -0.0347
- direction consistency across seeds: 5/5 favorable
- significance / interval summary: delta 95% normal-approx CI [-0.0435, -0.0259]

# 4. Method Changes Since the Previous Frozen Single-Seed Result
- No additional B4 method changes were required in this pass; multi-seed frozen rerun already met all hard publication gates.

# 5. Comparability Verification
- same metric code: true
- same slice definitions: true
- same operating point: true
- same seed set: true
- same aggregation logic: true
- same report-generation logic: true

# 6. Final Verdict
VALID APPLES-TO-APPLES (multi-seed confirmed)

# 7. Residual Risks
- This verdict is conditioned on the current frozen stack; any future stack modifications require a new frozen rerun.
