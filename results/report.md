# 1. Frozen Multi-Seed Protocol
- The evaluation stack is unchanged from the prior VALID APPLES-TO-APPLES frozen protocol, except that seed count is expanded.
- Baseline method: **B2**. Current method: **B4**.
- Exact shared seed set used for both methods: **[7, 11, 19, 23, 31]**.
- Frozen components unchanged: metric code, slice definitions, operating point, non-deny definition, served-traffic filtering, mixed-load construction, aggregation logic, and report-generation logic.

# 2. Multi-Seed Apples-to-Apples Results
## S4 PR-AUC
- per-seed B2 values: 0.5216, 0.5193, 0.5117, 0.5162, 0.5180
- per-seed B4 values: 0.9642, 0.9574, 0.9574, 0.9539, 0.9630
- mean ± std (B2): 0.5174 ± 0.0037
- mean ± std (B4): 0.9592 ± 0.0043
- delta mean (B4 - B2): 0.4418
- interval summary (delta 95% normal-approx CI): [0.4385, 0.4451]
- direction consistency across seeds: 5/5

## S4 Lift@100
- per-seed B2 values: 1.1800, 1.1000, 0.9800, 1.0800, 1.1600
- per-seed B4 values: 2.7202, 2.5823, 2.5496, 2.6968, 2.6520
- mean ± std (B2): 1.1000 ± 0.0787
- mean ± std (B4): 2.6402 ± 0.0730
- delta mean (B4 - B2): 1.5402
- interval summary (delta 95% normal-approx CI): [1.4914, 1.5890]
- direction consistency across seeds: 5/5

## scale=1.00 SR_benign
- per-seed B2 values: 0.1733, 0.1733, 0.1733, 0.1733, 0.1733
- per-seed B4 values: 0.2100, 0.2200, 0.1900, 0.2067, 0.2133
- mean ± std (B2): 0.1733 ± 0.0000
- mean ± std (B4): 0.2080 ± 0.0112
- delta mean (B4 - B2): 0.0347
- interval summary (delta 95% normal-approx CI): [0.0249, 0.0445]
- direction consistency across seeds: 5/5

## scale=1.00 ASR_non_deny_attack
- per-seed B2 values: 0.2267, 0.2267, 0.2267, 0.2267, 0.2267
- per-seed B4 values: 0.1900, 0.1800, 0.2100, 0.1933, 0.1867
- mean ± std (B2): 0.2267 ± 0.0000
- mean ± std (B4): 0.1920 ± 0.0112
- delta mean (B4 - B2): -0.0347
- interval summary (delta 95% normal-approx CI): [-0.0445, -0.0249]
- direction consistency across seeds: 5/5

# 3. Robustness Verification
- metric code: unchanged.
- slice definitions: unchanged.
- operating point: unchanged.
- non-deny definition: unchanged.
- served-traffic filtering: unchanged.
- mixed-load construction: unchanged.
- aggregation logic: unchanged.
- report-generation logic: unchanged.

# 4. Final Verdict
VALID APPLES-TO-APPLES (multi-seed confirmed)

# 5. Residual Risks
- Future stack/code changes would require a fresh frozen rerun before carrying this verdict forward.

**Does the current VALID APPLES-TO-APPLES conclusion remain stable under multi-seed frozen rerun?** Yes on aggregate, with the caveats above.
