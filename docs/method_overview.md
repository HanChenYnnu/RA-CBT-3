# Method Overview (Formal Rule-System Access Control)

This artifact defines a formal context-aware access-control method with explicit judgment forms and rule composition.

- Formal semantics (judgments, inference rules, transition chain): `docs/formal_semantics.md`.
- Abstract proofs over rule system: `docs/proofs.md`.
- Implementation instantiation of action order/composition: `baselines/B4_full/policy.py`.
- Runtime instantiation of credential lifecycle and signals: `baselines/B4_full/app.py`.

Core algebra:
- action order `allow < throttle < deny`,
- composition operator = severity-max join,
- hard-violation dominance and no-downgrade under additional stronger rules,
- replay-history accumulation rules (`REPLAY-ACCUM`, `REPLAY-HARD`) so delayed credential reuse evidence cannot be neutralized by benign-looking context.

Canonical reproducibility entrypoint remains:

```bash
python -m scripts.run_all --seed 7 --seeds 5
```
