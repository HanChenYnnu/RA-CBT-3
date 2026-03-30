# Method Overview (Formalized Access Control)

This artifact defines a formalized context-aware access-control method for API-facing LLM services.

- Formal semantics: `docs/formal_semantics.md`.
- Formal propositions/proofs: `docs/proofs.md`.
- Implementation decision object: `baselines/B4_full/policy.py`.
- End-to-end enforcement and state transitions: `baselines/B4_full/app.py`.

Core control order is explicit and reusable: `allow < throttle < deny`.
Rule composition is severity-max with deny precedence.

Canonical reproducibility entrypoint remains:

```bash
python -m scripts.run_all --seed 7 --seeds 1
```
