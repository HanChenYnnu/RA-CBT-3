# RA-CBT-3

Deterministic scaffold for baseline security experiments.

## One-command execution

Run from repository root:

```bash
python -m scripts.run_all
```

This generates:
- `results/report.csv`
- `results/report.md`
- `results/plots/*.svg`

## Developer commands

```bash
make setup
make lint
make test
make smoke
make all
```
