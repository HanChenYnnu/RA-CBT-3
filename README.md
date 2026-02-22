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


## Publishing and visibility

To regenerate and auto-commit result artifacts (CSV/MD/SVG only):

```bash
python -m scripts.run_all --publish-results true
```

Committed outputs are visible directly in the repository under `results/`, and workflow runs from `.github/workflows/run_all.yml` upload the same files as downloadable artifacts.
