"""Small deterministic smoke run."""

from __future__ import annotations

from experiments.expected_deltas import assert_required_deltas
from experiments.runner import synthetic_rows


def main() -> None:
    rows = synthetic_rows()
    assert_required_deltas(rows)
    print(f"[smoke_run] validated {len(rows)} synthetic rows and hard deltas")


if __name__ == "__main__":
    main()
