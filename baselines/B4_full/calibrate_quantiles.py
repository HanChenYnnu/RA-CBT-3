"""Compute B4 risk thresholds from benign calibration logs."""

from __future__ import annotations

import json
from pathlib import Path

INPUT_PATH = Path("results/raw/B4_calibration.jsonl")
OUTPUT_PATH = Path("baselines/B4_full/calibration.json")


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((len(ordered) - 1) * q))
    return float(ordered[idx])


def calibrate(input_path: Path = INPUT_PATH, output_path: Path = OUTPUT_PATH) -> dict[str, float]:
    risks: list[float] = []
    if input_path.exists():
        for line in input_path.read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            rec = json.loads(line)
            risks.append(float(rec.get("risk", 0.0)))

    tau_allow = _quantile(risks, 0.80)
    tau_deny = max(tau_allow + 0.05, _quantile(risks, 0.98))
    out = {"tau_allow": round(tau_allow, 4), "tau_deny": round(min(0.99, tau_deny), 4)}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def main() -> None:
    out = calibrate()
    print(json.dumps(out))


if __name__ == "__main__":
    main()
