"""Compute B4 risk thresholds from benign and attack calibration logs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

BENIGN_INPUT_PATH = Path("results/raw/B4_calibration_benign.jsonl")
ATTACK_INPUT_PATH = Path("results/raw/B4_calibration_attack.jsonl")
OUTPUT_PATH = Path("baselines/B4_full/calibration.json")


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((len(ordered) - 1) * q))
    return ordered[idx]


def _read_risks(path: Path) -> list[float]:
    if not path.exists():
        return []
    out: list[float] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            rec = json.loads(line)
            out.append(float(rec.get("risk", 0.0)))
    return out


def calibrate(*, benign_path: Path, attack_path: Path, output_path: Path) -> dict[str, float]:
    benign = _read_risks(benign_path)
    attack = _read_risks(attack_path)
    tau_allow = _quantile(benign, 0.80) if benign else 0.20
    tau_deny = _quantile(attack, 0.55) if attack else 0.75
    tau_allow_exchange = _quantile(benign, 0.90) + 0.15 if benign else 0.35
    tau_deny_exchange = max(tau_allow_exchange + 0.12, tau_deny + 0.05)

    out = {
        "tau_allow": round(max(0.05, min(0.60, tau_allow)), 4),
        "tau_deny": round(max(0.35, min(0.95, tau_deny)), 4),
        "tau_allow_exchange": round(max(0.15, min(0.75, tau_allow_exchange)), 4),
        "tau_deny_exchange": round(max(0.35, min(0.98, tau_deny_exchange)), 4),
        "benign_risk_p50": round(_quantile(benign, 0.50), 4) if benign else 0.0,
        "attack_risk_p50": round(_quantile(attack, 0.50), 4) if attack else 0.0,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benign", type=Path, default=BENIGN_INPUT_PATH)
    parser.add_argument("--attack", type=Path, default=ATTACK_INPUT_PATH)
    parser.add_argument("--out", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()
    out = calibrate(benign_path=args.benign, attack_path=args.attack, output_path=args.out)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
