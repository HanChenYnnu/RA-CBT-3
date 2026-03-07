import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from scripts.run_all import bootstrap_non_deny
import numpy as np


def test_bootstrap_deterministic():
    y = np.array([1, 0, 1, 0, 1, 0, 1, 0, 0, 1])
    s = np.array([0.9, 0.1, 0.8, 0.2, 0.7, 0.3, 0.6, 0.4, 0.5, 0.95])
    a = bootstrap_non_deny(y, s, seed=42)
    b = bootstrap_non_deny(y, s, seed=42)
    assert a['p_at_10']['mean'] == b['p_at_10']['mean']
