from scripts.run_all import LOSO_GROUPS


def test_s4_operating_point_frozen() -> None:
    assert "S4_mixedload_sweep_x1.00" in LOSO_GROUPS["S4_pair"]

