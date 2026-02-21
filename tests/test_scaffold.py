from pathlib import Path

from experiments.metrics import compute_metrics
from experiments.mock_upstream import chat_completion
from experiments.plots import generate_plots
from experiments.runner import synthetic_events


def test_mock_usage_scales_with_prompt_length() -> None:
    short = chat_completion(
        model="gpt-mock",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=40,
        request_id="a",
    )
    long = chat_completion(
        model="gpt-mock",
        messages=[{"role": "user", "content": "hi " * 100}],
        max_tokens=40,
        request_id="b",
    )
    assert long["usage"]["total_tokens"] > short["usage"]["total_tokens"]


def test_mock_usage_scales_with_max_tokens() -> None:
    low = chat_completion(
        model="gpt-mock",
        messages=[{"role": "user", "content": "same prompt"}],
        max_tokens=20,
        request_id="c",
    )
    high = chat_completion(
        model="gpt-mock",
        messages=[{"role": "user", "content": "same prompt"}],
        max_tokens=200,
        request_id="d",
    )
    assert high["usage"]["total_tokens"] > low["usage"]["total_tokens"]


def test_cost_leakage_tokens_is_sum() -> None:
    rows = compute_metrics(synthetic_events())
    b0_s4 = next(row for row in rows if row.baseline == "B0" and row.scenario == "S4_burst")
    assert b0_s4.cost_leakage_tokens > 500


def test_plot_generation_writes_multiple_svg_files() -> None:
    rows = compute_metrics(synthetic_events()[:6])
    plot_paths = generate_plots(rows)
    assert len(plot_paths) >= 3
    for path in plot_paths:
        assert path.suffix == ".svg"
        assert path.exists()
        assert path.read_text(encoding="utf-8").startswith("<svg")
        assert Path(path).stat().st_size > 0
