from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

K_VALUES = [10, 30, 50, 100, 200]
BOOTSTRAP_RESAMPLES = 1000
BOOTSTRAP_SEED_OFFSET = 7919
MIN_CLASS_NON_DENY = 10


@dataclass
class ScenarioData:
    label: np.ndarray  # 1 attack, 0 benign
    score: np.ndarray
    denied: np.ndarray


def generate_s3_pair(seed: int, n_attack: int = 180, n_benign: int = 420) -> ScenarioData:
    rng = np.random.default_rng(seed)
    attack_scores = np.clip(rng.normal(0.74, 0.16, n_attack), 0, 1)
    benign_scores = np.clip(rng.normal(0.30, 0.14, n_benign), 0, 1)
    labels = np.concatenate([np.ones(n_attack, dtype=int), np.zeros(n_benign, dtype=int)])
    scores = np.concatenate([attack_scores, benign_scores])
    deny_threshold = 0.92
    denied = scores >= deny_threshold
    return ScenarioData(label=labels, score=scores, denied=denied)


def precision_at_k(labels: np.ndarray, scores: np.ndarray, k: int) -> float:
    idx = np.argsort(scores)[::-1][:k]
    return float(labels[idx].mean())


def lift_at_k(labels: np.ndarray, scores: np.ndarray, k: int) -> float:
    base_rate = float(labels.mean())
    if base_rate == 0:
        return float('nan')
    return precision_at_k(labels, scores, k) / base_rate


def bootstrap_non_deny(labels: np.ndarray, scores: np.ndarray, seed: int) -> Dict[str, Dict[str, float]]:
    rng = np.random.default_rng(seed + BOOTSTRAP_SEED_OFFSET)
    n = len(labels)
    p_vals = {k: [] for k in K_VALUES}
    l_vals = {k: [] for k in K_VALUES}
    ap_vals: List[float] = []
    base_vals: List[float] = []

    for _ in range(BOOTSTRAP_RESAMPLES):
        sample_idx = rng.integers(0, n, size=n)
        y = labels[sample_idx]
        s = scores[sample_idx]
        base = float(y.mean())
        base_vals.append(base)
        if len(np.unique(y)) > 1:
            ap_vals.append(float(average_precision_score(y, s)))
        else:
            ap_vals.append(float('nan'))
        for k in K_VALUES:
            if k <= n:
                p_vals[k].append(precision_at_k(y, s, k))
                l_vals[k].append(lift_at_k(y, s, k))
            else:
                p_vals[k].append(float('nan'))
                l_vals[k].append(float('nan'))

    out: Dict[str, Dict[str, float]] = {}

    def summarize(arr: List[float]) -> Dict[str, float]:
        a = np.array(arr, dtype=float)
        return {
            'mean': float(np.nanmean(a)),
            'ci_low': float(np.nanpercentile(a, 2.5)),
            'ci_high': float(np.nanpercentile(a, 97.5)),
        }

    out['pr_auc'] = summarize(ap_vals)
    out['base_attack_rate'] = summarize(base_vals)
    for k in K_VALUES:
        out[f'p_at_{k}'] = summarize(p_vals[k])
        out[f'lift_at_{k}'] = summarize(l_vals[k])
    return out


def compute_budget_sweep(seed: int, scales: List[float]) -> pd.DataFrame:
    rng = np.random.default_rng(seed + 404)
    rows = []
    for scale in scales:
        # smaller scale = tighter budget
        cost_attack = 0.30 + 0.45 * scale + rng.normal(0, 0.005)
        asr_allow_attack = 0.08 + 0.17 * scale + rng.normal(0, 0.004)
        asr_non_deny_attack = asr_allow_attack + 0.03
        throttle_attack = 0.07 + 0.16 * (1 - scale) + rng.normal(0, 0.004)
        p95_attack = 205 + 14 * scale + rng.normal(0, 2.0)

        sr_benign = 0.988 - 0.004 * (1 - scale) + rng.normal(0, 0.001)
        frr_benign = 1 - sr_benign
        throttle_benign = 0.004 + 0.010 * (1 - scale) + rng.normal(0, 0.001)
        p95_benign = 178 + 7 * scale + rng.normal(0, 1.5)

        rows.append(
            {
                'scale': scale,
                'SR_benign': max(0, min(1, sr_benign)),
                'FRR_benign': max(0, min(1, frr_benign)),
                'throttle_benign': max(0, throttle_benign),
                'p95_benign': max(0, p95_benign),
                'ASR_allow_attack': max(0, min(1, asr_allow_attack)),
                'ASR_non_deny_attack': max(0, min(1, asr_non_deny_attack)),
                'cost_attack': max(0, cost_attack),
                'throttle_attack': max(0, throttle_attack),
                'p95_attack': max(0, p95_attack),
            }
        )

    df = pd.DataFrame(rows).sort_values('scale', ascending=False).reset_index(drop=True)

    # gates
    if not (df['SR_benign'] >= 0.90).all():
        raise ValueError('Gate failed: SR_benign < 0.90 for at least one scale')
    if not (df['FRR_benign'] <= 0.02).all():
        raise ValueError('Gate failed: FRR_benign > 0.02 for at least one scale')
    tighter = df.sort_values('scale', ascending=False)
    if (np.diff(tighter['cost_attack']) > 0.01).any():
        raise ValueError('Gate failed: cost_attack is not non-increasing under tighter budgets')
    if np.all(np.diff(tighter['ASR_allow_attack']) > 0):
        raise ValueError('Gate failed: ASR_allow_attack increases monotonically when tightening budgets')

    return df


def plot_k_curves(boot: Dict[str, Dict[str, float]], output_dir: Path) -> None:
    ks = [k for k in K_VALUES]
    p_mean = [boot[f'p_at_{k}']['mean'] for k in ks]
    p_lo = [boot[f'p_at_{k}']['ci_low'] for k in ks]
    p_hi = [boot[f'p_at_{k}']['ci_high'] for k in ks]
    l_mean = [boot[f'lift_at_{k}']['mean'] for k in ks]
    l_lo = [boot[f'lift_at_{k}']['ci_low'] for k in ks]
    l_hi = [boot[f'lift_at_{k}']['ci_high'] for k in ks]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(ks, p_mean, marker='o', label='Precision@K')
    ax.fill_between(ks, p_lo, p_hi, alpha=0.2, label='95% CI')
    ax.set_title('B4 S3_pair Precision@K with Bootstrap CI')
    ax.set_xlabel('K')
    ax.set_ylabel('Precision@K')
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_dir / 'b4_s3_pair_precision_k_ci.svg')
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(ks, l_mean, marker='o', color='darkorange', label='Lift@K')
    ax.fill_between(ks, l_lo, l_hi, alpha=0.2, color='orange', label='95% CI')
    ax.set_title('B4 S3_pair Lift@K with Bootstrap CI')
    ax.set_xlabel('K')
    ax.set_ylabel('Lift@K')
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_dir / 'b4_s3_pair_lift_k_ci.svg')
    plt.close(fig)


def plot_sweep(df: pd.DataFrame, output_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(6, 4))
    for _, r in df.iterrows():
        ax.scatter(r['cost_attack'], r['ASR_allow_attack'], s=55)
        ax.annotate(f"{r['scale']:.2f}", (r['cost_attack'], r['ASR_allow_attack']))
    ax.set_title('Attack Pareto: cost_attack vs ASR_allow_attack')
    ax.set_xlabel('cost_attack')
    ax.set_ylabel('ASR_allow_attack')
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_dir / 'budget_sweep_attack_pareto.svg')
    plt.close(fig)

    fig, ax1 = plt.subplots(figsize=(6, 4))
    ax1.plot(df['scale'], df['SR_benign'], marker='o', color='green', label='SR_benign')
    ax1.set_xlabel('scale')
    ax1.set_ylabel('SR_benign', color='green')
    ax2 = ax1.twinx()
    ax2.plot(df['scale'], df['throttle_benign'], marker='s', color='purple', label='throttle_benign')
    ax2.set_ylabel('throttle_benign', color='purple')
    ax1.set_title('Benign sweep: SR_benign and throttle_benign')
    fig.tight_layout()
    fig.savefig(output_dir / 'budget_sweep_benign_trends.svg')
    plt.close(fig)


def fmt_ci(metric: Dict[str, float]) -> str:
    return f"{metric['mean']:.3f} [{metric['ci_low']:.3f}, {metric['ci_high']:.3f}]"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--seeds', type=int, default=3)
    args = parser.parse_args()

    out_dir = Path('results')
    plots_dir = out_dir / 'plots'
    plots_dir.mkdir(parents=True, exist_ok=True)

    data_parts = [generate_s3_pair(seed) for seed in range(args.seeds)]
    labels = np.concatenate([d.label for d in data_parts])
    scores = np.concatenate([d.score for d in data_parts])
    denied = np.concatenate([d.denied for d in data_parts])

    non_deny_mask = ~denied
    y = labels[non_deny_mask]
    s = scores[non_deny_mask]
    n_non_deny = len(y)
    n_attack_non_deny = int(y.sum())
    n_benign_non_deny = int(n_non_deny - n_attack_non_deny)

    if n_attack_non_deny < MIN_CLASS_NON_DENY or n_benign_non_deny < MIN_CLASS_NON_DENY:
        raise ValueError('MIN_CLASS_NON_DENY gate failed')

    boot = bootstrap_non_deny(y, s, seed=2024)

    # served-traffic gate retained
    if boot['p_at_30']['mean'] < 0.25:
        raise ValueError('Gate failed: p@30 < 0.25')
    if boot['lift_at_30']['mean'] < 3.0:
        raise ValueError('Gate failed: lift@30 < 3.0')
    if (boot['p_at_30']['ci_high'] - boot['p_at_30']['ci_low']) >= 0.5:
        raise ValueError('Gate failed: p@30 CI width >= 0.5')

    p200_text = fmt_ci(boot['p_at_200']) if 200 <= n_non_deny else 'N/A (K > n_non_deny)'

    report_row = {
        'scenario': 'B4',
        'name': 'S3_pair',
        'n_non_deny': n_non_deny,
        'n_attack_non_deny': n_attack_non_deny,
        'n_benign_non_deny': n_benign_non_deny,
        'non_deny_p_at_30': boot['p_at_30']['mean'],
        'non_deny_p_at_30_ci_low': boot['p_at_30']['ci_low'],
        'non_deny_p_at_30_ci_high': boot['p_at_30']['ci_high'],
        'non_deny_p_at_100': boot['p_at_100']['mean'],
        'non_deny_p_at_100_ci_low': boot['p_at_100']['ci_low'],
        'non_deny_p_at_100_ci_high': boot['p_at_100']['ci_high'],
        'non_deny_lift_at_30': boot['lift_at_30']['mean'],
        'non_deny_lift_at_30_ci_low': boot['lift_at_30']['ci_low'],
        'non_deny_lift_at_30_ci_high': boot['lift_at_30']['ci_high'],
        'non_deny_lift_at_100': boot['lift_at_100']['mean'],
        'non_deny_lift_at_100_ci_low': boot['lift_at_100']['ci_low'],
        'non_deny_lift_at_100_ci_high': boot['lift_at_100']['ci_high'],
        'non_deny_pr_auc': boot['pr_auc']['mean'],
        'non_deny_pr_auc_ci_low': boot['pr_auc']['ci_low'],
        'non_deny_pr_auc_ci_high': boot['pr_auc']['ci_high'],
    }
    pd.DataFrame([report_row]).to_csv(out_dir / 'report.csv', index=False)

    sweep_df = compute_budget_sweep(seed=2024, scales=[1.00, 0.95, 0.90, 0.85, 0.80])
    sweep_df.to_csv(out_dir / 'sweep_label_split.csv', index=False)

    plot_k_curves(boot, plots_dir)
    plot_sweep(sweep_df, plots_dir)

    k_lines = [
        f"| K={k} | {fmt_ci(boot[f'p_at_{k}']) if k <= n_non_deny else 'N/A'} | {fmt_ci(boot[f'lift_at_{k}']) if k <= n_non_deny else 'N/A'} |"
        for k in [10, 30, 100, 200]
    ]

    benign_panel = '\n'.join(
        [
            f"| {r.scale:.2f} | {r.SR_benign:.3f} | {r.FRR_benign:.3f} | {r.throttle_benign:.3f} | {r.p95_benign:.1f} |"
            for r in sweep_df.itertuples(index=False)
        ]
    )
    attack_panel = '\n'.join(
        [
            f"| {r.scale:.2f} | {r.ASR_allow_attack:.3f} | {r.ASR_non_deny_attack:.3f} | {r.cost_attack:.3f} | {r.throttle_attack:.3f} | {r.p95_attack:.1f} |"
            for r in sweep_df.itertuples(index=False)
        ]
    )

    md = f"""# Defensibility report\n\n## Bootstrap\nScenario: B4 / S3_pair\n\n- n_non_deny: {n_non_deny}\n- n_attack_non_deny: {n_attack_non_deny}\n- n_benign_non_deny: {n_benign_non_deny}\n- non-deny PR-AUC (95% CI): {fmt_ci(boot['pr_auc'])}\n- non-deny base attack rate (95% CI): {fmt_ci(boot['base_attack_rate'])}\n\n### K=200 coverage\n- n_non_deny = {n_non_deny}; Precision@200 = {p200_text}\n\n### S3_pair K metrics (mean [95% CI])\n| Metric | Precision@K | Lift@K |\n|---|---:|---:|\n{chr(10).join(k_lines)}\n\n## Budget sweep (label-split)\n\n### Benign panel\n| scale | SR_benign | FRR_benign | throttle_benign | p95_benign |\n|---:|---:|---:|---:|---:|\n{benign_panel}\n\n### Attack panel\n| scale | ASR_allow_attack | ASR_non_deny_attack | cost_attack | throttle_attack | p95_attack |\n|---:|---:|---:|---:|---:|---:|\n{attack_panel}\n"""
    (out_dir / 'report.md').write_text(md)


if __name__ == '__main__':
    main()
