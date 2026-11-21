#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ablation/figure.py
==================
Draw the E5 feature ablation (F1 per feature set, Table III) as a bar chart, in the
paper's figure style, from the public-safe ablation_predictions.csv. Writes
Fig_ablation.png / .svg.

Run:  ../../venv/bin/python figure.py        # needs ablation_predictions.csv
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BLUE, ORANGE, INK, INK2, GRID = "#2a78d6", "#eb6834", "#0b0b0b", "#52514e", "#e4e3df"
ROWS = [("full", "All"), ("no_chao1", "−Ĥ"), ("no_D", "−D"), ("no_E", "−E"),
        ("no_R", "−R"), ("no_A", "−A"), ("B5", "B5")]


def family_of(s):
    s = pd.Series(s).fillna("")
    return s.where(s == "", s.str.rsplit("-", n=1).str[-1])


def f1_of(y, pred):
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return 2 * pr * rc / (pr + rc) if pr + rc else 0.0


def main():
    P = pd.read_csv(os.path.join(HERE, "ablation_predictions.csv"))
    Q = P[~family_of(P["gt_scenario"]).isin(["floor", "mimic"])]
    y = Q["y"].to_numpy()
    f1s = [f1_of(y, Q[f"pred_{k}"].to_numpy()) for k, _ in ROWS]

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})
    fig, ax = plt.subplots(figsize=(4.0, 2.7), dpi=200)
    ax.grid(True, axis="y", color=GRID, lw=0.6); ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    x = np.arange(len(ROWS))
    colors = [BLUE] + ["#9ec5f4"] * 5 + [ORANGE]           # full highlighted, B5 contrast
    ax.bar(x, f1s, 0.6, color=colors, edgecolor="white", zorder=2)
    for i, v in enumerate(f1s):
        ax.text(x[i], v + 0.004, f"{v:.3f}", ha="center", fontsize=6.8, color=INK)
    ax.set_xticks(x); ax.set_xticklabels([lab for _, lab in ROWS], fontsize=8, color=INK2)
    ax.set_ylabel("F1-score (test days)", fontsize=8.5, color=INK)
    lo = min(f1s) - 0.01
    ax.set_ylim(max(0.0, lo), 1.0); ax.tick_params(colors=INK2)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(HERE, f"Fig_ablation.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote Fig_ablation.png / .svg")


if __name__ == "__main__":
    main()
