#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sampling_robustness/figure.py
=============================
Draw Fig. 5 (F1 vs sampling rate) from the public-safe sampling_predictions.csv,
in the paper's figure style. Writes Fig5_F1_vs_Sampling.png / .svg.

Run:  ../../venv/bin/python figure.py        # needs sampling_predictions.csv
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BLUE, ORANGE, INK, INK2, GRID = "#2a78d6", "#eb6834", "#0b0b0b", "#52514e", "#e4e3df"


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
    F = pd.read_csv(os.path.join(HERE, "sampling_predictions.csv"))
    F = F[~family_of(F["gt_scenario"]).isin(["floor", "mimic"])]
    rows = []
    for N in sorted(F["rate_N"].unique()):
        Q = F[F["rate_N"] == N]; y = Q["y"].to_numpy()
        rows.append(dict(factor=N // 10000,
                         full=f1_of(y, Q["pred_full"].to_numpy()),
                         no_chao1=f1_of(y, Q["pred_no_chao1"].to_numpy())))
    T = pd.DataFrame(rows).sort_values("factor")

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})
    fig, ax = plt.subplots(figsize=(3.5, 2.6), dpi=200)
    ax.grid(True, color=GRID, lw=0.6); ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for cfg, col, mk, lab in (("full", BLUE, "o", "With Chao1 estimate"),
                              ("no_chao1", ORANGE, "s", "Without Chao1 estimate")):
        ax.plot(T["factor"], T[cfg], color=col, lw=2, marker=mk, ms=6, label=lab,
                markeredgecolor="white", markeredgewidth=1)
    ax.set_xscale("log", base=2)
    ax.set_xticks([1, 2, 4, 8]); ax.set_xticklabels(["N", "2N", "4N", "8N"])
    ax.set_xlabel("Sampling ratio (N = 10,000)", color=INK, fontsize=9)
    ax.set_ylabel("F1-score", color=INK, fontsize=9)
    ax.set_ylim(max(0.0, T[["full", "no_chao1"]].to_numpy().min() - 0.1), 1.0)
    ax.tick_params(colors=INK2)
    ax.legend(frameon=False, fontsize=8, loc="lower left")
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(HERE, f"Fig5_F1_vs_Sampling.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote Fig5_F1_vs_Sampling.png / .svg")


if __name__ == "__main__":
    main()
