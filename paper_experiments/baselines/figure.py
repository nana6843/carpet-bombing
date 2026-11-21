#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
baselines/figure.py
===================
Draw the E1 baseline comparison (F1 and carpet-bombing scenario-detection rate per
baseline) as a bar chart, in the paper's figure style. Reads baseline_results.csv,
which baselines.py writes; run baselines.py first. Writes Fig_baselines.png / .svg.

Run:  ../../venv/bin/python baselines.py        # writes baseline_results.csv
      ../../venv/bin/python figure.py
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BLUE, ORANGE, INK, INK2, GRID = "#2a78d6", "#eb6834", "#0b0b0b", "#52514e", "#e4e3df"


def main():
    path = os.path.join(HERE, "baseline_results.csv")
    if not os.path.exists(path):
        raise SystemExit("baseline_results.csv missing -- run baselines.py first")
    T = pd.read_csv(path)
    short = [b.split()[0] for b in T["baseline"]]           # 'B1', 'B2', ...

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})
    fig, ax = plt.subplots(figsize=(4.2, 2.8), dpi=200)
    ax.grid(True, axis="y", color=GRID, lw=0.6); ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    x = np.arange(len(T)); w = 0.4
    ax.bar(x - w / 2, T["f1"], w, color=BLUE, label="F1 (window)", edgecolor="white", zorder=2)
    ax.bar(x + w / 2, T["scenario_detection"], w, color=ORANGE,
           label="Scenario detection", edgecolor="white", zorder=2)
    ax.set_xticks(x); ax.set_xticklabels(short, fontsize=8, color=INK2)
    ax.set_ylabel("Score", fontsize=8.5, color=INK)
    ax.set_ylim(0, 1.05); ax.tick_params(colors=INK2)
    ax.legend(frameon=False, fontsize=7.5, loc="lower right")
    # annotate the headline B1 per-host result
    b1 = T[T["baseline"].str.startswith("B1")]
    if len(b1):
        i = int(b1.index[0])
        ax.annotate(f"{b1['scenario_detection'].iloc[0]:.0%}",
                    (i + w / 2, b1["scenario_detection"].iloc[0] + 0.03),
                    ha="center", fontsize=8, color=INK, fontweight="bold")
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(HERE, f"Fig_baselines.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote Fig_baselines.png / .svg")


if __name__ == "__main__":
    main()
