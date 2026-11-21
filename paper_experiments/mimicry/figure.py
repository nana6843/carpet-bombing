#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mimicry/figure.py
=================
Draw the E8 mimicry progression (unseen mimic-scenario detection by detector,
mean over seeds with per-seed dots) from the public-safe mimicry_predictions.csv,
in the paper's figure style. Writes Fig_mimicry_detection.png / .svg.

Run:  ../../venv/bin/python figure.py        # needs mimicry_predictions.csv
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
DETECTORS = ["full", "full_bw", "full_bw+CUSUM"]
LABELS = {"full": "Ensemble\nalone", "full_bw": "+ bandwidth", "full_bw+CUSUM": "+ CUSUM\nhybrid"}
COL = {"full": "#2a78d6", "full_bw": "#173f73", "full_bw+CUSUM": "#1baf7a"}


def scen_rate(M, pred):
    pos = M["y"].to_numpy() == 1
    d = pd.DataFrame({"sc": M["gt_scenario"].to_numpy()[pos], "p": pred[pos]})
    g = d.groupby("sc")["p"].max()
    return g.mean() if len(g) else 0.0


def main():
    F = pd.read_csv(os.path.join(HERE, "mimicry_predictions.csv"))
    F["pred_full_bw+CUSUM"] = (F["pred_full_bw"].to_numpy() | F["pred_CUSUM"].to_numpy())
    seeds = sorted(F["seed"].unique())
    per_seed = {d: [scen_rate(F[F["seed"] == s], F[F["seed"] == s][f"pred_{d}"].to_numpy())
                    for s in seeds] for d in DETECTORS}
    means = [np.mean(per_seed[d]) for d in DETECTORS]

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})
    fig, ax = plt.subplots(figsize=(3.6, 2.8), dpi=200)
    ax.grid(True, axis="y", color=GRID, lw=0.6); ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    x = np.arange(len(DETECTORS))
    ax.bar(x, means, width=0.6, color=[COL[d] for d in DETECTORS], edgecolor="white", zorder=2)
    rng = np.random.default_rng(0)
    for i, d in enumerate(DETECTORS):                       # per-seed dots
        jit = (rng.uniform(-0.12, 0.12, len(seeds)))
        ax.scatter(x[i] + jit, per_seed[d], s=18, color=INK, zorder=3,
                   edgecolor="white", linewidth=0.6)
    for i, m in enumerate(means):
        ax.text(x[i], m + 0.03, f"{m:.0%}", ha="center", fontsize=8.5, color=INK, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels([LABELS[d] for d in DETECTORS], fontsize=8, color=INK2)
    ax.set_ylabel("Mimic scenarios detected (unseen)", fontsize=8.5, color=INK)
    ax.set_ylim(0, 1.05); ax.set_yticks(np.arange(0, 1.01, 0.25))
    ax.set_yticklabels([f"{v:.0%}" for v in np.arange(0, 1.01, 0.25)])
    ax.tick_params(colors=INK2)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(HERE, f"Fig_mimicry_detection.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote Fig_mimicry_detection.png / .svg  (dots = per-seed, bar = mean of 4 seeds)")


if __name__ == "__main__":
    main()
