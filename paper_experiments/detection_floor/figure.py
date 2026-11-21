#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detection_floor/figure.py
=========================
Draw Fig. 6 (detection-floor recall heatmap, two panels: without / with the Chao1
estimate) from the public-safe floor_windows.csv, in the paper's figure style.
Writes Fig6_Detection_Floor.png / .svg.

Run:  ../../venv/bin/python figure.py        # needs floor_windows.csv
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.colors as mcolors  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INK, INK2 = "#0b0b0b", "#52514e"
SEQ = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]


def main():
    F = pd.read_csv(os.path.join(HERE, "floor_windows.csv"))
    G = F[(F["family"] == "floor") & (F["y"] == 1)].copy()
    G["coverage_cell"] = G["coverage"].round(2)
    covs = sorted(G["coverage_cell"].unique())
    rates = sorted(G["rate_mbps"].unique())

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.9), dpi=200, sharey=True)
    cmap = mcolors.LinearSegmentedColormap.from_list("seq", SEQ)
    im = None
    for ax, (cfg, title) in zip(axes, (("no_chao1", "(a) without Chao1 (raw dst_count)"),
                                        ("full", "(b) with Chao1 estimate"))):
        M = G.groupby(["coverage_cell", "rate_mbps"])[f"pred_{cfg}"].mean().unstack()
        M = M.reindex(index=covs, columns=rates)
        im = ax.imshow(M.to_numpy(), cmap=cmap, vmin=0, vmax=1, aspect="auto", origin="lower")
        for i in range(len(covs)):
            for j in range(len(rates)):
                v = M.to_numpy()[i, j]
                if not np.isnan(v):
                    ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=6.5,
                            color="white" if v > 0.55 else INK)
        ax.set_xticks(range(len(rates))); ax.set_xticklabels([f"{r:g}" for r in rates],
                                                             fontsize=7.5, color=INK2)
        ax.set_yticks(range(len(covs))); ax.set_yticklabels([f"{c * 100:.0f}%" for c in covs],
                                                            fontsize=7.5, color=INK2)
        ax.set_xlabel("Attack rate per /24 (Mbps)", fontsize=8.5, color=INK)
        ax.set_title(title, fontsize=9, color=INK)
        for s in ax.spines.values():
            s.set_visible(False)
    axes[0].set_ylabel("Host coverage", fontsize=8.5, color=INK)
    cb = fig.colorbar(im, ax=axes, fraction=0.03, pad=0.02)
    cb.set_label("Recall", fontsize=8, color=INK)
    cb.ax.tick_params(labelsize=7, colors=INK2); cb.outline.set_visible(False)
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(HERE, f"Fig6_Detection_Floor.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("wrote Fig6_Detection_Floor.png / .svg")


if __name__ == "__main__":
    main()
