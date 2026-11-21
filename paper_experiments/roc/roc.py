#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
roc/roc.py
==========
Detection-vs-false-alarm curves (the paper's ROC-style figure), in one readable
file. Each detector is a continuous score with a sliding threshold; we trace
window recall against false alarms per day, and mark the paper's operating points.

Two panels:
  (a) KNOWN attacks (E1) -- full / B5 / B3 / B2 / B1. Shows why per-host (B1) and
      per-/24 volume (B2) are hopeless while the ensemble sits at the top-left.
  (b) UNSEEN mimicry (E8) -- full vs full_bw, mean over the four seeds, with the
      CUSUM and the full_bw+CUSUM hybrid operating points marked.

CUSUM is a gated stream statistic, not a freely sweepable score, so it appears as
an operating point (a marker), not a curve. Writes Fig_detection_vs_fa.png / .svg
and prints a short recall@FA table.

Run:  ../../venv/bin/python roc.py        # needs roc_known.csv and roc_unseen.csv
      (build them first with: ../../venv/bin/python make_roc_data.py)
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import roc_curve  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
N_DAYS = 5
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
COL = {"full": "#2a78d6", "full_bw": "#173f73", "B5": "#eb6834",
       "B3": "#8f8e88", "B2": "#b5b4ad", "B1": "#c9c8c2",
       "CUSUM": "#b04a8a", "full_bw+CUSUM": "#1baf7a"}
NAME = {"full": "Ensemble (full)", "full_bw": "Ensemble + bandwidth", "B5": "B5 baseline ML",
        "B3": "B3 entropy", "B2": "B2 /24 volume", "B1": "B1 per-host"}


def fa_recall(y, score, n_neg):
    """False-alarms/day and recall along the full threshold sweep."""
    s = np.asarray(score, float)
    s = np.where(np.isfinite(s), s, np.nanmin(s[np.isfinite(s)]) - 1)
    fpr, tpr, _ = roc_curve(y, s)
    return fpr * n_neg / N_DAYS, tpr


def op_point(y, pred, n_neg):
    """Operating point (FA/day, recall) of a fixed 0/1 prediction."""
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    rec = tp / (tp + fn) if tp + fn else 0.0
    return fp / N_DAYS, rec


def panel_known(ax):
    F = pd.read_csv(os.path.join(HERE, "roc_known.csv"))
    y = F["y"].to_numpy(); n_neg = int((y == 0).sum())
    print("KNOWN attacks (E1):")
    for d in ["full", "B5", "B3", "B2", "B1"]:
        fa, rec = fa_recall(y, F[f"score_{d}"], n_neg)
        ax.plot(fa, rec, color=COL[d], lw=1.8, label=NAME[d])
        r5 = rec[fa <= 5].max() if (fa <= 5).any() else 0.0
        print(f"   {NAME[d]:<22} recall@FA≤5/day = {r5:.3f}")
    fa, rec = op_point(y, F["pred_full"].to_numpy(), n_neg)
    ax.scatter([fa], [rec], color=COL["full"], s=40, zorder=5, edgecolor="white",
               label="full operating point")
    ax.set_title("(a) known attacks (E1)", fontsize=9, color=INK)
    ax.set_xlim(0, 40); ax.set_ylim(0, 1.02)


def panel_unseen(ax):
    F = pd.read_csv(os.path.join(HERE, "roc_unseen.csv"))
    seeds = sorted(F["seed"].unique())
    grid = np.linspace(0, 40, 200)
    print("\nUNSEEN mimicry (E8), mean over seeds:")
    for d in ["full", "full_bw"]:
        curves = []
        for s in seeds:
            Q = F[F["seed"] == s]; y = Q["y"].to_numpy(); n_neg = int((y == 0).sum())
            fa, rec = fa_recall(y, Q[f"score_{d}"], n_neg)
            order = np.argsort(fa)
            curves.append(np.interp(grid, fa[order], rec[order], left=0, right=rec.max()))
        M = np.vstack(curves); mean = M.mean(0); sd = M.std(0)
        ax.plot(grid, mean, color=COL[d], lw=1.8, label=NAME[d])
        ax.fill_between(grid, mean - sd, mean + sd, color=COL[d], alpha=0.15, linewidth=0)
        print(f"   {NAME[d]:<22} recall@FA≤12/day = {mean[grid <= 12].max():.3f}")
    # operating points: compute per seed, then average (pooling would inflate FA/day by #seeds)
    F = F.assign(pred_hybrid=(F["pred_full_bw"].to_numpy() | F["pred_CUSUM"].to_numpy()))
    for col, key, mk in [("pred_CUSUM", "CUSUM", "s"),
                         ("pred_hybrid", "full_bw+CUSUM", "*")]:
        pts = []
        for s in seeds:
            Q = F[F["seed"] == s]; y = Q["y"].to_numpy(); n_neg = int((y == 0).sum())
            pts.append(op_point(y, Q[col].to_numpy(), n_neg))
        fa, rec = np.mean(pts, axis=0)
        ax.scatter([fa], [rec], color=COL[key], s=70 if mk == "*" else 40, marker=mk,
                   zorder=5, edgecolor="white", label=key.replace("full_bw+CUSUM", "hybrid (full_bw+CUSUM)"))
        print(f"   {key:<22} operating point: recall {rec:.3f} @ {fa:.1f} FA/day (mean of {len(seeds)} seeds)")
    ax.set_title("(b) unseen mimicry (E8)", fontsize=9, color=INK)
    ax.set_xlim(0, 40); ax.set_ylim(0, 1.02)


def main():
    for f in ("roc_known.csv", "roc_unseen.csv"):
        if not os.path.exists(os.path.join(HERE, f)):
            raise SystemExit(f"{f} missing -- run make_roc_data.py first")
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.0), dpi=200)
    for ax in axes:
        ax.grid(True, color=GRID, lw=0.6); ax.set_axisbelow(True)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        ax.set_xlabel("False alarms per day", fontsize=8.5, color=INK)
        ax.tick_params(colors=INK2)
    axes[0].set_ylabel("Detection (window recall)", fontsize=8.5, color=INK)
    panel_known(axes[0]); panel_unseen(axes[1])
    axes[0].legend(frameon=False, fontsize=6.6, loc="lower right")
    axes[1].legend(frameon=False, fontsize=6.6, loc="lower right")
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(HERE, f"Fig_detection_vs_fa.{ext}"), bbox_inches="tight")
    plt.close(fig)
    print("\nwrote Fig_detection_vs_fa.png / .svg")


if __name__ == "__main__":
    main()
