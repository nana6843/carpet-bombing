#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detection_floor/detection_floor.py
==================================
Two questions from Section III-H (Fig. 6), in one readable file:

  (A) Detection floor -- how faint can a carpet-bombing attack be and still get
      caught? Using the E4 "floor grid" (scenarios swept over attack rate x host
      coverage), find per coverage the lowest attack rate whose recall stays >= 0.9.

  (B) Chao1 victim-count bias -- how badly does sampling undercount the victims,
      and how much does the Chao1 estimate fix it? Compare, on clean in-scenario
      windows, the raw dst_count and the Chao1-corrected dst_count_est against the
      true victim count n_victims.

Nothing is retrained: the production run already wrote the ensemble's 0/1
prediction and the two victim-count features per window; the manifest supplies the
true attack rate, coverage, and victim count. So the numbers reproduce the paper.

Run:  ../../venv/bin/python detection_floor.py        # needs floor_windows.csv
      (build it first with: ../../venv/bin/python make_floor_data.py)
"""
import os
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
WINDOW = 60            # seconds
FLOOR_RECALL = 0.9     # recall target for the detection floor (paper default)
# families that are genuine carpet-bombing scenarios with a known victim count
BIAS_FAMILIES = ["floor", "full", "partial10", "partial25", "partial50",
                 "pulse", "lowrate", "multivector"]


def detection_floor(F):
    """(A) Lowest attack rate per coverage whose recall >= target (and stays >= it
    for every higher rate). Uses the floor-grid attack windows only."""
    G = F[(F["family"] == "floor") & (F["y"] == 1)].copy()
    G["coverage_cell"] = G["coverage"].round(2)
    out = {}
    for cfg in ["full", "no_chao1"]:
        grid = G.groupby(["coverage_cell", "rate_mbps"])[f"pred_{cfg}"].mean()
        rows = []
        for cov, sub in grid.groupby(level=0):
            sub = sub.sort_index()
            ok = sub.to_numpy() >= FLOOR_RECALL
            rates = sub.index.get_level_values(1).to_numpy()
            floor = next((rates[i] for i in range(len(ok)) if ok[i:].all()), np.nan)
            rows.append((cov, floor))
        out[cfg] = rows
    return out


def chao1_bias(F):
    """(B) Mean undercount of raw dst_count vs the Chao1 estimate dst_count_est,
    against the true victim count, on windows wholly inside a scenario."""
    B = F[(F["y"] == 1) & F["family"].isin(BIAS_FAMILIES)].copy()
    inside = (B["w"] * WINDOW >= B["sc_start"]) & ((B["w"] + 1) * WINDOW <= B["sc_end"])
    B = B[inside]
    B["group"] = np.where(B["n_victims"] >= 254, "full-subnet (254 hosts)", "partial (10–50%)")
    B["bias_chao1"] = B["dst_count_est"] - B["n_victims"]
    B["bias_dstcount"] = B["dst_count"] - B["n_victims"]
    return B.groupby("group").agg(windows=("w", "size"),
                                  bias_chao1=("bias_chao1", "mean"),
                                  bias_dstcount=("bias_dstcount", "mean")).reset_index()


def main():
    path = os.path.join(HERE, "floor_windows.csv")
    if not os.path.exists(path):
        raise SystemExit("floor_windows.csv missing -- run make_floor_data.py first")
    F = pd.read_csv(path)

    print("(A) Detection floor -- lowest attack rate with recall >= "
          f"{FLOOR_RECALL:.0%} (floor grid)\n")
    floors = detection_floor(F)
    print(f"{'coverage':>10}{'floor full (Mbps)':>20}{'floor no_chao1 (Mbps)':>24}")
    print("-" * 54)
    full = dict(floors["full"]); noc = dict(floors["no_chao1"])
    for cov in sorted(full):
        print(f"{cov * 100:>9.0f}%{full[cov]:>20g}{noc[cov]:>24g}")

    print("\n(B) Chao1 victim-count bias -- mean (estimate − true victims), "
          "clean in-scenario windows\n")
    bias = chao1_bias(F)
    print(f"{'group':<26}{'windows':>9}{'Chao1 Ĥ':>12}{'raw dst_count':>16}")
    print("-" * 63)
    for r in bias.itertuples():
        print(f"{r.group:<26}{r.windows:>9,}{r.bias_chao1:>+12.1f}{r.bias_dstcount:>+16.1f}")
    full_row = bias[bias["group"].str.startswith("full")]
    if len(full_row):
        r = full_row.iloc[0]
        print(f"\nReading: on a full /24 (254 victims) sampling hides most of them — raw dst_count\n"
              f"undercounts by {-r.bias_dstcount:.0f} hosts; the Chao1 estimate cuts that to "
              f"{-r.bias_chao1:.0f} (the 124→77 result).\n"
              "The detection floor is unchanged with/without Chao1: its value is counting the\n"
              "victims, not deciding whether an attack is present.")


if __name__ == "__main__":
    main()
