#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ablation/ablation.py
====================
The feature ablation of the paper (Section III-H, Table III), in one readable
file. It answers: "which of the sampling-aware features actually matter?" by
removing one feature group at a time and re-measuring the ensemble's F1 on the
test days.

It does NOT retrain anything. The production run already wrote, for every
(/24, 60-s window) of the test days, the trained ensemble's 0/1 prediction under
each feature set. Table III is just those predictions scored against the ground
truth, so the numbers reproduce the paper exactly.

Feature sets (each a column pred_<key> in ablation_predictions.csv):
  full      all 22 features (17 baseline + 5 sampling-aware: Hhat, D, E, R, A)
  no_chao1  drop the Chao1 victim-count estimate  Hhat
  no_D      drop the dark-host ratio              D
  no_E      drop the destination uniformity       E
  no_R      drop the reflector share              R
  no_A      drop the in/out asymmetry             A
  B5        baseline features only (none of the five sampling-aware features)

Positive class: carpet-bombing only (y == 1). Evaluation set (Table III): the
floor grid (E4-only) and mimic (E8-only) families are excluded, exactly as
../../experiments/evaluate.py does.

Run:  ../../venv/bin/python ablation.py        # needs ablation_predictions.csv
      (build it first with: ../../venv/bin/python make_ablation_data.py)
"""
import os
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))

ROWS = [("full", "All features"),
        ("no_chao1", "Without Chao1 estimate Ĥ"),
        ("no_D", "Without dark-host ratio D"),
        ("no_E", "Without uniformity E"),
        ("no_R", "Without reflector share R"),
        ("no_A", "Without asymmetry A"),
        ("B5", "Baseline features only (B5)")]


def family_of(gt_scenario):
    """'te0260-full' -> 'full' ('' for normal/benign windows)."""
    s = pd.Series(gt_scenario).fillna("")
    return s.where(s == "", s.str.rsplit("-", n=1).str[-1])


def f1_of(y, pred):
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return 2 * pr * rc / (pr + rc) if pr + rc else 0.0


def main():
    path = os.path.join(HERE, "ablation_predictions.csv")
    if not os.path.exists(path):
        raise SystemExit("ablation_predictions.csv missing -- run make_ablation_data.py first")
    P = pd.read_csv(path)

    # Table III set: exclude the floor grid (E4-only) and mimic (E8-only) families.
    keep = ~family_of(P["gt_scenario"]).isin(["floor", "mimic"])
    Q = P[keep].reset_index(drop=True)
    y = Q["y"].to_numpy()
    print(f"test windows (Table III set, floor/mimic excluded): {len(Q):,} "
          f"({int(y.sum()):,} carpet-bombing)\n")

    base = None
    print(f"{'Feature set':<34}{'F1':>7}{'ΔF1':>9}")
    print("-" * 50)
    for key, name in ROWS:
        f1 = f1_of(y, Q[f"pred_{key}"].to_numpy())
        if key == "full":
            base = f1
            print(f"{name:<34}{f1:>7.3f}{'–':>9}")
        else:
            print(f"{name:<34}{f1:>7.3f}{f1 - base:>+9.3f}")
    print("\nReading: removing any single sampling-aware feature barely moves F1 (the set is\n"
          "redundant for ordinary attacks); the baseline-only model (B5) is already strong.\n"
          "Their value shows up against mimicry attacks (see ../mimicry), not here.")


if __name__ == "__main__":
    main()
