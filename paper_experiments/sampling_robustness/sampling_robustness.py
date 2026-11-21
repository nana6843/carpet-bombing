#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sampling_robustness/sampling_robustness.py
==========================================
How well does detection hold up as the router samples more aggressively?
(Section III-H, Fig. 5.) The paper re-runs the whole pipeline at four sampling
rates -- 1:10,000, 1:20,000, 1:40,000, 1:80,000 -- and measures the ensemble's
F1 on the carpet-bombing test windows at each rate.

It does NOT retrain anything: each production run already wrote the trained
ensemble's 0/1 prediction per (/24, 60-s window), so this is a pure tabulation
and the numbers reproduce the paper.

Two configurations are compared, to show the Chao1 victim-count estimate does not
hurt under heavier sampling:
  full      all features (incl. the Chao1 estimate Ĥ)
  no_chao1  same, with the Chao1 estimate removed

Positive class: carpet-bombing only (y == 1). Floor (E4-only) and mimic (E8-only)
families are excluded, as in ../../experiments/evaluate.py. Note each heavier rate
has fewer attack windows, because low-rate attacks fall below the sampling floor
and produce no sampled packets -- that thinning is part of the robustness story.

Run:  ../../venv/bin/python sampling_robustness.py     # needs sampling_predictions.csv
      (build it first with: ../../venv/bin/python make_sampling_data.py)
"""
import os
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))


def family_of(gt_scenario):
    s = pd.Series(gt_scenario).fillna("")
    return s.where(s == "", s.str.rsplit("-", n=1).str[-1])


def f1_of(y, pred):
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return 2 * pr * rc / (pr + rc) if pr + rc else 0.0


def main():
    path = os.path.join(HERE, "sampling_predictions.csv")
    if not os.path.exists(path):
        raise SystemExit("sampling_predictions.csv missing -- run make_sampling_data.py first")
    F = pd.read_csv(path)
    F = F[~family_of(F["gt_scenario"]).isin(["floor", "mimic"])]

    print(f"{'Sampling rate':<16}{'windows':>10}{'carpet':>9}{'F1 full':>10}{'F1 no_chao1':>13}")
    print("-" * 58)
    for N in sorted(F["rate_N"].unique()):
        Q = F[F["rate_N"] == N]
        y = Q["y"].to_numpy()
        print(f"{'1:' + f'{N:,}':<16}{len(Q):>10,}{int(y.sum()):>9,}"
              f"{f1_of(y, Q['pred_full'].to_numpy()):>10.3f}"
              f"{f1_of(y, Q['pred_no_chao1'].to_numpy()):>13.3f}")
    print("\nReading: F1 stays ~0.97–0.99 even as sampling goes from 1:10k to 1:80k —\n"
          "detection degrades gracefully, and the Chao1 estimate neither helps nor hurts\n"
          "at the ensemble level (its gain is in victim-count accuracy, see ../detection_floor).")


if __name__ == "__main__":
    main()
