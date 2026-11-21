#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mimicry/mimicry.py
==================
The paper's hardest case (Section III-H / §IV-E, Table X): carpet bombing that
*disguises itself* as ordinary web traffic -- no reflector source ports, normal
packet sizes -- so the sampling-aware fingerprints vanish. The mimic scenarios are
held OUT of training ("unseen"), so this measures true generalization.

The story is a progression of three detectors, averaged over four random seeds:
    full            the ensemble alone (22 features)
    full_bw         ensemble + the two bandwidth-change features
    full_bw+CUSUM   the hybrid: full_bw OR the robust-z/CUSUM stream detector

Nothing is retrained: each seed's production run already wrote the per-window 0/1
predictions; the hybrid is just full_bw OR CUSUM (as in e8_hybrid.py). We report
the mimic-scenario detection rate (how many of the held-out mimic scenarios are
caught), plus window F1 and false alarms/day, per seed and averaged.

Run:  ../../venv/bin/python mimicry.py          # needs mimicry_predictions.csv
      (build it first with: ../../venv/bin/python make_mimicry_data.py)
"""
import os
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
N_DAYS = 5     # test days 22-26 Oct
DETECTORS = ["full", "full_bw", "full_bw+CUSUM"]
NAMES = {"full": "Ensemble alone (full)",
         "full_bw": "+ bandwidth change (full_bw)",
         "full_bw+CUSUM": "+ CUSUM hybrid (full_bw+CUSUM)"}


def metrics(M, pred):
    """Scenario detection rate over mimic scenarios, window F1, false alarms/day."""
    y = M["y"].to_numpy()
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    pos = y == 1                                            # mimic scenario windows
    det = pd.DataFrame({"sc": M["gt_scenario"].to_numpy()[pos], "p": pred[pos]})
    by_sc = det.groupby("sc")["p"].max()
    scen_rate = by_sc.mean() if len(by_sc) else 0.0
    return dict(scen_det=scen_rate, n_det=int(by_sc.sum()), n_sc=int(len(by_sc)),
                f1=f1, fa_day=fp / N_DAYS)


def main():
    path = os.path.join(HERE, "mimicry_predictions.csv")
    if not os.path.exists(path):
        raise SystemExit("mimicry_predictions.csv missing -- run make_mimicry_data.py first")
    F = pd.read_csv(path)
    F["pred_full_bw+CUSUM"] = (F["pred_full_bw"].to_numpy() | F["pred_CUSUM"].to_numpy())

    seeds = sorted(F["seed"].unique())
    rows = {d: [] for d in DETECTORS}
    print("Per-seed mimic-scenario detection (unseen; held out of training)\n")
    print(f"{'detector':<30}" + "".join(f"{'seed ' + str(s):>11}" for s in seeds) + f"{'mean':>9}")
    print("-" * (30 + 11 * len(seeds) + 9))
    for d in DETECTORS:
        cells = []
        for s in seeds:
            m = metrics(F[F["seed"] == s], F[F["seed"] == s][f"pred_{d}"].to_numpy())
            rows[d].append(m)
            cells.append(f"{m['n_det']}/{m['n_sc']}")
        mean_rate = np.mean([r["scen_det"] for r in rows[d]])
        print(f"{NAMES[d]:<30}" + "".join(f"{c:>11}" for c in cells) + f"{mean_rate:>8.1%}")

    print("\nMean over seeds (unseen mimic)\n")
    print(f"{'detector':<30}{'scen.det':>10}{'F1':>8}{'FA/day':>9}")
    print("-" * 57)
    for d in DETECTORS:
        sd = np.mean([r["scen_det"] for r in rows[d]])
        f1 = np.mean([r["f1"] for r in rows[d]])
        fa = np.mean([r["fa_day"] for r in rows[d]])
        print(f"{NAMES[d]:<30}{sd:>10.1%}{f1:>8.3f}{fa:>9.1f}")

    print("\nReading: the ensemble alone generalizes poorly to disguised attacks; adding the\n"
          "two bandwidth-change features lifts mimic detection to ~73%, and OR-ing in the\n"
          "CUSUM stream detector (the hybrid) reaches ~93% — at a higher false-alarm cost.\n"
          "This is why the paper keeps the bandwidth features and the CUSUM hybrid despite\n"
          "their redundancy on ordinary attacks (see ../ablation).")


if __name__ == "__main__":
    main()
