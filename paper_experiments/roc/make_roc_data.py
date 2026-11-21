#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
roc/make_roc_data.py
====================
One-off preparation: build the PUBLIC-SAFE score tables for the detection-vs-false-
alarm curves (`roc.py`), from the production runs.

Two panels:
  (a) KNOWN attacks (E1, Table IV): w60_k1 run, the continuous score of each
      detector + the ground truth, non-floor/mimic windows.
  (b) UNSEEN mimicry (E8, Table X): the four seed unseen runs, the ensemble /
      bandwidth scores + CUSUM, on the mimic subset (grace-excluded).

ROC uses only the per-window scores and the label -- NO subnet is needed, so these
tables carry no IP-derived field at all and are safe to share.

Run once:  ../../venv/bin/python make_roc_data.py
"""
import ipaddress, os
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = os.path.join(HERE, "..", "..", "experiments")
KNOWN_RUN = os.path.join(EXP, "exp_out", "run", "w60_k1", "test_predictions.csv.gz")
OUT_KNOWN = os.path.join(HERE, "roc_known.csv")
OUT_UNSEEN = os.path.join(HERE, "roc_unseen.csv")

SEEDS = {"2026": ("exp_bw/run", "exp_mimic/attacks/manifest.csv"),
         "11":   ("exp_seed11/run", "exp_seed11/attacks/manifest.csv"),
         "23":   ("exp_seed23/run", "exp_seed23/attacks/manifest.csv"),
         "37":   ("exp_seed37/run", "exp_seed37/attacks/manifest.csv")}
WINDOW, GRACE = 60, 2


def known():
    cols = ["y", "gt_kind", "gt_scenario",
            "score_full", "score_B5", "score_B3", "score_B2", "score_B1",
            "score_CUSUM", "pred_full", "pred_CUSUM"]
    P = pd.read_csv(KNOWN_RUN, low_memory=False, usecols=cols)
    fam = P["gt_scenario"].fillna("").str.rsplit("-", n=1).str[-1]
    P = P[~fam.isin(["floor", "mimic"])].copy()
    P["y"] = (P["gt_kind"].astype(str) == "carpet_bombing").astype(int)
    for c in ["pred_full", "pred_CUSUM"]:
        P[c] = P[c].astype(str).str.lower().isin(["true", "1"]).astype(int)
    out = ["y"] + [c for c in cols if c.startswith("score_")] + ["pred_full", "pred_CUSUM"]
    P[out].to_csv(OUT_KNOWN, index=False)
    print(f"wrote {OUT_KNOWN}: {len(P):,} windows ({int(P['y'].sum()):,} carpet-bombing)")


def grace_windows(P, m):
    m = m.assign(subnet=m["subnet_24"].str.split("/").str[0].map(
        lambda s: int(ipaddress.ip_address(s)) >> 8))
    out = np.zeros(len(P), bool)
    ws = P["w"].to_numpy() * WINDOW
    sub = P["subnet_real"].to_numpy(); kind = P["gt_kind"].to_numpy()
    idx_by_sub = pd.Series(np.arange(len(P))).groupby(sub).apply(np.array).to_dict()
    for r in m.itertuples():
        idx = idx_by_sub.get(r.subnet)
        if idx is None:
            continue
        hit = (ws[idx] >= r.end) & (ws[idx] < r.end + GRACE * WINDOW) & (kind[idx] == "normal")
        out[idx[hit]] = True
    return out


def unseen():
    parts = []
    for seed, (runs, mf) in SEEDS.items():
        path = os.path.join(EXP, runs, "w60_k1_unseen", "test_predictions.csv.gz")
        P = pd.read_csv(path, low_memory=False,
                        usecols=["w", "subnet_24", "y", "gt_kind", "gt_scenario",
                                 "score_full", "score_full_bw", "score_CUSUM",
                                 "pred_full_bw", "pred_CUSUM"])
        P["y"] = P["y"].astype(int)
        P["gt_kind"] = P["gt_kind"].fillna("normal").astype(str)
        P["gt_scenario"] = P["gt_scenario"].fillna("").astype(str)
        P["subnet_real"] = P["subnet_24"].str.split("/").str[0].map(
            lambda s: int(ipaddress.ip_address(s)) >> 8)
        m = pd.read_csv(os.path.join(EXP, mf))
        fam = P["gt_scenario"].map(m.groupby("scenario_id")["family"].first()).fillna("")
        g = grace_windows(P, m)
        mask = ~g & (fam != "floor").to_numpy() & ((fam == "mimic") | (P["y"] == 0)).to_numpy()
        Q = P[mask].copy(); Q["seed"] = seed
        for c in ["pred_full_bw", "pred_CUSUM"]:
            Q[c] = Q[c].astype(str).str.lower().isin(["true", "1"]).astype(int)
        parts.append(Q[["seed", "y", "gt_scenario", "score_full", "score_full_bw",
                        "score_CUSUM", "pred_full_bw", "pred_CUSUM"]])
    F = pd.concat(parts, ignore_index=True)
    F.to_csv(OUT_UNSEEN, index=False)
    print(f"wrote {OUT_UNSEEN}: {len(F):,} windows across {F['seed'].nunique()} seeds")


def main():
    known()
    unseen()


if __name__ == "__main__":
    main()
