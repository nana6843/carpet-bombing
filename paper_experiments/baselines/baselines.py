#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
baselines/baselines.py
======================
The five baseline detectors B1-B5 from the paper (Section III-H), in one
readable file, one function per baseline. Faithful to the production
implementation (../../experiments/train.py + common.py), but focused: it reads the
public-safe labeled feature table `labeled_features.csv` and reproduces the
Table IV comparison.

Positive class: carpet-bombing only (`y = gt_kind == "carpet_bombing"`). Benign
look-alikes (flash crowd, CDN, /16 scan, single-target) and normal are negatives.

Evaluation (Section III-H): temporal split -- train on days 1-5, test on days
6-10. Single-score detectors (B1-B3) pick their threshold on the TRAINING data
(maximize F1), then apply it to the test days. The ML baselines (B4 dst_count-only
and B5) are trained on the training days and predicted on the test days.

  B1  Per-host threshold        score = max_host_bps                 (busiest host's bitrate)
  B2  Per-/24 volume threshold  score = bps                          (whole-/24 bitrate)
  B3  Destination entropy       score = uniformity_E * ln(dst_count) (spread of destinations)
  B4a Fan-out rule              dst_count >= 5 AND dst_count_ratio >= 3.0   (fixed rule)
  B4b dst_count-only model      RF + LightGBM on [dst_count]
  B5  Baseline-features model   RF + LightGBM on the 17 baseline features

Run:  ../../venv/bin/python baselines.py          # needs labeled_features.csv
      (build it first with: ../../venv/bin/python make_labeled_features.py)
"""
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_curve
import lightgbm as lgb

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_DAYS = 5          # days 6-10
MAX_TRAIN_NEG = 40_000 # subsample normal windows when fitting (speed), as in train.py

BASELINE_17 = ["flow_count", "pkt_count", "byte_count", "uniq_src_ip", "uniq_src_port",
               "uniq_dst_port", "proto_div", "syn_pkts", "fin_pkts", "icmp_pkts", "udp_pkts",
               "bytes_per_pkt", "pkts_per_flow", "dports_per_flow", "src_spread",
               "dst_count", "dst_count_ratio"]
W_GRID = [0.0, 0.25, 0.5, 0.75, 1.0]   # RF/LGB blend weights to try


# ─────────────────── scores and the fixed rule (one function each) ───────────────────

def score_B1(F):
    """B1 per-host: the bitrate of the busiest single destination host in the /24."""
    return F["max_host_bps"].fillna(0).to_numpy()


def score_B2(F):
    """B2 per-/24 volume: the total bitrate of the whole /24 subnet."""
    return F["bps"].fillna(0).to_numpy()


def score_B3(F):
    """B3 destination entropy: unnormalized entropy of the destination-address spread."""
    return F["uniformity_E"].fillna(0).to_numpy() * np.log(np.maximum(F["dst_count"].to_numpy(), 1))


def rule_B4(F):
    """B4 fan-out rule: a fixed if-then, no training. Alarm on many destinations rising fast."""
    return ((F["dst_count"] >= 5) & (F["dst_count_ratio"] >= 3.0)).to_numpy()


# ─────────────────── threshold / model helpers (from train.py) ───────────────────

def best_threshold(y, s):
    """Threshold that maximizes F1 (chosen on training data)."""
    if y.sum() == 0:
        return 0.5
    p, r, t = precision_recall_curve(y, s)
    f = np.where(p + r > 0, 2 * p * r / np.where(p + r > 0, p + r, 1), 0)[:-1]
    return float(t[int(np.argmax(f))])


def _subsample_neg(F, rng):
    neg = (F["y"] == 0).to_numpy()
    if neg.sum() <= MAX_TRAIN_NEG:
        return F
    keep = ~neg
    keep[rng.choice(np.flatnonzero(neg), MAX_TRAIN_NEG, replace=False)] = True
    return F[keep]


def _fit_pair(Xtr, ytr):
    rf = RandomForestClassifier(n_estimators=300, max_depth=None, n_jobs=-1,
                                class_weight="balanced", random_state=0).fit(Xtr, ytr)
    lg = lgb.LGBMClassifier(n_estimators=400, learning_rate=0.05, num_leaves=63,
                            class_weight="balanced", random_state=0, verbose=-1).fit(Xtr, ytr)
    return rf, lg


def train_ensemble(train, test, feats, rng):
    """RF + LightGBM ensemble (Section III-F recipe). Pick the blend weight w and the
    threshold tau by leave-one-day-out out-of-fold F1 on the training days, then refit on
    all training days and predict the test days. Returns the test-day prediction (0/1)."""
    days = sorted(train["day"].unique())
    p_rf = np.full(len(train), np.nan); p_lg = np.full(len(train), np.nan)
    pos = train.reset_index(drop=True)
    for d in days:                                   # leave-one-day-out OOF on train
        va = (pos["day"] == d).to_numpy()
        tr = _subsample_neg(pos[~va], rng)
        if tr["y"].sum() == 0 or pos.loc[va, "y"].sum() == 0:
            continue
        rf, lg = _fit_pair(tr[feats].to_numpy(), tr["y"].to_numpy())
        Xva = pos.loc[va, feats].to_numpy()
        p_rf[va] = rf.predict_proba(Xva)[:, 1]
        p_lg[va] = lg.predict_proba(Xva)[:, 1]
    ok = ~np.isnan(p_rf)
    yv = pos["y"].to_numpy()[ok]
    best = (-1.0, 0.5, 0.5)                            # (f1, w, tau)
    for w in W_GRID:
        s = w * p_rf[ok] + (1 - w) * p_lg[ok]
        tau = best_threshold(yv, s)
        f = _f1(yv, s >= tau)
        if f > best[0]:
            best = (f, w, tau)
    _, w, tau = best
    tr = _subsample_neg(pos, rng)                      # refit on all training days
    rf, lg = _fit_pair(tr[feats].to_numpy(), tr["y"].to_numpy())
    Xte = test[feats].to_numpy()
    s_te = w * rf.predict_proba(Xte)[:, 1] + (1 - w) * lg.predict_proba(Xte)[:, 1]
    return (s_te >= tau).astype(int)


# ─────────────────── metrics ───────────────────

def _f1(y, pred):
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return 2 * p * r / (p + r) if p + r else 0.0


def family_of(gt_scenario):
    """Scenario id 'te0260-full' -> family 'full' ('' for normal/benign windows)."""
    s = pd.Series(gt_scenario).fillna("")
    return s.where(s == "", s.str.rsplit("-", n=1).str[-1])


def evaluate(test, pred, n_days, eval_keep=None):
    """Window precision/recall/F1, carpet-bombing scenario detection rate, false alarms/day.
    eval_keep: boolean mask of test windows to score (paper's eval_mask excludes the floor grid,
    an E4-only experiment, from the Table IV comparison)."""
    if eval_keep is not None:
        test = test[eval_keep].reset_index(drop=True)
        pred = pred[eval_keep.to_numpy()]
    y = test["y"].to_numpy()
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    carpet = test[test["y"] == 1]
    det = pred[test["y"].to_numpy() == 1]
    n_sc = carpet["gt_scenario"].nunique()
    n_det = carpet.loc[det == 1, "gt_scenario"].nunique()
    fa_day = fp / n_days
    return dict(precision=prec, recall=rec, f1=f1,
                scenario_detection=n_det / n_sc if n_sc else 0.0, fa_per_day=fa_day)


# ─────────────────── main ───────────────────

def main():
    rng = np.random.default_rng(2026)
    path = os.path.join(HERE, "labeled_features.csv")
    if not os.path.exists(path):
        raise SystemExit("labeled_features.csv missing -- run make_labeled_features.py first")
    F = pd.read_csv(path)
    train = F[F["split"] == "train"].reset_index(drop=True)
    test = F[F["split"] == "test"].reset_index(drop=True)
    n_days = 5                                            # test days 6-10 (22-26 Oct)
    # Table IV eval set: exclude the floor grid (E4-only) and mimic (E8-only), as in evaluate.py.
    keep = ~family_of(test["gt_scenario"]).isin(["floor", "mimic"])
    scored = test[keep]
    print(f"train {len(train):,} windows ({int(train['y'].sum()):,} carpet-bombing) | "
          f"test (Table IV set, floor/mimic excluded) {int(keep.sum()):,} windows "
          f"({int(scored['y'].sum()):,} carpet-bombing, "
          f"{scored[scored['y']==1]['gt_scenario'].nunique()} scenarios, {n_days} days)\n")

    results = {}
    # B1-B3: tune the threshold on the training days, apply to the test days
    for name, scorer in [("B1 Per-host threshold", score_B1),
                         ("B2 Per-/24 volume", score_B2),
                         ("B3 Destination entropy", score_B3)]:
        tau = best_threshold(train["y"].to_numpy(), scorer(train))
        results[name] = evaluate(test, (scorer(test) >= tau).astype(int), n_days, keep)

    # B4a: fixed fan-out rule (no training)
    results["B4 Fan-out rule"] = evaluate(test, rule_B4(test).astype(int), n_days, keep)

    # B4b, B5: trained ensembles
    print("training B4 dst_count-only model ...")
    results["B4 dst_count-only"] = evaluate(test, train_ensemble(train, test, ["dst_count"], rng), n_days, keep)
    print("training B5 baseline-features model ...")
    results["B5 Baseline features"] = evaluate(test, train_ensemble(train, test, BASELINE_17, rng), n_days, keep)

    print(f"\n{'Baseline':<26}{'F1':>7}{'Prec':>7}{'Recall':>8}{'Scn.det':>9}{'FA/day':>8}")
    print("-" * 65)
    for name, m in results.items():
        print(f"{name:<26}{m['f1']:>7.3f}{m['precision']:>7.3f}{m['recall']:>8.3f}"
              f"{m['scenario_detection']:>9.3f}{m['fa_per_day']:>8.1f}")
    print("\n(Reference: the full 24-feature ensemble reaches F1 ~0.985 in the paper, Table IV.)")

    # save the table so figure.py can draw it without retraining
    pd.DataFrame([dict(baseline=n, **m) for n, m in results.items()]).to_csv(
        os.path.join(HERE, "baseline_results.csv"), index=False)


if __name__ == "__main__":
    main()
