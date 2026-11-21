#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mimicry/make_mimicry_data.py
============================
One-off preparation: build the PUBLIC-SAFE per-window table for the mimicry demo
(`mimicry.py`), from the four multi-seed production runs.

E8 (Table X / §IV-E) tests carpet bombing that *disguises itself* as web traffic
(no reflector ports, normal packet sizes). The honest test is the "unseen" run,
where the mimic scenarios are held out of training (train.py
--exclude-train-families mimic). We take, per seed, the unseen run's per-window
predictions and reproduce the mimic subset exactly as ../../experiments/evaluate.py +
extra_common.py do:

    subset = (not in a post-scenario grace window) and (family != floor)
             and (family == mimic OR y == 0)

keeping the three detectors of the mimicry story:
    pred_full      the ensemble alone (22 features)
    pred_full_bw   ensemble + the two bandwidth-change features
    pred_CUSUM     the robust-z / CUSUM stream detector
(the hybrid pred_full_bw+CUSUM is formed in mimicry.py as full_bw OR CUSUM.)

Seeds and their runs (same as new_exp8/e8_seeds.py):
    2026 -> exp_bw/run         (attacks/features from exp_mimic)
    11   -> exp_seed11/run
    23   -> exp_seed23/run
    37   -> exp_seed37/run

The only sensitive field is the real `subnet_24`. We map it through the SAME
Crypto-PAn secret as exports_anon; the grace mask (which needs the manifest's real
subnet) is applied here, so the output carries only anonymized subnets.

Run once:  ../../venv/bin/python make_mimicry_data.py
"""
import hashlib, hmac, ipaddress, os, socket, struct
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = os.path.join(HERE, "..", "..", "experiments")
SECRET = bytes.fromhex(open(os.path.join(HERE, "..", "..", "ip_anon_secret.key")).read().strip())
OUT = os.path.join(HERE, "mimicry_predictions.csv")

SEEDS = {"2026": ("exp_bw/run", "exp_mimic/attacks/manifest.csv"),
         "11":   ("exp_seed11/run", "exp_seed11/attacks/manifest.csv"),
         "23":   ("exp_seed23/run", "exp_seed23/attacks/manifest.csv"),
         "37":   ("exp_seed37/run", "exp_seed37/attacks/manifest.csv")}
WINDOW, GRACE = 60, 2
PRED_COLS = ["pred_full", "pred_full_bw", "pred_CUSUM"]
_cache = {}


def cpan(addr: int) -> int:
    """Crypto-PAn prefix-preserving map (same secret as exports_anon)."""
    v = _cache.get(addr)
    if v is not None:
        return v
    result = 0
    for pos in range(32):
        prefix = ((addr >> (32 - pos)) << (32 - pos)) if pos else 0
        bit = hmac.new(SECRET, struct.pack("!II", prefix, pos), hashlib.sha256).digest()[0] & 1
        result |= (((addr >> (31 - pos)) & 1) ^ bit) << (31 - pos)
    _cache[addr] = result
    return result


def anon_subnet24(s: str) -> str:
    net = s.split("/")[0]
    real = struct.unpack("!I", socket.inet_aton(net))[0]
    a24 = (cpan(real) >> 8) << 8
    return socket.inet_ntoa(struct.pack("!I", a24)) + "/24"


def grace_windows(P, m):
    """Boolean mask: normal window within GRACE windows after a scenario ends in the
    same /24 (mirrors common.grace_mask)."""
    m = m.assign(subnet=m["subnet_24"].str.split("/").str[0].map(
        lambda s: int(ipaddress.ip_address(s)) >> 8))
    out = np.zeros(len(P), bool)
    ws = P["w"].to_numpy() * WINDOW
    sub = P["subnet_real"].to_numpy()
    kind = P["gt_kind"].to_numpy()
    idx_by_sub = pd.Series(np.arange(len(P))).groupby(sub).apply(np.array).to_dict()
    for r in m.itertuples():
        idx = idx_by_sub.get(r.subnet)
        if idx is None:
            continue
        hit = (ws[idx] >= r.end) & (ws[idx] < r.end + GRACE * WINDOW) & (kind[idx] == "normal")
        out[idx[hit]] = True
    return out


def load_seed(seed, runs, manifest):
    path = os.path.join(EXP, runs, "w60_k1_unseen", "test_predictions.csv.gz")
    P = pd.read_csv(path, low_memory=False,
                    usecols=["w", "subnet_24", "y", "gt_kind", "gt_scenario"] + PRED_COLS)
    for c in PRED_COLS:
        P[c] = P[c].astype(str).str.lower().isin(["true", "1"]).astype(int)
    P["y"] = P["y"].astype(int)
    P["gt_kind"] = P["gt_kind"].fillna("normal").astype(str)
    P["gt_scenario"] = P["gt_scenario"].fillna("").astype(str)
    P["subnet_real"] = P["subnet_24"].str.split("/").str[0].map(
        lambda s: int(ipaddress.ip_address(s)) >> 8)

    m = pd.read_csv(os.path.join(EXP, manifest))
    fam = P["gt_scenario"].map(m.groupby("scenario_id")["family"].first()).fillna("")
    g = grace_windows(P, m)
    mask = ~g & (fam != "floor").to_numpy() & ((fam == "mimic") | (P["y"] == 0)).to_numpy()

    M = P[mask].copy()
    M["family"] = fam[mask].to_numpy()
    M["seed"] = seed
    return M


def main():
    parts = [load_seed(s, runs, mf) for s, (runs, mf) in SEEDS.items()]
    F = pd.concat(parts, ignore_index=True)
    uniq = {s: anon_subnet24(s) for s in F["subnet_24"].unique()}
    F["subnet_24"] = F["subnet_24"].map(uniq)

    cols = ["seed", "subnet_24", "w", "y", "gt_kind", "gt_scenario", "family"] + PRED_COLS
    F[cols].to_csv(OUT, index=False)
    print(f"wrote {OUT}: {len(F):,} rows across {F['seed'].nunique()} seeds")
    for s in SEEDS:
        sub = F[F["seed"] == s]
        nmimic = sub[sub["family"] == "mimic"]["gt_scenario"].nunique()
        print(f"  seed {s:<5} {len(sub):>7,} windows, {nmimic} unseen mimic scenarios")


if __name__ == "__main__":
    main()
