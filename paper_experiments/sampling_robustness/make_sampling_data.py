#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sampling_robustness/make_sampling_data.py
=========================================
One-off preparation: build the PUBLIC-SAFE per-window prediction table for the
sampling-robustness demo (`sampling_robustness.py`), from the production runs.

The paper re-runs the whole pipeline at four router sampling rates by keeping
only every k-th sampled packet on top of the native 1:10,000:
    w60_k1 -> 1:10,000   w60_k2 -> 1:20,000   w60_k4 -> 1:40,000   w60_k8 -> 1:80,000
Each run (../../experiments/exp_out/run/w60_k*/test_predictions.csv.gz) already
carries the trained ensemble's 0/1 prediction per (/24, 60-s window), so Fig. 5
is a pure tabulation -- nothing is retrained and the numbers match the paper.

The only sensitive field is `subnet_24`. We map it through the SAME Crypto-PAn
secret that anonymized exports_anon, keep the ground truth and the two relevant
predictions (full, no_chao1), tag each row with its sampling rate, and write
`sampling_predictions.csv`.

Run once:  ../../venv/bin/python make_sampling_data.py
"""
import hashlib, hmac, os, socket, struct
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "..", "..", "experiments", "exp_out", "run")
SECRET = bytes.fromhex(open(os.path.join(HERE, "..", "..", "ip_anon_secret.key")).read().strip())
OUT = os.path.join(HERE, "sampling_predictions.csv")

RATES = {"w60_k1": 10000, "w60_k2": 20000, "w60_k4": 40000, "w60_k8": 80000}
PRED_COLS = ["pred_full", "pred_no_chao1"]
KEEP = ["subnet_24", "gt_kind", "gt_scenario", "y"] + PRED_COLS

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


def load(tag, N):
    path = os.path.join(RUN, tag, "test_predictions.csv.gz")
    P = pd.read_csv(path, low_memory=False, usecols=[c for c in KEEP if c])
    for c in PRED_COLS:
        P[c] = P[c].astype(str).str.lower().isin(["true", "1"]).astype(int)
    P["y"] = P["y"].astype(int)
    P["gt_kind"] = P["gt_kind"].fillna("normal").astype(str)
    P["gt_scenario"] = P["gt_scenario"].fillna("").astype(str)
    P["rate_N"] = N
    return P


def main():
    parts = [load(tag, N) for tag, N in RATES.items()]
    F = pd.concat(parts, ignore_index=True)
    uniq = {s: anon_subnet24(s) for s in F["subnet_24"].unique()}
    F["subnet_24"] = F["subnet_24"].map(uniq)

    cols = ["rate_N", "subnet_24", "gt_kind", "gt_scenario", "y"] + PRED_COLS
    F[cols].to_csv(OUT, index=False)
    print(f"wrote {OUT}: {len(F):,} rows, {F['subnet_24'].nunique()} anon /24")
    for N in RATES.values():
        sub = F[F["rate_N"] == N]
        print(f"  1:{N:<6} {len(sub):>8,} windows, {int(sub['y'].sum()):>5,} carpet-bombing")


if __name__ == "__main__":
    main()
