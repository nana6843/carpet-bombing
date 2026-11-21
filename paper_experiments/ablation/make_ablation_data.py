#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ablation/make_ablation_data.py
==============================
One-off preparation: build the PUBLIC-SAFE per-window prediction table for the
feature-ablation demo (`ablation.py`), from the production run.

The production run (../../experiments/exp_out/run/w60_k1/test_predictions.csv.gz) is
the exact (/24, 60-s window) table the paper's Table III is tabulated from. Each
row already carries the trained ensemble's 0/1 prediction for every feature set
(full, no_chao1, no_D, no_E, no_R, no_A, B5), so the ablation is a pure tabulation
-- no model is retrained here and the numbers match the paper exactly.

The only sensitive field is `subnet_24` (a real customer /24). We map it through
the SAME Crypto-PAn secret that anonymized exports_anon, keep just the ground
truth and the per-config predictions, and write `ablation_predictions.csv`.

Run once:  ../../venv/bin/python make_ablation_data.py
"""
import hashlib, hmac, os, socket, struct
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
PRED = os.path.join(HERE, "..", "..", "experiments", "exp_out", "run", "w60_k1", "test_predictions.csv.gz")
SECRET = bytes.fromhex(open(os.path.join(HERE, "..", "..", "ip_anon_secret.key")).read().strip())
OUT = os.path.join(HERE, "ablation_predictions.csv")

# the ablation configurations (Table III); each has a pred_<key> column
CONFIGS = ["full", "no_chao1", "no_D", "no_E", "no_R", "no_A", "B5"]
PRED_COLS = [f"pred_{k}" for k in CONFIGS]
KEEP = ["subnet_24", "day", "gt_kind", "gt_scenario", "y"] + PRED_COLS

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
    """'103.183.187.0/24' -> anon '.../24' (consistent with exports_anon)."""
    net = s.split("/")[0]
    real = struct.unpack("!I", socket.inet_aton(net))[0]
    a24 = (cpan(real) >> 8) << 8
    return socket.inet_ntoa(struct.pack("!I", a24)) + "/24"


def main():
    P = pd.read_csv(PRED, low_memory=False, usecols=[c for c in KEEP if c])
    for c in PRED_COLS:                                  # normalize to 0/1
        P[c] = P[c].astype(str).str.lower().isin(["true", "1"]).astype(int)
    P["y"] = P["y"].astype(int)
    P["gt_kind"] = P["gt_kind"].fillna("normal").astype(str)
    P["gt_scenario"] = P["gt_scenario"].fillna("").astype(str)
    uniq = {s: anon_subnet24(s) for s in P["subnet_24"].unique()}   # anonymize the only sensitive field
    P["subnet_24"] = P["subnet_24"].map(uniq)

    P[KEEP].to_csv(OUT, index=False)
    print(f"wrote {OUT}: {len(P):,} windows, {P['subnet_24'].nunique()} anon /24, "
          f"{int(P['y'].sum()):,} carpet-bombing windows")


if __name__ == "__main__":
    main()
