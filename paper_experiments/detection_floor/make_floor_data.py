#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detection_floor/make_floor_data.py
==================================
One-off preparation: build the PUBLIC-SAFE per-window table for the detection-floor
and Chao1-bias demo (`detection_floor.py`), from the production run + manifest.

Two inputs, joined on the scenario id:
  * ../../experiments/exp_out/run/w60_k1/test_predictions.csv.gz  -- per (/24, window)
    ground truth, the ensemble's prediction (full / no_chao1), and the two
    victim-count features dst_count (raw) and dst_count_est (Chao1-corrected).
  * ../../experiments/exp_out/attacks/manifest.csv  -- per-scenario attack parameters
    (family, rate_mbps, coverage, n_victims, start, end).

The only sensitive fields are the real victim `subnet_24` (predictions) and the
manifest's victim subnet. We map the prediction `subnet_24` through the SAME
Crypto-PAn secret as exports_anon and DROP the manifest subnet entirely; only the
non-sensitive attack parameters are kept. Output: `floor_windows.csv`.

Run once:  ../../venv/bin/python make_floor_data.py
"""
import hashlib, hmac, os, socket, struct
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
PRED = os.path.join(HERE, "..", "..", "experiments", "exp_out", "run", "w60_k1", "test_predictions.csv.gz")
MANIFEST = os.path.join(HERE, "..", "..", "experiments", "exp_out", "attacks", "manifest.csv")
SECRET = bytes.fromhex(open(os.path.join(HERE, "..", "..", "ip_anon_secret.key")).read().strip())
OUT = os.path.join(HERE, "floor_windows.csv")

PRED_COLS = ["pred_full", "pred_no_chao1"]
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


def main():
    P = pd.read_csv(PRED, low_memory=False,
                    usecols=["w", "subnet_24", "y", "gt_kind", "gt_scenario",
                             "dst_count", "dst_count_est"] + PRED_COLS)
    for c in PRED_COLS:
        P[c] = P[c].astype(str).str.lower().isin(["true", "1"]).astype(int)
    P["y"] = P["y"].astype(int)
    P["gt_kind"] = P["gt_kind"].fillna("normal").astype(str)
    P["gt_scenario"] = P["gt_scenario"].fillna("").astype(str)

    # per-scenario attack parameters (non-sensitive; victim subnet is dropped)
    m = pd.read_csv(MANIFEST)
    sc = m.groupby("scenario_id").agg(
        family=("family", "first"), rate_mbps=("rate_mbps", "first"),
        coverage=("coverage", "first"), n_victims=("n_victims", "first"),
        sc_start=("start", "min"), sc_end=("end", "max"))
    P = P.merge(sc, how="left", left_on="gt_scenario", right_index=True)

    uniq = {s: anon_subnet24(s) for s in P["subnet_24"].unique()}   # anonymize the only sensitive field
    P["subnet_24"] = P["subnet_24"].map(uniq)

    cols = ["subnet_24", "w", "y", "gt_kind", "gt_scenario", "family", "rate_mbps",
            "coverage", "n_victims", "sc_start", "sc_end", "dst_count", "dst_count_est"] + PRED_COLS
    P[cols].to_csv(OUT, index=False)
    n_floor = int(((P["family"] == "floor") & (P["y"] == 1)).sum())
    print(f"wrote {OUT}: {len(P):,} windows ({n_floor:,} floor-grid attack windows), "
          f"{P['subnet_24'].nunique()} anon /24")


if __name__ == "__main__":
    main()
