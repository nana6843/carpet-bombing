#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
baselines/make_labeled_features.py
==================================
One-off preparation step: build a PUBLIC-SAFE labeled feature table for the
baseline demo (`baselines.py`), from the production feature CSVs.

The production features (../../experiments/exp_out/feat/w60_k1/feat_*.csv) are the
exact labeled (/24, 60-s window) samples used for the paper's Table IV. Their
only sensitive field is `subnet_24` (a real customer /24). We map it through the
SAME Crypto-PAn secret that anonymized exports_anon, keep just the columns the
baselines need, add the temporal split, and write `labeled_features.csv`.

Output columns:
  subnet_24 (anon), day, split, y, gt_kind, gt_scenario,
  max_host_bps, bps, uniformity_E, and the 17 baseline features.

Run once:  ../../venv/bin/python make_labeled_features.py
"""
import hashlib, hmac, os, socket, struct
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
FEAT_DIR = os.path.join(HERE, "..", "..", "experiments", "exp_out", "feat", "w60_k1")
SECRET = bytes.fromhex(open(os.path.join(HERE, "..", "..", "ip_anon_secret.key")).read().strip())
OUT = os.path.join(HERE, "labeled_features.csv")

TRAIN_DAYS = ["2026-10-17", "2026-10-18", "2026-10-19", "2026-10-20", "2026-10-21"]

BASELINE_17 = ["flow_count", "pkt_count", "byte_count", "uniq_src_ip", "uniq_src_port",
               "uniq_dst_port", "proto_div", "syn_pkts", "fin_pkts", "icmp_pkts", "udp_pkts",
               "bytes_per_pkt", "pkts_per_flow", "dports_per_flow", "src_spread",
               "dst_count", "dst_count_ratio"]
KEEP = ["window_start", "subnet_24", "max_host_bps", "bps", "uniformity_E",
        "gt_scenario", "gt_kind"] + BASELINE_17

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


def load(path, split, day=None):
    df = pd.read_csv(path, usecols=[c for c in KEEP if c])
    df["day"] = day if day else pd.to_datetime(df["window_start"]).dt.strftime("%Y-%m-%d")
    df["split"] = split
    return df


def main():
    parts = [load(os.path.join(FEAT_DIR, f"feat_{d}.csv"), "train", d) for d in TRAIN_DAYS]
    parts.append(load(os.path.join(FEAT_DIR, "feat_test.csv"), "test"))
    F = pd.concat(parts, ignore_index=True)

    F["gt_kind"] = F["gt_kind"].fillna("normal").astype(str)
    F["y"] = (F["gt_kind"] == "carpet_bombing").astype(int)        # positive class (common.py)
    uniq = {s: anon_subnet24(s) for s in F["subnet_24"].unique()}  # anonymize the only sensitive field
    F["subnet_24"] = F["subnet_24"].map(uniq)

    cols = ["subnet_24", "day", "split", "y", "gt_kind", "gt_scenario",
            "max_host_bps", "bps", "uniformity_E"] + BASELINE_17
    F[cols].to_csv(OUT, index=False)
    print(f"wrote {OUT}: {len(F):,} rows "
          f"({int(F['y'].sum()):,} carpet-bombing, {F['subnet_24'].nunique()} anon /24)")
    print("  train:", int((F['split'] == 'train').sum()), "| test:", int((F['split'] == 'test').sum()))


if __name__ == "__main__":
    main()
