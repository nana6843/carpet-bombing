#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_features_v2.py
======================
Single self-contained file that computes the **24 features** per
(destination /24 subnet x 60-second window) directly from the anonymized flow
CSVs in `exports_anon/` (source/destination IPs anonymized with Crypto-PAn,
prefix-preserving, 1:1 -- the paper's SS III-C method -- so every prefix length
is kept: a real /24 maps to a distinct anon /24 and all per-/24 and src_spread
structure, counts and attack patterns are identical to the real data).

Input columns read from exports_anon/flows_*.csv:
    ts, te, td, sa, da, sp, dp, pr, flg, ipkt, ibyt

The 24 features (see experiments/feature_table.md and the paper's TABLE II):
  A. 17 baseline features (SS III-D) : 13 direct + 4 derived
  B.  5 sampling-aware features (SS III-E)
  C.  2 bandwidth-change features    : z_B, bw_jump

Each DERIVED feature has its own function (feat_*), for readability/testing:
    feat_bytes_per_pkt, feat_pkts_per_flow, feat_dports_per_flow,   (baseline derived)
    feat_dst_count_ratio,
    feat_dst_count_est, feat_uniformity_E, feat_dark_ratio_D,       (sampling-aware)
    feat_reflector_share_R, feat_asymmetry_A,
    feat_z_B, feat_bw_jump                                          (bandwidth-change)

Reference implementation: ../netflow_collector_v2.py (compute_features,
StatefulScorer, robust-z eq.6) and ../experiments/common.py (bw_jump).

Memory note: data is aggregated **one day file at a time** (per-flow data for a
single day is small), then the compact per-(window, subnet) tables are concatenated
and the temporal features / robust-z baseline are computed on that small table.
This keeps peak RAM low (~hundreds of MB) even for millions of flows.

Faithfulness notes vs the production collector / the paper:
  * Counters are treated as "sampled" (raw sampled values); vp = ipkt*N, vb = ibyt*N.
  * All flows are treated as ingress (subnet = da/24). out_bytes for asymmetry_A is
    the bytes LEAVING that same /24 (sa/24 == subnet).
  * z_B (eq.6): the per-(subnet, 5-min slot) median/MAD baseline is learned from the
    CALIBRATION days only (default: the first 5 dates), pooling all windows of the
    same day type within +/-30 minutes, with fallback to the subnet median and then
    the global median -- matching the paper. A scale-aware epsilon keeps z finite.
  * dst_count_ratio uses the k previous windows (history); the production collector
    restricts history to non-alarm windows from CUSUM. Identical when no alarm fires.
  * dark_ratio_D needs the active-host set U(s). With --customer-prefixes-anon the
    monitored /24 set is known and U(s) is built (default) from egress senders on the
    calibration days (paper SS III-C: "senders, not receivers"); --active-from prefix
    uses allocated customer addresses instead, and --active-hosts CSV supplies U(s)
    directly. Without any of these the value is NaN (collector with active_hosts=None).

Usage:
    python extract_features_v2.py                       # read ../exports_anon -> ./features_v2.csv
    python extract_features_v2.py --input ../exports_anon --out features_v2.csv
    python extract_features_v2.py --days 2026-10-17 2026-10-18
    python extract_features_v2.py --calibration-days 2026-10-17 2026-10-18 2026-10-19 2026-10-20 2026-10-21
"""

import argparse
import glob
import os
import socket
import struct
import sys
from collections import deque

import numpy as np
import pandas as pd

# ---------------------------- Constants (same as the collector) ----------------------------
WINDOW_SEC    = 60
SLOT_SEC      = 300            # 5-minute time-of-day slot for the robust-z baseline
N_SLOTS       = 86400 // SLOT_SEC   # 288 slots per day
SAMPLING_N    = 10_000        # router sampling ratio (1:N)
USABLE_HOSTS  = 254           # |s| for a /24 (usable host count)
RATIO_K       = 5             # k for dst_count_ratio (eq.3)
BW_K          = 10            # k for bw_jump
CHAO_MIN_PKTS = 10            # below this, Chao1 falls back to dst_count
MAX_SPAN_WIN  = 10            # cap on windows per flow (guard against broken timestamps)
POOL_HALF     = 6            # +/-30 min = +/-6 slots of 5 min for baseline pooling
REFLECTOR_PORTS = np.array([53, 111, 123, 137, 161, 389, 1434, 1900, 3702, 11211])  # paper SS III-E

TCP_FLAG_BITS = {"F": 1, "S": 2, "R": 4, "P": 8, "A": 16, "U": 32, "E": 64, "C": 128}
PROTO_NAMES   = {"TCP": 6, "UDP": 17, "ICMP": 1, "IGMP": 2, "GRE": 47, "ESP": 50,
                 "ICMP6": 58, "SCTP": 132}


def log(msg):
    print(f"[v2] {msg}", file=sys.stderr, flush=True)


# ============================ 1. INPUT PARSING ============================

def ipv4_to_int(s: pd.Series) -> np.ndarray:
    """IPv4 string -> uint32 (NaN for non-IPv4)."""
    parts = s.astype(str).str.strip().str.split(".", expand=True)
    octs = parts.reindex(columns=range(4)).apply(pd.to_numeric, errors="coerce")
    bad = octs.isna().any(axis=1) | (octs > 255).any(axis=1) | (octs < 0).any(axis=1)
    val = (octs[0] * 16777216 + octs[1] * 65536 + octs[2] * 256 + octs[3]).to_numpy(dtype=float)
    val[bad.to_numpy()] = np.nan
    return val


def parse_time(s: pd.Series) -> np.ndarray:
    """'2026-10-17 16:00:44' (UTC) or epoch -> epoch seconds (float)."""
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() > 0.99:
        return num.to_numpy(dtype=float)
    dt = pd.to_datetime(s.astype(str).str.strip(), errors="coerce", format="mixed")
    return ((dt - pd.Timestamp("1970-01-01")).dt.total_seconds()).to_numpy(dtype=float)


def parse_proto(s: pd.Series) -> np.ndarray:
    """Protocol name ('TCP'/'UDP'/...) or number -> IANA protocol number."""
    num = pd.to_numeric(s, errors="coerce")
    rest = num.isna()
    if rest.any():
        num[rest] = s[rest].astype(str).str.strip().str.upper().map(PROTO_NAMES)
    return num.fillna(0).to_numpy(dtype=np.int64)


def parse_flag_bits(s: pd.Series) -> np.ndarray:
    """TCP flags '...AP.S.', a number, or '0x12' -> integer bitmask."""
    num = pd.to_numeric(s, errors="coerce")
    out = num.fillna(0).to_numpy(dtype=np.int64)
    rest = num.isna() & s.notna()
    if rest.any():
        def conv(v):
            v = str(v).strip()
            if v.lower().startswith("0x"):
                try:
                    return int(v, 16)
                except ValueError:
                    return 0
            return sum(TCP_FLAG_BITS.get(ch, 0) for ch in set(v.upper()))
        out[rest.to_numpy()] = s[rest].map(conv).to_numpy(dtype=np.int64)
    return out


def load_one_file(path, sampling=SAMPLING_N) -> pd.DataFrame:
    """Read one exports_anon CSV, parse, drop non-IPv4, apply sampling weights.
    Output columns: ts, te, sa, da(int), sp, dp, proto, flags, samp, vp, vb."""
    df = pd.read_csv(path, dtype=str)
    if len(df) == 0:
        return pd.DataFrame()
    sa = ipv4_to_int(df["sa"]); da = ipv4_to_int(df["da"])
    out = pd.DataFrame({
        "ts":    parse_time(df["ts"]),
        "te":    parse_time(df["te"]) if "te" in df else parse_time(df["ts"]),
        "sa":    sa, "da": da,
        "sp":    pd.to_numeric(df["sp"], errors="coerce").fillna(0).to_numpy(np.int64),
        "dp":    pd.to_numeric(df["dp"], errors="coerce").fillna(0).to_numpy(np.int64),
        "proto": parse_proto(df["pr"]),
        "flags": parse_flag_bits(df["flg"]) if "flg" in df else 0,
        "pkts":  pd.to_numeric(df["ipkt"], errors="coerce").to_numpy(float),
        "bytes": pd.to_numeric(df["ibyt"], errors="coerce").to_numpy(float),
    })
    bad = out[["ts", "sa", "da", "pkts", "bytes"]].isna().any(axis=1)
    out = out[~bad].copy()
    out["te"] = np.where(np.isnan(out["te"]), out["ts"], np.maximum(out["te"], out["ts"]))
    out["sa"] = out["sa"].astype(np.int64); out["da"] = out["da"].astype(np.int64)
    # sampling weights: "sampled" counters -> vp/vb = value * N, samp = sampled packets
    out["samp"] = out["pkts"]
    out["vp"]   = out["pkts"] * sampling
    out["vb"]   = out["bytes"] * sampling
    return out


# ============================ 2. WINDOW EXPANSION (SS III-C) ============================

def expand_windows(rec: pd.DataFrame, W=WINDOW_SEC) -> pd.DataFrame:
    """Split each flow into the non-overlapping 60-s windows it covers. vp/vb are split
    proportionally to the time overlap; the sampled packet count (samp) is assigned
    whole to the window with the largest overlap. Reference: collector _expand()."""
    ts, te = rec["ts"].to_numpy(), rec["te"].to_numpy()
    w0 = np.floor(ts / W).astype(np.int64)
    w1 = np.minimum(np.floor(te / W).astype(np.int64), w0 + MAX_SPAN_WIN - 1)
    n = (w1 - w0 + 1)

    rep = np.repeat(np.arange(len(rec)), n)
    ex = rec.iloc[rep].reset_index(drop=True)
    offs = np.arange(len(rep)) - np.repeat(np.cumsum(n) - n, n)
    w = np.repeat(w0, n) + offs
    ex["w"] = w

    if (n > 1).any():
        tsr, ter = ts[rep], te[rep]
        dur = ter - tsr
        ov = np.clip(np.minimum(ter, (w + 1) * W) - np.maximum(tsr, w * W), 0, None)
        frac = np.where(dur > 0, ov / np.where(dur > 0, dur, 1), 1.0)
        frac = np.where(np.repeat(n, n) == 1, 1.0, frac)
        best = pd.Series(ov).groupby(rep).transform("max").to_numpy()
        is_best = (ov == best)
        first_best = pd.Series(is_best).groupby(rep).cumsum().to_numpy() == 1
        keep = is_best & first_best
        ex["vp"]   = ex["vp"].to_numpy() * frac
        ex["vb"]   = ex["vb"].to_numpy() * frac
        ex["samp"] = np.where(keep, ex["samp"].to_numpy(), 0.0)
    return ex


# ============================ 3. PER-DAY AGGREGATION ============================
# Produces the 13 DIRECT features plus helper columns the derived features need.

def aggregate_day(flows: pd.DataFrame, active_hosts=None) -> pd.DataFrame:
    """Aggregate one day's flows into one row per (w, subnet). Returns a flat DataFrame
    with the 13 direct features and the helper columns: refl_bytes, m_sampled, f1, f2,
    ent_sum (for uniformity_E), dark_sum (for dark_ratio_D), out_bytes (for asymmetry_A)."""
    ex = expand_windows(flows)
    ex = ex.assign(
        subnet=ex["da"].to_numpy() >> 8,
        host=ex["da"].to_numpy() & 0xFF,
        s24=ex["sa"].to_numpy() >> 8,
        flow=1,
    )
    fl, pr, vp = ex["flags"].to_numpy(), ex["proto"].to_numpy(), ex["vp"].to_numpy()
    tcp = pr == 6
    ex["syn"]  = np.where(tcp & ((fl & 2) > 0), vp, 0.0)   # SYN bit = 2
    ex["fin"]  = np.where(tcp & ((fl & 1) > 0), vp, 0.0)   # FIN bit = 1
    ex["icmp"] = np.where(pr == 1, vp, 0.0)
    ex["udp"]  = np.where(pr == 17, vp, 0.0)
    sp, dp = ex["sp"].to_numpy(), ex["dp"].to_numpy()
    refl = (pr == 17) & (np.isin(sp, REFLECTOR_PORTS) | ((sp == 0) & (dp == 0)))
    ex["refl"] = np.where(refl, ex["vb"].to_numpy(), 0.0)

    key = ["w", "subnet"]
    g = ex.groupby(key, sort=True)
    F = g.agg(
        flow_count=("flow", "sum"),
        pkt_count=("vp", "sum"),
        byte_count=("vb", "sum"),
        uniq_src_ip=("sa", "nunique"),
        uniq_src_port=("sp", "nunique"),
        uniq_dst_port=("dp", "nunique"),
        proto_div=("proto", "nunique"),
        syn_pkts=("syn", "sum"),
        fin_pkts=("fin", "sum"),
        icmp_pkts=("icmp", "sum"),
        udp_pkts=("udp", "sum"),
        src_spread=("s24", "nunique"),
        refl_bytes=("refl", "sum"),
        m_sampled=("samp", "sum"),
    )

    # host level: dst_count, f1/f2 (singleton/doubleton), entropy sum, dark host count
    H = (ex.groupby(key + ["host"], sort=False)
           .agg(samp=("samp", "sum"), vb=("vb", "sum"))
           .reset_index())
    H["one"] = (H["samp"] == 1).astype(int)
    H["two"] = (H["samp"] == 2).astype(int)
    tot = H.groupby(key)["vb"].transform("sum").to_numpy()
    q = np.where(tot > 0, H["vb"].to_numpy() / np.where(tot > 0, tot, 1), 0.0)
    H["plogq"] = np.where(q > 0, -q * np.log(np.where(q > 0, q, 1)), 0.0)
    if active_hosts is not None:
        H = H.merge(active_hosts.assign(known=1), on=["subnet", "host"], how="left")
        H["dark"] = H["known"].isna().astype(int)
    hg = H.groupby(key)
    F["dst_count"] = hg.size()
    F["f1"] = hg["one"].sum()
    F["f2"] = hg["two"].sum()
    F["ent_sum"] = hg["plogq"].sum()
    F["dark_sum"] = hg["dark"].sum() if active_hosts is not None else np.nan

    # out_bytes per /24: bytes leaving that subnet (sa/24 == subnet)
    outb = ex.groupby(["w", "s24"])["vb"].sum()
    outb.index = outb.index.rename(["w", "subnet"])
    F["out_bytes"] = outb.reindex(F.index).fillna(0.0)

    return F.reset_index()


def merge_duplicate_windows(F: pd.DataFrame) -> pd.DataFrame:
    """Merge any (w, subnet) rows duplicated across day-file boundaries (midnight-spanning
    flows). Additive columns are summed; count-like columns take the max (tiny boundary effect)."""
    if not F.duplicated(["w", "subnet"]).any():
        return F
    add = ["flow_count", "pkt_count", "byte_count", "syn_pkts", "fin_pkts", "icmp_pkts",
           "udp_pkts", "refl_bytes", "m_sampled", "f1", "f2", "ent_sum", "dark_sum", "out_bytes"]
    mx  = ["uniq_src_ip", "uniq_src_port", "uniq_dst_port", "proto_div", "src_spread", "dst_count"]
    agg = {c: "sum" for c in add}
    agg.update({c: "max" for c in mx})
    if "date" in F.columns:
        agg["date"] = "first"
    return F.groupby(["w", "subnet"], as_index=False).agg(agg)


# ============================ 4. ONE FUNCTION PER DERIVED FEATURE ============================
# ---- Baseline derived (SS III-D) ----

def feat_bytes_per_pkt(F):
    """#12 bytes_per_pkt = byte_count / pkt_count."""
    return F["byte_count"] / F["pkt_count"].where(F["pkt_count"] > 0)


def feat_pkts_per_flow(F):
    """#13 pkts_per_flow = pkt_count / flow_count."""
    return F["pkt_count"] / F["flow_count"]


def feat_dports_per_flow(F):
    """#14 dports_per_flow = uniq_dst_port / flow_count."""
    return F["uniq_dst_port"] / F["flow_count"]


def feat_dst_count_ratio(F, k=RATIO_K):
    """#17 dst_count_ratio = dst_count(t) / mean dst_count over the k previous windows on the
    same /24 (eq.3). Empty windows in between count as dst_count 0. When history is empty or
    its mean is 0, the denominator is 1 (ratio = dst_count). Reference: StatefulScorer.score()."""
    out = np.full(len(F), np.nan)
    w_all = F["w"].to_numpy(np.int64)
    dc_all = F["dst_count"].to_numpy(float)
    sub_all = F["subnet"].to_numpy()
    for s in np.unique(sub_all):
        idx = np.where(sub_all == s)[0]
        order = idx[np.argsort(w_all[idx])]
        ws, dc = w_all[order], dc_all[order]
        hist = deque(maxlen=k)
        last_w = None
        for pos, j in enumerate(order):
            if last_w is not None:
                gap = ws[pos] - last_w - 1
                for _ in range(min(max(gap, 0), k)):
                    hist.append(0.0)
            mean = (sum(hist) / len(hist)) if hist else 0.0
            out[j] = dc[pos] / mean if mean > 0 else dc[pos]
            hist.append(dc[pos])
            last_w = ws[pos]
    return out


# ---- Sampling-aware (SS III-E) ----

def feat_dst_count_est(F):
    """#18 Bias-corrected Chao1 estimate (eq.4). Gate: m<10 -> dst_count. Upper bound
    max(254, dst_count). Reference: compute_features()."""
    m    = F["m_sampled"].to_numpy(float)
    f1   = F["f1"].to_numpy(float)
    f2   = F["f2"].to_numpy(float)
    hobs = F["dst_count"].to_numpy(float)
    corr = np.where(m > 0, (m - 1) / np.where(m > 0, m, 1), 0.0) * f1 * (f1 - 1) / (2 * (f2 + 1))
    cap = np.maximum(USABLE_HOSTS, hobs)
    est = np.minimum(cap, hobs + corr)
    return np.where(m < CHAO_MIN_PKTS, hobs, est)


def feat_uniformity_E(F):
    """#19 Normalized per-host byte entropy: H(q)/log(dst_count), in [0, 1]. 1 = even spread.
    Uses ent_sum = sum_h -q_h log q_h precomputed per (w, subnet) in aggregate_day()."""
    hobs = F["dst_count"].to_numpy(float)
    ent = F["ent_sum"].to_numpy(float)
    e = np.where(hobs > 1, ent / np.log(np.where(hobs > 1, hobs, 2)), 0.0)
    return np.clip(e, 0.0, 1.0)   # bounded in [0,1]; clip float/boundary artifacts


def feat_dark_ratio_D(F):
    """#20 Share of hit destinations that are 'dark', i.e. NOT in the active-host set U(s).
    U(s) is, by default, the hosts seen as a SOURCE in outbound records on the calibration
    days (paper SS III-C); NaN when no active-host set is available."""
    d = F["dark_sum"].to_numpy() / F["dst_count"].to_numpy()
    return np.clip(d, 0.0, 1.0)   # NaN stays NaN when no active-host list given


def feat_reflector_share_R(F):
    """#21 reflector_share_R = bytes from reflector ports / total bytes."""
    return F["refl_bytes"] / F["byte_count"].where(F["byte_count"] > 0)


def feat_asymmetry_A(F):
    """#22 asymmetry_A = inbound byte_count / (out_bytes + 1), where out_bytes is the bytes
    leaving that same /24 (sa/24 == subnet). Victims under attack do not reply -> large A."""
    return F["byte_count"].to_numpy() / (F["out_bytes"].to_numpy() + 1.0)


# ---- Bandwidth-change ----

def slot_of(w, window=WINDOW_SEC, tz_offset=0, day_type=True):
    """5-minute time-of-day slot (0..287). With day_type, weekend windows are offset by
    N_SLOTS (288..575) so weekdays and weekends keep separate baselines (paper SS III-F)."""
    t = w * window + tz_offset
    slot = ((t % 86400) // SLOT_SEC).astype(np.int64)
    if day_type:
        dow = (np.floor_divide(t, 86400) + 3) % 7      # 1970-01-01 = Thursday; Monday = 0
        slot = slot + np.where(dow >= 5, N_SLOTS, 0)
    return slot


def _median_abs_dev(frame, key, val):
    """Grouped MAD = median(|x - median(x)|), computed vectorized."""
    med = frame.groupby(key)[val].transform("median")
    frame = frame.assign(_ad=(frame[val] - med).abs())
    return frame.groupby(key)["_ad"].median()


def build_zB_baseline(F, cal_mask, pool_half=POOL_HALF, eps_frac=1e-3):
    """Learn the robust-z baseline for byte count B per (subnet, slot) from calibration
    windows only, pooling +/-pool_half slots within the same day-type band (paper eq.6).
    Returns a lookup object with slot-level, subnet-level and global median/MAD, plus eps."""
    cal = F.loc[cal_mask, ["subnet", "slot", "byte_count"]].copy()
    if len(cal) == 0:
        raise SystemExit("no calibration windows found; check --calibration-days")

    # pool each calibration window into neighboring slots (within the same day-type band)
    base = (cal["slot"].to_numpy() % N_SLOTS)
    band = (cal["slot"].to_numpy() // N_SLOTS) * N_SLOTS
    sub  = cal["subnet"].to_numpy()
    B    = cal["byte_count"].to_numpy()
    subs, slots, vals = [], [], []
    for d in range(-pool_half, pool_half + 1):
        subs.append(sub)
        slots.append(band + ((base + d) % N_SLOTS))
        vals.append(B)
    pooled = pd.DataFrame({"subnet": np.concatenate(subs),
                           "slot":   np.concatenate(slots),
                           "B":      np.concatenate(vals)})
    med = pooled.groupby(["subnet", "slot"])["B"].median()
    mad = _median_abs_dev(pooled, ["subnet", "slot"], "B")
    cnt = pooled.groupby(["subnet", "slot"])["B"].size()

    # fallbacks: per-subnet, then global (over calibration windows)
    smed = cal.groupby("subnet")["byte_count"].median()
    smad = _median_abs_dev(cal.rename(columns={"byte_count": "B"}), ["subnet"], "B")
    gmed = float(cal["byte_count"].median())
    gmad = float((cal["byte_count"] - gmed).abs().median())
    eps = eps_frac * max(gmed, 1.0)    # scale-aware epsilon (paper: +eps in the denominator)
    return {"med": med, "mad": mad, "cnt": cnt, "smed": smed, "smad": smad,
            "gmed": gmed, "gmad": gmad, "eps": eps, "min_cnt": pool_half}


def feat_z_B(F, baseline):
    """#23 z_B = (B - median) / (1.4826*MAD + eps), robust z-score of byte count against the
    per-(subnet, slot) calibration baseline, with subnet and global fallback (paper eq.6)."""
    bl = baseline
    key = list(zip(F["subnet"].to_numpy(), F["slot"].to_numpy()))
    med = bl["med"].reindex(key).to_numpy()
    mad = bl["mad"].reindex(key).to_numpy()
    cnt = bl["cnt"].reindex(key).to_numpy()

    # fall back to subnet-level where the slot has too little data
    sub = F["subnet"].to_numpy()
    smed = bl["smed"].reindex(sub).to_numpy()
    smad = bl["smad"].reindex(sub).to_numpy()
    need = ~(cnt >= 1) | np.isnan(med)
    med = np.where(need, smed, med)
    mad = np.where(need, smad, mad)

    # then global
    med = np.where(np.isnan(med), bl["gmed"], med)
    mad = np.where(np.isnan(mad), bl["gmad"], mad)

    # Floor the MAD at a fraction of the local median so a near-zero MAD (quiet subnet with
    # near-identical calibration bytes) cannot blow the z-score up. Keeps z bounded and robust.
    denom = 1.4826 * np.maximum(mad, 0.1 * np.abs(med)) + bl["eps"]
    return (F["byte_count"].to_numpy() - med) / denom


def feat_bw_jump(F, k=BW_K):
    """#24 bw_jump = log1p(bytes now) - median log1p(bytes) over the k previous windows on the
    same /24. Missing windows count as 0 bytes. Reference: experiments/common.py bw_jump()."""
    w = F["w"].to_numpy(np.int64); w = w - w.min()
    B = np.log1p(F["byte_count"].to_numpy(float))
    out = np.full(len(F), np.nan)
    sub_arr = F["subnet"].to_numpy()
    for s in np.unique(sub_arr):
        idx = np.where(sub_arr == s)[0]
        ww = w[idx]
        dense = np.zeros(ww.max() + 1)
        dense[ww] = B[idx]
        med = pd.Series(dense).shift(1).rolling(k, min_periods=1).median().to_numpy()
        out[idx] = B[idx] - med[ww]
    return out


# ============================ 5. CUSTOMER PREFIXES -> ANON MONITORED SET ============================
# The flows are anonymized with Crypto-PAn (prefix-preserving). Normally we just pass the
# anon customer prefixes directly (--customer-prefixes-anon customer_prefixes_anon.txt), since
# they live in the same anon space as the flows. Alternatively the real prefixes + the 1:1 key
# (ip_anon_key.csv) classify every IP in real space (monitored /24? allocated customer host?)
# and record the result in ANON space. Because Crypto-PAn preserves EVERY prefix length, a real
# /24 maps to exactly one anon /24 (no straddling), so per-anon-/24 == per-real-/24 monitoring.

def _ip_to_int_array(series):
    return series.map(lambda x: struct.unpack("!I", socket.inet_aton(x))[0]).to_numpy(np.int64)


def load_prefix_intervals(path):
    """Read a customer prefix list (one CIDR per line, '#' comments) -> sorted (starts, ends)."""
    import ipaddress
    starts, ends = [], []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        net = ipaddress.ip_network(line.split()[0], strict=False)
        starts.append(int(net.network_address))
        ends.append(int(net.broadcast_address))
    starts = np.array(starts, dtype=np.int64)
    ends = np.array(ends, dtype=np.int64)
    order = np.argsort(starts)
    return starts[order], ends[order]


def in_prefixes(ips, starts, ends):
    """Vectorized membership test: is each ip inside any [start, end] prefix interval?"""
    idx = np.searchsorted(starts, ips, side="right") - 1
    ok = idx >= 0
    res = np.zeros(len(ips), dtype=bool)
    res[ok] = ips[ok] <= ends[idx[ok]]
    return res


def build_prefix_maps(prefix_path, key_path):
    """From customer prefixes (real space) + the anon key, return:
      * monitored_anon_24: set of anon /24 subnet ids whose real /24 contains customer prefixes,
      * active_hosts: DataFrame[subnet, host] of allocated customer addresses, in ANON space."""
    starts, ends = load_prefix_intervals(prefix_path)
    monitored_real_24 = set((starts >> 8).tolist()) | set((ends >> 8).tolist())
    key = pd.read_csv(key_path)
    oi = _ip_to_int_array(key["original_ip"])
    pi = _ip_to_int_array(key["anon_ip"])
    # monitored anon /24 = anon /24 of any seen IP whose real /24 is monitored
    real24 = oi >> 8
    is_mon = np.fromiter((r in monitored_real_24 for r in real24), dtype=bool, count=len(real24))
    monitored_anon_24 = set(np.unique(pi[is_mon] >> 8).tolist())
    # allocated (active) hosts = seen IPs that fall inside a customer prefix, mapped to anon space
    alloc = in_prefixes(oi, starts, ends)
    active = (pd.DataFrame({"subnet": (pi[alloc] >> 8), "host": (pi[alloc] & 0xFF)})
              .drop_duplicates().reset_index(drop=True))
    return monitored_anon_24, active


def build_from_anon_prefixes(prefix_path):
    """From customer prefixes ALREADY in anon space (Crypto-PAn output; e.g.
    customer_prefixes_anon.txt), build (monitored_anon_24, active_hosts) directly -- no key
    needed, so the public can reproduce from the shared anonymized data alone."""
    starts, ends = load_prefix_intervals(prefix_path)
    monitored = set()
    subs, hosts = [], []
    for s, e in zip(starts.tolist(), ends.tolist()):
        for ip in range(s, e + 1):          # allocated addresses in this prefix
            subs.append(ip >> 8)
            hosts.append(ip & 0xFF)
            monitored.add(ip >> 8)
    active = pd.DataFrame({"subnet": subs, "host": hosts}).drop_duplicates().reset_index(drop=True)
    return monitored, active


def active_hosts_from_egress(paths, calibration_dates, monitored_subnets) -> pd.DataFrame:
    """Build the active-host set U(s) the way the paper does (SS III-C): the hosts of the
    monitored /24s that appear as a SOURCE address in outbound records (sa in a monitored
    /24) during the calibration days. Senders are used rather than receivers, because
    background Internet scanning reaches unallocated addresses, so a receiver-based set
    would cover almost the whole /24 and push the dark-host ratio to zero."""
    mon = set(int(s) for s in monitored_subnets)
    seen = set()
    for p in paths:
        if calibration_dates and date_of_path(p) not in calibration_dates:
            continue
        df = pd.read_csv(p, usecols=["sa"], dtype=str)
        if len(df) == 0:
            continue
        sa = ipv4_to_int(df["sa"])
        sa = sa[~np.isnan(sa)].astype(np.int64)         # drop non-IPv4
        sub = (sa >> 8); host = (sa & 0xFF)
        m = np.fromiter((int(s) in mon for s in sub), dtype=bool, count=len(sub))
        seen.update(zip(sub[m].tolist(), host[m].tolist()))
    if not seen:
        return pd.DataFrame({"subnet": [], "host": []})
    arr = np.array(sorted(seen), dtype=np.int64)
    return pd.DataFrame({"subnet": arr[:, 0], "host": arr[:, 1]})


# ============================ 6. ORCHESTRATION ============================

def subnet24_str(sub):
    return f"{socket.inet_ntoa(struct.pack('!I', int(sub) << 8))}/24"


BASELINE_17 = ["flow_count", "pkt_count", "byte_count", "uniq_src_ip", "uniq_src_port",
               "uniq_dst_port", "proto_div", "syn_pkts", "fin_pkts", "icmp_pkts", "udp_pkts",
               "bytes_per_pkt", "pkts_per_flow", "dports_per_flow", "src_spread",
               "dst_count", "dst_count_ratio"]
PROPOSED_5  = ["dst_count_est", "uniformity_E", "dark_ratio_D", "reflector_share_R", "asymmetry_A"]
BW_2        = ["z_B", "bw_jump"]
ALL_24      = BASELINE_17 + PROPOSED_5 + BW_2


def date_of_path(path):
    """flows_2026-10-17.csv -> '2026-10-17'."""
    base = os.path.basename(path)
    return base.replace("flows_", "").replace(".csv", "")


def extract(paths, calibration_dates, sampling=SAMPLING_N, tz_offset=0,
            day_type=True, active_hosts=None, monitored_subnets=None) -> pd.DataFrame:
    # Aggregate one day at a time (memory-safe), then combine the small per-window tables.
    log(f"1/4 aggregate per day ({len(paths)} files) ...")
    parts = []
    for p in paths:
        flows = load_one_file(p, sampling=sampling)
        if len(flows) == 0:
            log(f"    {os.path.basename(p)}: empty, skipped")
            continue
        day = aggregate_day(flows, active_hosts=active_hosts)
        day["date"] = date_of_path(p)
        parts.append(day)
        log(f"    {os.path.basename(p)}: {len(flows)} flows -> {len(day)} (window x subnet)")
        del flows
    if not parts:
        sys.exit("no data aggregated")
    F = merge_duplicate_windows(pd.concat(parts, ignore_index=True))
    log(f"    combined: {len(F)} rows (window x subnet)")

    if monitored_subnets is not None:
        before = len(F)
        F = F[F["subnet"].isin(monitored_subnets)].reset_index(drop=True)
        log(f"    filtered to {len(monitored_subnets)} monitored /24: "
            f"{len(F)}/{before} rows kept, {F['subnet_24'].nunique() if 'subnet_24' in F else F['subnet'].nunique()} subnets")

    log("2/4 per-row derived features ...")
    F["bytes_per_pkt"]     = feat_bytes_per_pkt(F)
    F["pkts_per_flow"]     = feat_pkts_per_flow(F)
    F["dports_per_flow"]   = feat_dports_per_flow(F)
    F["dst_count_est"]     = feat_dst_count_est(F)
    F["uniformity_E"]      = feat_uniformity_E(F)
    F["dark_ratio_D"]      = feat_dark_ratio_D(F)
    F["reflector_share_R"] = feat_reflector_share_R(F)
    F["asymmetry_A"]       = feat_asymmetry_A(F)

    log("3/4 temporal + robust-z features ...")
    F["slot"] = slot_of(F["w"].to_numpy(), window=WINDOW_SEC, tz_offset=tz_offset, day_type=day_type)
    # robust-z baseline from calibration days only (paper eq.6)
    if calibration_dates:
        cal_mask = F["date"].isin(calibration_dates).to_numpy()
    else:
        cal_mask = np.ones(len(F), dtype=bool)   # fall back to in-sample
    log(f"    z_B baseline from {int(cal_mask.sum())} calibration windows "
        f"(dates: {', '.join(calibration_dates) if calibration_dates else 'all (in-sample)'})")
    baseline = build_zB_baseline(F, cal_mask)
    F["z_B"] = feat_z_B(F, baseline)
    F["bw_jump"] = feat_bw_jump(F)
    F["dst_count_ratio"] = feat_dst_count_ratio(F)

    log("4/4 finalize output ...")
    F["window_start"] = pd.to_datetime(F["w"] * WINDOW_SEC, unit="s", utc=True).dt.strftime("%Y-%m-%d %H:%M:%S")
    F["subnet_24"] = [subnet24_str(s) for s in F["subnet"].to_numpy()]
    cols = ["window_start", "w", "subnet_24", "slot"] + ALL_24 + ["f1", "f2", "m_sampled"]
    return F[cols].sort_values(["w", "subnet_24"]).reset_index(drop=True)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Extract the 24 features from exports_anon")
    ap.add_argument("--input", default=os.path.join(here, "..", "exports_anon"),
                    help="folder with flows_*.csv (default ../exports_anon)")
    ap.add_argument("--out", default=os.path.join(here, "features_v2.csv"))
    ap.add_argument("--days", nargs="*", help="limit to these dates, e.g. 2026-10-17 2026-10-18")
    ap.add_argument("--calibration-days", nargs="*",
                    help="dates used to learn the z_B baseline (default: first 5 dates present)")
    ap.add_argument("--sampling", type=int, default=SAMPLING_N)
    ap.add_argument("--tz-offset", type=int, default=0, help="seconds offset from UTC for slots")
    ap.add_argument("--no-day-type", action="store_true", help="do not split baseline by weekday/weekend")
    ap.add_argument("--active-hosts", help="CSV subnet,host of the active-host set (for dark_ratio_D)")
    ap.add_argument("--active-from", choices=["egress", "prefix"], default="egress",
                    help="how the dark-host set U(s) is built: 'egress' = hosts seen as a SOURCE in "
                         "outbound records on the calibration days (paper SS III-C, the default); "
                         "'prefix' = allocated customer addresses from the prefix list")
    ap.add_argument("--customer-prefixes-anon", help="customer prefixes ALREADY in anon space "
                    "(e.g. customer_prefixes_anon.txt); gives the monitored /24 set and (with "
                    "--active-from prefix) the allocated hosts. NO key needed. Recommended for Crypto-PAn data.")
    ap.add_argument("--customer-prefixes", help="customer prefix list (REAL IP CIDRs); needs --anon-key "
                    "to map into the anon space of the data")
    ap.add_argument("--anon-key", default=os.path.join(here, "..", "ip_anon_key.csv"),
                    help="key CSV (original_ip,anon_ip) to map real prefixes into anon space")
    args = ap.parse_args()

    paths = sorted(glob.glob(os.path.join(args.input, "flows_*.csv")))
    if args.days:
        paths = [p for p in paths if date_of_path(p) in args.days]
    if not paths:
        sys.exit(f"no flows_*.csv in {args.input}")

    all_dates = [date_of_path(p) for p in paths]
    cal_dates = args.calibration_days if args.calibration_days else all_dates[:5]
    cal_dates = [d for d in cal_dates if d in all_dates]
    log(f"{len(paths)} input files; calibration dates: {', '.join(cal_dates)}")

    active, monitored, alloc = None, None, None
    if args.customer_prefixes_anon:
        monitored, alloc = build_from_anon_prefixes(args.customer_prefixes_anon)
        log(f"anon customer prefixes -> {len(monitored)} monitored /24, {len(alloc)} allocated hosts")
    elif args.customer_prefixes:
        monitored, alloc = build_prefix_maps(args.customer_prefixes, args.anon_key)
        log(f"customer prefixes -> {len(monitored)} monitored anon /24, {len(alloc)} allocated anon hosts")

    if args.active_hosts:                       # explicit set wins
        active = pd.read_csv(args.active_hosts)[["subnet", "host"]]
    elif monitored is not None:
        if args.active_from == "egress":        # paper SS III-C: senders on the calibration days
            active = active_hosts_from_egress(paths, cal_dates, monitored)
            log(f"dark-host set U(s) from egress senders on {len(cal_dates)} calibration days: "
                f"{len(active)} hosts in {active['subnet'].nunique() if len(active) else 0} /24")
        else:                                   # alternative: allocated customer addresses
            active = alloc
            log(f"dark-host set U(s) from allocated customer addresses: {len(active)} hosts")

    F = extract(paths, cal_dates, sampling=args.sampling, tz_offset=args.tz_offset,
                day_type=not args.no_day_type, active_hosts=active, monitored_subnets=monitored)
    F.to_csv(args.out, index=False)
    log(f"done: {len(F)} rows (window x subnet) -> {args.out}")
    log(f"columns: {', '.join(F.columns)}")


if __name__ == "__main__":
    main()
