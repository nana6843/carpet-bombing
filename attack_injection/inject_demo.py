#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attack_injection/inject_demo.py
===============================
A compact, self-contained reference for the paper's attack-generation and
injection step (Section III-G). It reproduces the production pipeline
(../experiments/attack_generator.py + ../experiments/inject_extract.py) in one
readable file, using the SAME method and parameters as the paper -- only the
driver is shorter and focused on a single scenario.

Pipeline (one function per stage, mirroring Section III-G):
    1. build_attack_flows()  generate a carpet-bombing attack already passed
                             through the router's 1:N sampling, assembled into
                             flows with the 60-s active / 30-s inactive timeouts.
    2. inject_attack()       merge the attack into real anonymized benign flows,
                             ordered by end-time, BEFORE any windowing.

Fidelity to the paper (Section III-G), line by line:
  * "retains every 10,000th packet ... binomial whose success probability equals
     the attack's share of the interface traffic"      -> sampled_counts()
  * "packet-size distributions from CIC-DDoS2019 and the standard reflector
     source ports of each service"                      -> PROFILES + draw_sizes/draw_ports
  * "120-260 source addresses"                          -> build_attack_flows (src pool)
  * carpet-bombing = load spread over a whole /24       -> build_attack_flows (victims)
  * "60-s active and 30-s inactive timeouts"            -> assemble_flows()
  * "Inbound records carry the attacks" (Section III-C) -> inbound only, no replies
  * "injected ... before window division, so dst_count_ratio uses real histories"
                                                        -> inject_attack() (merge by te)

Deviations (both immaterial to the method, stated for the reviewer):
  (a) Packet sizes use the generator's built-in CIC-DDoS2019 approximations
      (PROFILES below). The paper's runs pass exact CIC-derived quantiles via
      --profiles; the injection mechanism is independent of the exact sizes.
  (b) The attack is injected into an anonymized /24 from exports_anon (CryptoPAn,
      prefix-preserving, Section III-C) instead of a raw customer /24, so the
      demo is safe to share. CryptoPAn keeps the /24 structure, so the injection
      is equivalent.

Inputs : ../exports_anon/flows_<day>.csv (CryptoPAn-anonymized benign flows).
Outputs (next to this file), same schema as exports_anon:
    flow_attack.csv   the synthetic attack flows only            (label = attack)
    merged.csv        benign + attack, sorted by end-time        (what the collector sees)
Schema : ts, te, td, sa, da, sp, dp, pr, flg, ipkt, ibyt, label

Run:
    ../venv/bin/python inject_demo.py
    ../venv/bin/python inject_demo.py --vectors Syn --rate-mbps 500 --coverage 1.0
    ../venv/bin/python inject_demo.py --day 2026-10-23 --victim 12.110.0.0/24
"""

import argparse
import os
import socket
import struct
import sys

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- router / sampling constants (Section III-C / III-G) ----
SAMPLING_N = 10_000       # router keeps 1 of every N packets on the interface
ACTIVE_TIMEOUT = 60.0     # a flow is cut after 60 s of activity
INACTIVE_TIMEOUT = 30.0   # ... or after a 30 s gap with no packets
PROTO_NAME = {6: "TCP", 17: "UDP", 1: "ICMP"}

# ---- attack vectors (copied verbatim from ../experiments/attack_generator.py) ----
# size_q = packet-size quantiles 0,10,...,100% (IP bytes, CIC-DDoS2019 shape).
# sport/dport = fixed service port list or "eph" (ephemeral 1024-65535).
# frag = fraction of packets that are non-first fragments (port 0/0 in the record).
PROFILES = {
    "Syn":     dict(proto=6,  sport="eph",   dport=[80, 443, 22, 3389, 8080], flags=2,
                    size_q=[40, 40, 40, 44, 52, 60, 60, 60, 60, 64, 74], frag=0.0),
    "UDP":     dict(proto=17, sport="eph",   dport="eph", flags=0,
                    size_q=[60, 400, 512, 700, 900, 1100, 1300, 1400, 1450, 1472, 1500], frag=0.0),
    "UDPLag":  dict(proto=17, sport="eph",   dport="eph", flags=0,
                    size_q=[29, 40, 50, 60, 70, 80, 100, 120, 150, 200, 400], frag=0.0),
    "NetBIOS": dict(proto=17, sport=[137],   dport="eph", flags=0,
                    size_q=[90, 229, 229, 280, 300, 330, 360, 400, 450, 500, 600], frag=0.0),
    "LDAP":    dict(proto=17, sport=[389],   dport="eph", flags=0,
                    size_q=[200, 600, 1000, 1400, 1460, 1472, 1500, 1500, 1500, 1500, 1500], frag=0.45),
    "MSSQL":   dict(proto=17, sport=[1434],  dport="eph", flags=0,
                    size_q=[100, 300, 350, 400, 420, 450, 500, 550, 600, 700, 1000], frag=0.0),
    "Portmap": dict(proto=17, sport=[111],   dport="eph", flags=0,
                    size_q=[80, 150, 200, 300, 350, 400, 450, 500, 600, 800, 1200], frag=0.0),
}


# =====================================================================
# 0. SMALL HELPERS
# =====================================================================

def ip_to_int(dotted: str) -> int:
    return struct.unpack("!I", socket.inet_aton(dotted))[0]


def int_to_ip(x: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", int(x) & 0xFFFFFFFF))


def flags_to_str(mask: int) -> str:
    """TCP flag byte -> nfdump string, order 'C E U A P R S F'. SYN(2) -> '......S.'."""
    return "".join(ch if mask & b else "." for b, ch in
                   [(128, "C"), (64, "E"), (32, "U"), (16, "A"),
                    (8, "P"), (4, "R"), (2, "S"), (1, "F")])


def eph(rng, n):
    return rng.integers(1024, 65536, n)


def draw_ports(spec, rng, n):
    return eph(rng, n) if isinstance(spec, str) else rng.choice(np.asarray(spec, np.int64), n)


def draw_sizes(size_q, rng, n):
    """Draw n packet sizes by inverting the 0..100% quantile curve (as in production)."""
    u = rng.uniform(0, 10, n)
    return np.rint(np.interp(u, np.arange(11), np.asarray(size_q, float))).astype(np.int64)


def mean_size(size_q):
    return float(np.mean(np.interp(np.linspace(0, 10, 1001), np.arange(11), np.asarray(size_q, float))))


def random_external_ips(rng, n):
    """n random public IPv4 sources (avoids 0/8, 10/8, 127/8, 224/3)."""
    first = rng.choice(np.setdiff1d(np.arange(1, 224), [10, 127]), n)
    return (first.astype(np.int64) << 24) | rng.integers(0, 1 << 24, n)


# =====================================================================
# 1a. ROUTER SAMPLING  (Section III-G, "pass them through the sampling process")
# =====================================================================

def sampled_counts(raw_pps: np.ndarray, iface_pps: float, rng) -> np.ndarray:
    """How many attack packets the router KEEPS each second (deterministic 1:N).

    The router keeps every N-th packet across ALL interface traffic, so attack
    packets compete for the sampled slots with everything else:
        positions_t ~ (attack_pps + iface_pps) / N     slots in second t
        share_t      =  attack_pps / (attack_pps + iface_pps)
        kept_t      ~ Binomial(positions_t, share_t)
    In expectation kept_t = attack_pps / N: the interface rate cancels out, so
    each attack packet is kept with probability ~1/N. Drawing attributes only for
    kept packets is statistically identical to sampling every packet.
    """
    raw_pps = np.maximum(raw_pps, 0.0)
    total = raw_pps + iface_pps
    cum = np.cumsum(total) + rng.uniform(0, SAMPLING_N)         # random phase of the counter
    positions = np.diff(np.floor(np.concatenate([[cum[0] - total[0]], cum]) / SAMPLING_N)).astype(np.int64)
    share = np.where(total > 0, raw_pps / total, 0.0)
    return rng.binomial(positions, share)


# =====================================================================
# 1b. FLOW ASSEMBLY  (Section III-G, "60-s active and 30-s inactive timeouts")
# =====================================================================

def assemble_flows(pkt: pd.DataFrame) -> pd.DataFrame:
    """Group sampled packets (t, sa, da, sp, dp, proto, flags, size) into flow
    records exactly as the router's exporter does: same 5-tuple, a new flow when
    the gap exceeds the inactive timeout or the flow reaches the active timeout."""
    key = ["sa", "da", "sp", "dp", "proto"]
    pkt = pkt.sort_values(key + ["t"], kind="stable").reset_index(drop=True)
    new_key = (pkt[key].diff().abs().sum(axis=1) != 0).to_numpy()
    new_key[0] = True
    gap = np.diff(pkt["t"].to_numpy(), prepend=-np.inf)
    brk = new_key | (gap > INACTIVE_TIMEOUT)            # start a new flow here
    fid = np.cumsum(brk)
    t0 = pkt.groupby(fid)["t"].transform("min").to_numpy()
    seg = np.floor((pkt["t"].to_numpy() - t0) / ACTIVE_TIMEOUT).astype(np.int64)
    pkt["fid"] = fid * 100000 + seg                    # split a long flow at the active timeout
    g = pkt.groupby("fid", sort=False)
    R = g.agg(ts=("t", "min"), te=("t", "max"), sa=("sa", "first"), da=("da", "first"),
              sp=("sp", "first"), dp=("dp", "first"), proto=("proto", "first"),
              ipkt=("t", "size"), ibyt=("size", "sum"))
    fl = pkt["flags"].to_numpy()
    R["flags"] = sum(((pd.Series((fl & b) > 0).groupby(pkt["fid"].to_numpy(), sort=False).max()
                       .reindex(R.index).to_numpy()) * b) for b in (1, 2, 4, 8, 16, 32, 64, 128))
    return R.reset_index(drop=True)


# =====================================================================
# 1. ATTACK GENERATION  (carpet-bombing, already sampled)
# =====================================================================

def build_attack_flows(victim24, start_epoch, duration_s, rate_mbps, coverage,
                       vectors, iface_pps, rng) -> pd.DataFrame:
    """Generate the sampled flow records of ONE carpet-bombing scenario.

    victim24 : /24 index of the target subnet (anon space)
    coverage : fraction of the 254 host addresses attacked (1.0 = full /24)
    vectors  : list of PROFILES keys; byte load is split evenly across them
    """
    dur = int(duration_s)
    weights = np.full(len(vectors), 1.0 / len(vectors))          # equal byte share per vector
    msz = np.array([mean_size(PROFILES[v]["size_q"]) for v in vectors])
    pw = weights / msz
    pw /= pw.sum()                                               # byte weights -> packet weights
    raw_pps = np.full(dur, rate_mbps * 1e6 / 8.0 / float(np.sum(pw * msz)))

    kept = sampled_counts(raw_pps, iface_pps, rng)               # packets kept per second
    K = int(kept.sum())
    if K == 0:
        return pd.DataFrame()
    t = start_epoch + np.repeat(np.arange(dur), kept) + rng.uniform(0, 1, K)
    vi = rng.choice(len(vectors), K, p=pw)                       # which vector each packet is

    # --- carpet-bombing: spread the load over the victims with small jitter ---
    n_hosts = max(1, int(round(coverage * 254)))
    victim_hosts = rng.choice(np.arange(1, 255), n_hosts, replace=False)
    hw = rng.lognormal(0, 0.1, n_hosts)                          # near-uniform (host_jitter)
    host = rng.choice(victim_hosts, K, p=hw / hw.sum())
    da = (np.int64(victim24) << 8) | host

    # --- attacker sources: a pool of 120-260 external IPs ---
    pool = random_external_ips(rng, int(rng.integers(120, 261)))
    sa = rng.choice(pool, K)

    # --- per-vector packet attributes (proto, flags, ports, size, fragments) ---
    sp = np.zeros(K, np.int64); dp = np.zeros(K, np.int64)
    proto = np.zeros(K, np.int64); flags = np.zeros(K, np.int64); size = np.zeros(K, np.int64)
    for j, v in enumerate(vectors):
        m = vi == j
        n = int(m.sum())
        if n == 0:
            continue
        p = PROFILES[v]
        sp[m], dp[m] = draw_ports(p["sport"], rng, n), draw_ports(p["dport"], rng, n)
        proto[m], flags[m] = p["proto"], p["flags"]
        size[m] = draw_sizes(p["size_q"], rng, n)
        if p.get("frag", 0) > 0:                                 # non-first fragments: no ports
            fr = np.flatnonzero(m)[rng.uniform(0, 1, n) < p["frag"]]
            sp[fr], dp[fr] = 0, 0
            size[fr] = rng.integers(500, 1501, len(fr))

    pkt = pd.DataFrame(dict(t=t, sa=sa, da=da, sp=sp, dp=dp, proto=proto, flags=flags, size=size))
    flows = assemble_flows(pkt)
    out = pd.DataFrame({
        "ts": pd.to_datetime(flows["ts"], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S"),
        "te": pd.to_datetime(flows["te"], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S"),
        "td": (flows["te"] - flows["ts"]).round(3),
        "sa": flows["sa"].map(int_to_ip),
        "da": flows["da"].map(int_to_ip),
        "sp": flows["sp"].astype(int),
        "dp": flows["dp"].astype(int),
        "pr": flows["proto"].map(PROTO_NAME),
        "flg": flows["flags"].map(flags_to_str),
        "ipkt": flows["ipkt"].astype(int),
        "ibyt": flows["ibyt"].astype(int),
        "label": "attack",
    })
    out["_epoch"] = flows["te"].astype(np.int64)
    return out


# =====================================================================
# 2. INJECTION  (Section III-G, "injected ... before window division")
# =====================================================================

def load_background_flows(input_dir: str, day: str) -> pd.DataFrame:
    """Load one day of real benign flows from exports_anon (CryptoPAn anonymized)."""
    path = os.path.join(input_dir, f"flows_{day}.csv")
    if not os.path.exists(path):
        sys.exit(f"background file not found: {path}")
    df = pd.read_csv(path, dtype={"sa": str, "da": str, "pr": str, "flg": str})
    df["_epoch"] = pd.to_datetime(df["te"]).astype("int64") // 1_000_000_000
    df["label"] = "background"
    return df


def inject_attack(background: pd.DataFrame, attack: pd.DataFrame) -> pd.DataFrame:
    """Splice the attack flows into the benign stream, ordered by end-time (te).

    Merging BEFORE feature windowing is the point: the collector sees one single
    time-ordered flow stream, so temporal features (dst_count_ratio, CUSUM) score
    the attack against the subnet's own real history, and export-path differences
    between benign and attack records disappear.
    """
    cols = ["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "flg", "ipkt", "ibyt", "label"]
    merged = pd.concat([background[cols + ["_epoch"]], attack[cols + ["_epoch"]]], ignore_index=True)
    merged = merged.sort_values("_epoch", kind="stable").reset_index(drop=True)
    return merged[cols]


def busiest_monitored_subnet(bg: pd.DataFrame, monitored_file: str) -> int:
    monitored = set()
    for line in open(monitored_file):
        line = line.strip()
        if line and not line.startswith("#"):
            monitored.add(ip_to_int(line.split("/")[0]) >> 8)
    da24 = bg["da"].map(ip_to_int).to_numpy() >> 8
    counts = pd.Series(da24[np.isin(da24, list(monitored))]).value_counts()
    if counts.empty:
        sys.exit("no monitored /24 appears in the background day")
    return int(counts.index[0])


# =====================================================================
# MAIN
# =====================================================================

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=os.path.join(HERE, "..", "exports_anon"))
    ap.add_argument("--monitored", default=os.path.join(HERE, "..", "feature_extraction",
                                                        "monitored_subnets_anon.txt"))
    ap.add_argument("--day", default="2026-10-22")
    ap.add_argument("--vectors", default="Syn",
                    help="comma-separated PROFILES keys: " + ",".join(PROFILES))
    ap.add_argument("--rate-mbps", type=float, default=500.0)
    ap.add_argument("--duration", type=int, default=300)
    ap.add_argument("--coverage", type=float, default=1.0, help="fraction of 254 hosts hit")
    ap.add_argument("--iface-pps", type=float, default=66_333.0,
                    help="interface packet rate outside the attack (paper run: 66,333)")
    ap.add_argument("--context-min", type=int, default=30,
                    help="benign minutes kept on each side of the attack in merged.csv")
    ap.add_argument("--victim", default=None, help="anon /24, e.g. 12.110.0.0/24 (default: busiest)")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--outdir", default=HERE)
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    vectors = [v for v in args.vectors.split(",") if v]
    for v in vectors:
        if v not in PROFILES:
            sys.exit(f"unknown vector {v!r}; choose from {','.join(PROFILES)}")

    print(f"[1] loading background flows for {args.day} ...")
    bg = load_background_flows(args.input, args.day)
    print(f"    {len(bg):,} benign flows")

    victim24 = (ip_to_int(args.victim.split("/")[0]) >> 8) if args.victim \
        else busiest_monitored_subnet(bg, args.monitored)
    victim_str = int_to_ip(victim24 << 8) + "/24"

    center = int(np.median(bg["_epoch"]))
    start_epoch = center - args.duration // 2
    end_epoch = start_epoch + args.duration

    print(f"[2] generating carpet-bombing attack ({'+'.join(vectors)}) ...")
    print(f"    victim /24 = {victim_str}, {args.rate_mbps:.0f} Mbps, "
          f"{args.duration}s, coverage {args.coverage:.0%}")
    attack = build_attack_flows(victim24, start_epoch, args.duration, args.rate_mbps,
                                args.coverage, vectors, args.iface_pps, rng)
    if attack.empty:
        sys.exit("attack produced 0 sampled flows -- raise --rate-mbps or --duration")
    print(f"    {len(attack):,} sampled attack flows, {attack['da'].nunique()} victim hosts, "
          f"{attack['sa'].nunique()} sources")

    w = args.context_min * 60
    ctx = bg[(bg["_epoch"] >= start_epoch - w) & (bg["_epoch"] <= end_epoch + w)]
    print(f"[3] injecting (merge by end-time) into ±{args.context_min} min of background "
          f"({len(ctx):,} benign flows) ...")
    merged = inject_attack(ctx, attack)

    cols = ["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "flg", "ipkt", "ibyt", "label"]
    atk_path = os.path.join(args.outdir, "flow_attack.csv")
    mrg_path = os.path.join(args.outdir, "merged.csv")
    attack[cols].to_csv(atk_path, index=False)
    merged.to_csv(mrg_path, index=False)

    n_atk = int((merged["label"] == "attack").sum())
    print(f"\n    flow_attack.csv : {len(attack):,} rows (attack only)      -> {atk_path}")
    print(f"    merged.csv      : {len(merged):,} rows "
          f"({n_atk:,} attack, {len(merged) - n_atk:,} benign) -> {mrg_path}")

    # the carpet-bombing fingerprint the detector must find in merged.csv
    m = merged.copy()
    m["_epoch"] = pd.to_datetime(m["te"]).astype("int64") // 1_000_000_000
    vic = m[m["da"].map(ip_to_int).to_numpy() >> 8 == victim24]
    atk_min = vic[(vic["_epoch"] >= start_epoch) & (vic["_epoch"] < start_epoch + 60)]
    quiet_min = vic[(vic["_epoch"] >= start_epoch - 600) & (vic["_epoch"] < start_epoch - 540)]
    print(f"\n    Carpet-bombing fingerprint in the victim /24 ({victim_str}), one 60-s window:")
    print(f"      {'metric':<26}{'normal minute':>15}{'attack minute':>15}")
    for name, col in [("flows", None), ("distinct dst hosts", "da"), ("distinct sources", "sa")]:
        a = len(atk_min) if col is None else atk_min[col].nunique()
        q = len(quiet_min) if col is None else quiet_min[col].nunique()
        print(f"      {name:<26}{q:>15,}{a:>15,}")
    print("    -> many destinations + many sources at once = the carpet-bombing signal"
          " (dst_count, src_spread, entropy) that a per-host threshold misses.")


if __name__ == "__main__":
    main()
