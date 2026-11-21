# feature_extraction — standalone 24-feature extractor

`extract_features_v2.py` is a single, self-contained Python file that rebuilds the paper's
**24 features** per **(destination /24 subnet × 60-second window)** directly from the
anonymized flow CSVs in `../exports_anon/`. Each derived feature is its own function, so the
file doubles as a readable reference for how every feature is defined (matches the paper's
TABLE II and `../experiments/feature_table.md`).

## Run

```bash
cd feature_extraction
../venv/bin/python extract_features_v2.py                 # ../exports_anon -> features_v2.csv

# Restrict to the monitored customer /24s and enable dark_ratio_D (recommended):
../venv/bin/python extract_features_v2.py \
    --customer-prefixes-anon customer_prefixes_anon.txt

../venv/bin/python extract_features_v2.py --days 2026-10-17 2026-10-18
```

Key options: `--input` (default `../exports_anon`), `--out`, `--days`,
`--calibration-days` (default: first 5 dates; used to learn the z_B baseline),
`--customer-prefixes-anon` (see below), `--active-from` (`egress` default / `prefix`),
`--active-hosts` (CSV `subnet,host` supplying the active-host set U(s) directly),
`--tz-offset`, `--no-day-type`.

## Data: Crypto-PAn anonymized flows (`../exports_anon`)

The flows are anonymized with **Crypto-PAn (prefix-preserving)**, the method used in the paper
(§III-C). Every prefix length is preserved, so a real /24 maps 1:1 to a distinct anon /24 and
all per-/24 and `src_spread` (source-/24) features are valid. The output IPs are not RFC1918
private addresses -- prefix preservation at internet scale (106k distinct source /24s) needs the
full IPv4 space -- but real IPs are cryptographically hidden and only reversible with the secret
key.

## Monitored subnets and dark_ratio_D (`--customer-prefixes-anon`)

`customer_prefixes_anon.txt` (shipped here, **public-safe, needs no key**) is the Crypto-PAn
anonymized version of the real customer prefix list: the same **5511 prefixes** (the paper's set),
same lengths (/28-/30), but in anon space. The real list it was built from (`customer_prefixes.txt`,
real IPs) is **sensitive** and lives in the project root — it is not part of this folder and is
not shared. With `--customer-prefixes-anon` the extractor:

- keeps only windows whose /24 is one of the 562 monitored customer /24s (444 appear in the
  ten-day data), and
- fills `dark_ratio_D` = share of hit destinations NOT in the active-host set U(s).

Following the paper (§III-C), U(s) is built **from egress senders**: the hosts that appear as a
**source** address in outbound records on the calibration days (`--active-from egress`, the
default). Senders are used rather than receivers because background Internet scanning also reaches
unallocated addresses, so a receiver-based set would cover almost the whole /24 and push `D` to
zero. (`--active-from prefix` instead uses allocated customer addresses, and `--active-hosts CSV`
supplies U(s) directly.) On normal days `D` is high because most addresses of a /24 never send
traffic -- a real property of the data.

Input columns read: `ts, te, td, sa, da, sp, dp, pr, flg, ipkt, ibyt`.
Output: one row per (window × /24), columns `window_start, w, subnet_24, slot`, then the
24 features, then helper columns `f1, f2, m_sampled`.

## The 24 features

| Group | Features |
|-------|----------|
| **A. Baseline, 17** (§III-D) | flow_count, pkt_count, byte_count, uniq_src_ip, uniq_src_port, uniq_dst_port, proto_div, syn_pkts, fin_pkts, icmp_pkts, udp_pkts, bytes_per_pkt, pkts_per_flow, dports_per_flow, src_spread, dst_count, dst_count_ratio |
| **B. Sampling-aware, 5** (§III-E) | dst_count_est (Chao1), uniformity_E, dark_ratio_D, reflector_share_R, asymmetry_A |
| **C. Bandwidth-change, 2** | z_B, bw_jump |

13 of these are **direct** aggregations of raw NetFlow fields; 11 are **derived**
(ratios, temporal comparisons, entropy, the Chao1 estimator, and the robust z-score).
Each derived feature has a `feat_*` function.

## Pipeline

1. **Per-day aggregation** (`aggregate_day`) — memory-safe: only one day's flows are held
   at a time. Each flow is weighted for 1:10,000 sampling (`vp = ipkt×N`, `vb = ibyt×N`),
   split across the 60-s windows it covers (`expand_windows`), then aggregated per (w, /24).
2. **Per-row derived features** — bytes_per_pkt, pkts_per_flow, dports_per_flow,
   dst_count_est, uniformity_E, dark_ratio_D, reflector_share_R, asymmetry_A.
3. **Temporal + robust-z** — dst_count_ratio (k=5), bw_jump (k=10), and z_B against a
   per-(subnet, 5-min slot) baseline learned from the calibration days (paper eq. 6).

## Faithfulness notes vs the production collector / paper

- Counters treated as *sampled* (raw sampled values), scaled by N = 10,000.
- All flows treated as **ingress** (subnet = da/24); `out_bytes` for `asymmetry_A` is the
  bytes leaving that same /24.
- **z_B** baseline is learned from calibration days only, pooling ±30 min within the same
  day type (weekday/weekend), with subnet→global fallback and a local MAD floor for
  stability (paper eq. 6 uses the same structure).
- **dst_count_ratio** uses the k previous windows; the collector restricts history to
  non-alarm windows (identical when no alarm fires).
- **dark_ratio_D** needs an active-host set U(s): `--customer-prefixes-anon` (egress senders on
  the calibration days, paper §III-C) or `--active-hosts`; otherwise it is NaN.
- `uniformity_E` and `dark_ratio_D` are clipped to [0, 1] (removes float / midnight-boundary
  artifacts).

## Data note

Source = `../exports_anon/` (IPs anonymized with Crypto-PAn, prefix-preserving, 1:1).
The analysis covers the **ten days 2026-10-17 … 10-26** (matching the paper); `flows_2026-10-27.csv`
is a small spillover tail (~11k flows) past the end of the recording. The anonymization is a
bijection that preserves every prefix length, so all counts and features (including per-/24 and
src_spread) are identical to the real data — only the addresses are masked.
