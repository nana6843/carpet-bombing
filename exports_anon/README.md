# NetFlow CSV Export — ANONYMIZED (Crypto-PAn)

Per-flow NetFlow records with the **Source IP (`sa`)** and **Destination IP (`da`)**
anonymized using **Crypto-PAn (prefix-preserving)** — the method used in the paper (§III-C).

One file per day. The analysis covers the **ten days 17–26 October 2026**
(`flows_2026-10-17.csv` … `flows_2026-10-26.csv`), matching the paper. A small
spillover tail past the end of the recording is kept in `flows_2026-10-27.csv`
(~11k flows) and is not part of the ten-day dataset.

**Provenance (paper §III-C).** NetFlow v5 records exported by the provider-edge
router from **both directions of one uplink**, **fixed-interval sampled at
1:10,000**, 60-s active timeout. The counts (`ipkt`, `ibyt`) are **raw sampled
counts** (not scaled by the sampling ratio). The data covers the **562 monitored
/24 subnets**.

> These files are large (hundreds of thousands to millions of rows). Open them with
> **pandas / Python**, not Excel (Excel only shows the first ~1 million rows).

## How the anonymization works

- Every real IP maps to one anon IP, **1 to 1** (a bijection), **consistently everywhere**.
- It is **prefix-preserving**: if two real IPs share a k-bit prefix, their anon versions also
  share a k-bit prefix. So a real /24 maps to a distinct anon /24, and all per-/24 and
  source-/24 (`src_spread`) structure is **preserved** — uniqueness, grouping and attack
  patterns are identical to the real data.
- Only `sa` and `da` are changed; all other columns are untouched.
- The anon IPs are **not** RFC1918-private addresses: prefix preservation of ~106k internet-wide
  source /24s needs the full IPv4 space. They are cryptographically masked and reversible only
  with the secret key.

## Columns

Each **row = one network flow** (one "conversation" between two IPs during a time window).

| Column | Meaning (simple) |
|--------|------------------|
| `ts`   | **Start time** — when the flow started. |
| `te`   | **End time** — when the flow ended. |
| `td`   | **Duration** — how long the flow lasted, in seconds. |
| `sa`   | **Source IP** — who sent the traffic. **(anonymized, prefix-preserving)** |
| `da`   | **Destination IP** — who received the traffic. **(anonymized, prefix-preserving)** |
| `sp`   | **Source port**. |
| `dp`   | **Destination port** (e.g. 80 = web, 53 = DNS). |
| `pr`   | **Protocol** — `TCP`, `UDP`, `ICMP`, `ESP`, etc. |
| `flg`  | **TCP flags** — order `C E U A P R S F`; dots = not set (e.g. `......S.` = SYN only). |
| `ipkt` | **Packets** in this flow. |
| `ibyt` | **Bytes** in this flow. |

## Important

- **The real IPs are NOT in this folder.** This folder is safe to share publicly.
- The re-identification key (`ip_anon_key.csv`) and the Crypto-PAn secret (`ip_anon_secret.key`)
  live in the project root and are **sensitive** — keep them private, never share.
- To extract the 24 features from this data, see `../feature_extraction/` (use
  `--customer-prefixes-anon customer_prefixes_anon.txt`).
