# attack_injection — attack generation and injection (Section III-G)

A compact, self-contained reference for how synthetic carpet-bombing attacks are
passed through the router's sampling and **injected** into real flows. It
reproduces the production pipeline
(`../experiments/attack_generator.py` + `../experiments/inject_extract.py`) in
one readable file, using the **same method and parameters as the paper** — only
the driver is shorter and focused on a single scenario.

## Files

| File | What it is |
|------|------------|
| `inject_demo.py` | The pipeline: generate a sampled carpet-bombing attack, then inject it into real anonymized benign flows. |
| `flow_attack.csv` | The synthetic attack flows only (`label = attack`). |
| `merged.csv` | Benign + attack, sorted by end-time — the single stream the collector sees. Same schema as `../exports_anon`. |

Schema (both CSVs): `ts, te, td, sa, da, sp, dp, pr, flg, ipkt, ibyt, label`.

## The two stages (one function each)

1. **`build_attack_flows`** — one carpet-bombing scenario, already sampled:
   - `sampled_counts` keeps 1 of every N=10,000 packets the way the router does
     (deterministic binomial; success = the attack's share of the interface
     traffic, so in expectation `kept = attack_pps / N`);
   - packet sizes and ports come from the per-vector `PROFILES` (CIC-DDoS2019
     shape, standard reflector source ports);
   - the load is spread **across the whole /24** (up to 254 hosts) from a pool of
     **120–260** attacker sources — the carpet-bombing pattern;
   - `assemble_flows` groups sampled packets into flows using the router's
     **60-s active and 30-s inactive** timeouts.
2. **`inject_attack`** — concatenate attack + background and **sort by `te`**.
   Merging *before* windowing lets the temporal features (`dst_count_ratio`,
   CUSUM) see the attack against the subnet's real history.

## Fidelity to the paper (Section III-G)

Every element matches the production generator/injector and the paper:

| Paper (Section III-G / III-C) | In `inject_demo.py` |
|---|---|
| "retains every 10,000th packet … binomial whose success probability equals the attack's share of the interface traffic" | `sampled_counts()` |
| "packet-size distributions from CIC-DDoS2019 and the standard reflector source ports" | `PROFILES`, `draw_sizes`, `draw_ports` |
| "120–260 source addresses" | source pool in `build_attack_flows` |
| carpet-bombing = load spread across a /24 | victim spread in `build_attack_flows` |
| "60-s active and 30-s inactive timeouts" | `assemble_flows()` |
| "Inbound records carry the attacks" (III-C) | inbound only, no synthetic replies |
| "injected … before window division, so dst_count_ratio uses real histories" | `inject_attack()` (merge by `te`) |
| interface rate used by the paper run | `--iface-pps` default **66,333** |

**Two deviations, both immaterial to the method and stated for the reviewer:**
1. Packet sizes use the generator's built-in CIC-DDoS2019 *approximations*
   (`PROFILES`); the paper's runs pass exact CIC-derived quantiles via
   `--profiles`. The injection mechanism does not depend on the exact sizes.
2. The attack is injected into an **anonymized** /24 from `../exports_anon`
   (prefix-preserving CryptoPAn, Section III-C), not a raw customer /24, so the
   demo is safe to share. CryptoPAn preserves the /24 structure, so injection is
   equivalent.

## Run

```bash
cd attack_injection
../venv/bin/python inject_demo.py                                 # full-subnet Syn, 500 Mbps
../venv/bin/python inject_demo.py --vectors LDAP,MSSQL --rate-mbps 300
../venv/bin/python inject_demo.py --day 2026-10-23 --victim 12.110.0.0/24 --coverage 0.5
```

Options: `--vectors` (any of `Syn,UDP,UDPLag,NetBIOS,LDAP,MSSQL,Portmap`),
`--rate-mbps`, `--duration`, `--coverage` (fraction of 254 hosts), `--iface-pps`,
`--day`, `--victim`, `--context-min`, `--seed`.

## What it shows

With the defaults, the victim /24 jumps, in a single 60-s window, from a handful
of destinations and sources to **hundreds of both at once** — the carpet-bombing
fingerprint the paper's features capture (`dst_count`, `src_spread`, entropy) and
that a per-host threshold misses. Inputs are anonymized; no real customer IPs are
used.
