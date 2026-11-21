# detection_floor — detection floor + Chao1 victim count (Section III-H, Fig. 6)

Two results in one readable file:

- **(A) Detection floor** — how faint can a carpet-bombing attack be and still be
  caught? Using the E4 "floor grid" (scenarios swept over attack rate × host
  coverage), the lowest attack rate per coverage whose recall stays ≥ 0.9.
- **(B) Chao1 victim-count bias** — how badly does sampling undercount the victims,
  and how much does the Chao1 estimate fix it?

## Files

| File | What it is |
|------|------------|
| `detection_floor.py` | Computes the floor grid and the Chao1 bias table. |
| `floor_windows.csv` | **Public-safe** per-(/24, 60-s window) table: ground truth, `pred_full`/`pred_no_chao1`, `dst_count`, `dst_count_est`, joined to each scenario's attack parameters (anonymized `subnet_24`; victim subnet dropped). |
| `make_floor_data.py` | The one-off prep from the production run + manifest (local only; needs the Crypto-PAn secret — not for reviewers). |

## How it works (no retraining)

The production run already wrote the ensemble's 0/1 prediction and the two
victim-count features (`dst_count` raw, `dst_count_est` Chao1-corrected) per
window; the attack manifest supplies the true `rate_mbps`, `coverage`, and
`n_victims`. Fig. 6 is a tabulation of those, so the numbers match the paper.

## Evaluation (Section III-H)

- **(A)** uses the floor-grid attack windows only (`family == floor`, `y == 1`).
  Per coverage, the floor is the lowest rate that reaches recall ≥ 0.9 **and**
  stays ≥ 0.9 for every higher rate.
- **(B)** uses carpet-bombing windows wholly inside their scenario
  (`w·60 ≥ start` and `(w+1)·60 ≤ end`), split by true victim count:
  full-subnet (≥ 254 hosts) vs partial (10–50%).

## Fidelity to the paper (Fig. 6 / §IV-D)

| | paper | here |
|---|---|---|
| floor, coverage 10% | 3.0 Mbps | **3.0** |
| floor, coverage 25% | 5.0 Mbps | **5.0** |
| floor, coverage 50% | 10.0 Mbps | **10.0** |
| floor, coverage 100% | 5.0 Mbps | **5.0** |
| full-subnet bias, Chao1 Ĥ | −76.7 hosts | **−76.7** |
| full-subnet bias, raw dst_count | −123.7 hosts | **−123.7** |
| partial bias, Chao1 Ĥ | −16.0 hosts | **−16.0** |
| partial bias, raw dst_count | −29.8 hosts | **−29.8** |

## Reading the result

On a full /24 (254 victims) sampling hides most of them: raw `dst_count`
undercounts by ~124 hosts; the Chao1 estimate cuts that to ~77 — the paper's
**124 → 77** result. The detection floor is identical with and without Chao1:
Chao1's value is *counting* the victims accurately, not *deciding* whether an
attack is present (which is why removing it barely moves F1 in `../ablation`).

## Run

```bash
cd detection_floor
../../venv/bin/python detection_floor.py        # uses floor_windows.csv
../../venv/bin/python figure.py                 # draws Fig6_Detection_Floor.png/.svg
```

## Note on the data

Only the real victim `subnet_24` is sensitive; it is mapped through the same
prefix-preserving Crypto-PAn secret as `../../exports_anon`, and the manifest's
victim subnet is dropped. The attack parameters (rate, coverage, victim count)
describe the synthetic attacks, not customers, so the table is safe to share.
