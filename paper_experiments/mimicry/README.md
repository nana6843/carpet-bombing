# mimicry — disguised carpet bombing (Section III-H / §IV-E, Table X)

The paper's hardest case: carpet bombing that **disguises itself** as ordinary web
traffic — no reflector source ports, normal packet sizes — so the sampling-aware
fingerprints vanish. The mimic scenarios are held **out of training** ("unseen"),
so this measures true generalization, averaged over four random seeds.

## Files

| File | What it is |
|------|------------|
| `mimicry.py` | Scores the three detectors per seed and prints the mimic progression. |
| `mimicry_predictions.csv` | **Public-safe** per-window table across 4 seeds: the unseen-mimic subset, ground truth + `pred_full` / `pred_full_bw` / `pred_CUSUM` (anonymized `subnet_24`). |
| `make_mimicry_data.py` | The one-off prep from the four production runs (local only; needs the Crypto-PAn secret — not for reviewers). |

## The three detectors (a progression)

| Key | Detector |
|---|---|
| `full` | the ensemble alone (22 features) |
| `full_bw` | ensemble **+ the two bandwidth-change features** |
| `full_bw+CUSUM` | the **hybrid**: `full_bw` OR the robust-z/CUSUM stream detector |

The hybrid is formed in `mimicry.py` as `pred_full_bw OR pred_CUSUM`, exactly as
`../../experiments/e8_hybrid.py` does — no retraining.

## Evaluation (Section III-H)

- **Unseen**: mimic scenarios are excluded from training (`train.py
  --exclude-train-families mimic`); only their generalization to the test days is
  scored.
- Subset (as in `evaluate.py` + `extra_common.py`): drop post-scenario grace
  windows and the floor grid, keep mimic windows plus all negatives.
- Four seeds: 2026 (`exp_bw`), 11, 23, 37 — same runs as `new_exp8/e8_seeds.py`.

## Fidelity to the paper (Table X)

Per-seed mimic scenarios detected (of 40) reproduce the paper's reference counts
exactly:

| detector | seed 2026 | seed 11 | seed 23 | seed 37 | mean |
|---|---|---|---|---|---|
| full | 5/40 | 4/40 | 28/40 | 28/40 | **40.6%** |
| full_bw | 22/40 | 22/40 | 37/40 | 36/40 | **73.1%** |
| full_bw+CUSUM | 34/40 | 39/40 | 39/40 | 37/40 | **93.1%** |

The bandwidth result (**73%**) and the hybrid (**~93%**, paper "~94%") match, and
the hybrid's false-alarm cost (**~13/day**) matches the paper's "~12/day". The
ensemble-alone mean reproduces as **~41%** across these four seeds — if the draft
states a different figure (e.g. "24%") for that cell, reconcile the wording with
this per-seed table, which is the verifiable source.

## Reading the result

The ensemble alone generalizes poorly to disguised attacks. The two
bandwidth-change features lift mimic detection to ~73%; OR-ing in the CUSUM stream
detector (the hybrid) reaches ~93%, at a higher false-alarm cost. This is why the
paper keeps the bandwidth features and the CUSUM hybrid despite their redundancy on
ordinary attacks (where removing them barely moves F1 — see `../ablation`).

## Run

```bash
cd mimicry
../../venv/bin/python mimicry.py          # uses mimicry_predictions.csv
../../venv/bin/python figure.py           # draws Fig_mimicry_detection.png/.svg (41→73→93%)
```

## Note on the data

Only `subnet_24` is sensitive; it is mapped through the same prefix-preserving
Crypto-PAn secret as `../../exports_anon`, and the grace mask (which needs the real
subnet) is applied during prep, so the shipped table carries only anonymized
subnets. No raw IPs, flows, or customer identities are present.
