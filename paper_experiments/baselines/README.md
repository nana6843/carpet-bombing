# baselines — the B1–B5 baseline detectors (Section III-H)

The paper's five baselines in one readable file, one function per baseline,
reproducing the Table IV comparison. Faithful to the production implementation
(`../../experiments/train.py` + `common.py`), but focused and self-contained.

## Files

| File | What it is |
|------|------------|
| `baselines.py` | The baselines B1–B5 + the temporal-split evaluation. |
| `labeled_features.csv` | **Public-safe** labeled (/24, 60-s window) samples it runs on (anonymized `subnet_24`). |
| `make_labeled_features.py` | The one-off prep that produced `labeled_features.csv` (local only; needs the Crypto-PAn secret and the production features — not for reviewers). |

## The five baselines (one function each)

| Baseline | Definition |
|---|---|
| **B1** Per-host threshold | score = `max_host_bps` (busiest host's bitrate); threshold tuned on the training days |
| **B2** Per-/24 volume | score = `bps` (whole-/24 bitrate); threshold tuned on the training days |
| **B3** Destination entropy | score = `uniformity_E · ln(dst_count)`; threshold tuned on the training days |
| **B4a** Fan-out rule | fixed: `dst_count ≥ 5 AND dst_count_ratio ≥ 3.0` (no training) |
| **B4b** dst_count-only model | RF + LightGBM on `[dst_count]` |
| **B5** Baseline-features model | RF + LightGBM on the 17 baseline features |

## Evaluation protocol (Section III-H)

- **Temporal split**: train on days 1–5, test on days 6–10.
- **Positive class**: carpet-bombing only (`y = gt_kind == "carpet_bombing"`); benign
  look-alikes and normal are negatives.
- **Thresholds** for B1–B3 are chosen on the training data (maximize F1), then applied
  to the test days — never tuned on the test set.
- **Table IV set**: the floor grid (family `floor`, an E4-only experiment) and `mimic`
  (E8-only) are excluded from the comparison, exactly as `evaluate.py` does. This leaves
  the **153 carpet-bombing scenarios / 1,404 attack windows** of §IV-A.

## Fidelity to the paper (Table IV)

Running `baselines.py` reproduces the paper's baseline numbers closely, with several
matching exactly:

| | paper | here |
|---|---|---|
| B1 scenario detection | 34.0% | **0.340** |
| B3 entropy F1 | 0.915 | **0.915** |
| B4 fan-out F1 | 0.869 | **0.869** |
| B5 F1 | 0.984 | 0.989 |

(Small gaps on B2/B5 come from this file using a compact ensemble recipe with a single
seed and no grace-window mask, vs the production pipeline's tuned hyperparameters.)

## Run

```bash
cd baselines
../../venv/bin/python baselines.py          # uses labeled_features.csv; writes baseline_results.csv
../../venv/bin/python figure.py             # draws Fig_baselines.png/.svg (needs baseline_results.csv)
```

To rebuild the labeled table from the production features (local only, needs the secret):

```bash
../../venv/bin/python make_labeled_features.py
```

## Note on the data

`labeled_features.csv` holds per-(/24, window) **aggregate feature values** with the only
sensitive field — `subnet_24` — mapped through the same prefix-preserving Crypto-PAn secret
as `../../exports_anon`. No raw IPs, flows, or customer identities are present, so it is safe to
share. The full 24-feature ensemble (F1 ≈ 0.985) lives in the production pipeline
(`../../experiments/`); this folder covers the baselines only.
