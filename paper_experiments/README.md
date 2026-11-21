# paper_experiments


One folder per experiment. Each reproduces a table or figure from the paper
**exactly** by tabulating the production run's precomputed per-(/24, 60-s window)
predictions — no model is retrained here. Every folder is self-contained: one
readable evaluator, its **public-safe** input CSV (the only sensitive field,
`subnet_24`, is anonymized with the same prefix-preserving Crypto-PAn secret as
`../exports_anon`), a `make_*.py` that built that CSV (local only; needs the
secret — not for reviewers), and a README with a fidelity table.

| Folder | Experiment | Reproduces | Headline |
|--------|------------|-----------|----------|
| [`baselines/`](baselines) | E1 | Table IV | B1 34.0%; B3 0.915; B4 0.869; B5 0.989 |
| [`ablation/`](ablation) | E5 | Table III | full 0.985; no_E 0.984; no_A 0.990; B5 0.984 |
| [`sampling_robustness/`](sampling_robustness) | E2 | Fig. 5 | F1 0.985 → 0.977 as sampling goes 1:10k → 1:80k |
| [`detection_floor/`](detection_floor) | E4 | Fig. 6 | floor 3/5/10/5 Mbps; Chao1 victim-count error 124 → 77 |
| [`mimicry/`](mimicry) | E8 | Table X | mimic detection: full 41% → +bandwidth 73% → +CUSUM hybrid 93% |
| [`roc/`](roc) | E1 & E8 | ROC-style fig | detection vs false-alarms/day; full/B5 hug top-left, B1/B2 at floor |

The injection and feature-extraction stages (not experiments, but the pipeline
they feed) are in the sibling `../attack_injection/` and `../feature_extraction/`.

## Run any experiment

```bash
cd paper_experiments/<folder>
../../venv/bin/python <folder>.py        # prints the table (uses the public-safe CSV in the folder)
../../venv/bin/python figure.py          # draws the figure (.png + .svg), in the paper's style
```

To rebuild a folder's CSV from the production run (local only, needs the secret):

```bash
../../venv/bin/python make_*.py
```

## Figures

Each folder has a `figure.py` that redraws its figure from the same public-safe
CSV, so figures are reproducible, not just shipped as images:

| Folder | Figure file | Paper |
|--------|-------------|-------|
| `baselines/` | `Fig_baselines.{png,svg}` | E1 bar: F1 + scenario detection per baseline (run `baselines.py` first) |
| `ablation/` | `Fig_ablation.{png,svg}` | E5 bar: F1 per feature set |
| `sampling_robustness/` | `Fig5_F1_vs_Sampling.{png,svg}` | **Fig. 5** |
| `detection_floor/` | `Fig6_Detection_Floor.{png,svg}` | **Fig. 6** |
| `mimicry/` | `Fig_mimicry_detection.{png,svg}` | E8 bar: 41% → 73% → 93% (dots = per-seed) |
| `roc/` | `Fig_detection_vs_fa.{png,svg}` | E1 & E8: detection vs false-alarms/day (two panels) |

## Data provenance

E2–E8 draw from the production evaluation output
`../experiments/exp_out/run/w60_k1/test_predictions.csv.gz` (plus the `w60_k2/4/8`
runs for E2, and the `exp_bw` / `exp_seed11/23/37` unseen runs for E8); E1
(`baselines/`) draws from the production feature CSVs
`../experiments/exp_out/feat/w60_k1/feat_*.csv`. Those
production files carry real customer `/24`s and are **sensitive**; the CSVs
shipped here carry only anonymized subnets, ground truth, and model predictions,
so they are safe to share.

## One caveat (E8)

The ensemble-alone mimic-detection figure reproduces as **~41%** (mean of the
per-seed counts 5/4/28/28 of 40), not "24%". The bandwidth (**73%**), hybrid
(**~93%**), and false-alarm (**~12/day**) figures match the paper. See
`mimicry/README.md` — the per-seed table is the verifiable source.
