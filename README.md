# Carpet-bombing DDoS detection — reproduction bundle

Public, reviewer-facing code and data for the paper on detecting **carpet-bombing
DDoS** in sampled NetFlow. Everything here reproduces the paper's tables and
figures from **anonymized** data — no real customer IPs, keys, or raw flows are
included.

## What's in here

| Folder | Role |
|--------|------|
| `exports_anon/` | 10 days of benign NetFlow flows, Crypto-PAn anonymized (prefix-preserving). |
| `attack_injection/` | §III-G attack generation + injection demo (`inject_demo.py`), with `flow_attack.csv` and `merged.csv`. |
| `feature_extraction/` | the 24 per-(/24, 60 s) features (`extract_features_v2.py`) and `features_v2.csv`. |
| `paper_experiments/` | one folder per experiment (E1–E8) + ROC; each reproduces a table/figure. See `paper_experiments/README.md`. |

`paper_experiments/` contains: `baselines/` (E1, Table IV), `ablation/` (E5,
Table III), `sampling_robustness/` (E2, Fig. 5), `detection_floor/` (E4, Fig. 6),
`mimicry/` (E8, Table X), and `roc/` (E1 & E8 detection-vs-false-alarm curves).

## Large files

GitHub caps a single file at 100 MB, so the 13 largest tables ship gzipped as
`<name>.csv.gz` (148 MB instead of 845 MB). Restore them once after cloning —
every script expects the plain `.csv`:

```bash
./unpack.sh
```

This affects `exports_anon/flows_2026-10-18..26.csv`, `feature_extraction/features_v2.csv`,
`paper_experiments/baselines/labeled_features.csv`, `paper_experiments/mimicry/mimicry_predictions.csv`
and `paper_experiments/roc/roc_unseen.csv`. The smaller CSVs are committed as-is.

## Setup

Python 3.11 recommended. From this folder:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The experiment scripts call `../../venv/bin/python`, so creating the virtualenv
here (at the bundle root) is all that is needed.

## Reproduce a result

Each experiment folder has a readable evaluator (prints the table) and a `figure.py`
(draws the figure), both reading a public-safe CSV already in the folder:

```bash
cd paper_experiments/ablation
../../venv/bin/python ablation.py        # prints Table III
../../venv/bin/python figure.py          # writes Fig_ablation.png / .svg
```

(For `baselines/`, run `baselines.py` before `figure.py` — it writes the results
the figure reads. For `roc/`, run `roc.py`.)

## What you can and cannot run

- **Evaluators and figures**: fully runnable here — they use only the anonymized
  CSVs shipped in each folder.
- **`make_*.py`**: these rebuilt the CSVs from the private production run and the
  Crypto-PAn secret. Those inputs are **not** included (they contain real customer
  data), so the `make_*.py` scripts are provided for transparency only and will
  not run in this bundle.

## Data safety

Every shipped table carries only anonymized subnets (Crypto-PAn, the same
prefix-preserving mapping as `exports_anon/`), aggregate feature values, model
scores, and ground-truth labels. The ROC tables carry no subnet field at all.
No raw customer IPs, anonymization keys, customer-prefix lists, or production
pipeline code are present.
