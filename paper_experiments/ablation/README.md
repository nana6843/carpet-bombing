# ablation — feature ablation (Section III-H, Table III)

Which of the five sampling-aware features actually matter? This folder removes
one feature group at a time and re-measures the ensemble's F1 on the test days,
reproducing the paper's **Table III** — in one readable file.

## Files

| File | What it is |
|------|------------|
| `ablation.py` | Scores each feature set and prints Table III (F1 and ΔF1). |
| `ablation_predictions.csv` | **Public-safe** per-(/24, 60-s window) table: ground truth + the trained ensemble's 0/1 prediction under each feature set (anonymized `subnet_24`). |
| `make_ablation_data.py` | The one-off prep that produced it from the production run (local only; needs the Crypto-PAn secret — not for reviewers). |

## How it works (no retraining)

The production pipeline already trained the ensemble once per feature set and
wrote, for every test-day window, its 0/1 prediction (`pred_full`, `pred_no_D`,
…). Table III is just those predictions scored against the carpet-bombing ground
truth. So the numbers here reproduce the paper **exactly**, not approximately.

## Feature sets

| Key | Feature set |
|---|---|
| `full` | all 22 (17 baseline + 5 sampling-aware: Ĥ, D, E, R, A) |
| `no_chao1` | drop the Chao1 victim-count estimate Ĥ |
| `no_D` | drop the dark-host ratio D |
| `no_E` | drop the destination uniformity E |
| `no_R` | drop the reflector share R |
| `no_A` | drop the in/out asymmetry A |
| `B5` | baseline features only (none of the five) |

## Evaluation (Section III-H)

- Positive class: carpet-bombing only (`y == 1`).
- Test days only (temporal split; training days are not scored).
- The floor grid (`floor`, E4-only) and `mimic` (E8-only) families are excluded,
  exactly as `../../experiments/evaluate.py` does.

## Fidelity to the paper (Table III)

Running `ablation.py` reproduces every row of Table III:

| Feature set | paper | here |
|---|---|---|
| All features | 0.985 | **0.985** |
| Without Chao1 Ĥ | 0.985 | **0.985** |
| Without dark-host ratio D | 0.985 | **0.985** |
| Without uniformity E | 0.984 | **0.984** |
| Without reflector share R | 0.985 | **0.985** |
| Without asymmetry A | 0.990 | **0.990** |
| Baseline features only (B5) | 0.984 | **0.984** |

## Reading the result

For *ordinary* carpet-bombing, the sampling-aware features are redundant —
removing any one barely moves F1, and the baseline-only model (B5) is already
strong. Their value appears against **mimicry** attacks (see `../mimicry`), where
an attacker strips the obvious fingerprints. Table III is the honest negative
result that motivates the bandwidth + CUSUM additions.

## Run

```bash
cd ablation
../../venv/bin/python ablation.py          # uses ablation_predictions.csv
../../venv/bin/python figure.py            # draws Fig_ablation.png/.svg (F1 per feature set)
```

## Note on the data

`ablation_predictions.csv` holds per-window ground truth and model predictions;
its only sensitive field — `subnet_24` — is mapped through the same
prefix-preserving Crypto-PAn secret as `../../exports_anon`. No raw IPs, flows, or
customer identities are present, so it is safe to share.
