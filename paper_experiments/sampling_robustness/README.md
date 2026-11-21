# sampling_robustness — detection vs sampling rate (Section III-H, Fig. 5)

Does detection survive heavier router sampling? This folder re-measures the
ensemble's F1 at four sampling rates — 1:10,000, 1:20,000, 1:40,000, 1:80,000 —
reproducing the paper's **Fig. 5**, in one readable file.

## Files

| File | What it is |
|------|------------|
| `sampling_robustness.py` | Scores the ensemble at each rate and prints the Fig. 5 table. |
| `sampling_predictions.csv` | **Public-safe** per-(/24, 60-s window) table across the four rates: ground truth + `pred_full` / `pred_no_chao1` (anonymized `subnet_24`). |
| `make_sampling_data.py` | The one-off prep from the production runs (local only; needs the Crypto-PAn secret — not for reviewers). |

## How it works (no retraining)

The paper runs the whole pipeline four times, keeping every k-th sampled packet
on top of the native 1:10,000 (`w60_k1/2/4/8` → 1:10k/20k/40k/80k). Each run
already wrote the trained ensemble's 0/1 prediction per window, so Fig. 5 is just
those predictions scored against the ground truth — matching the paper exactly.

## Evaluation (Section III-H)

- Positive class: carpet-bombing only (`y == 1`).
- Floor (E4-only) and mimic (E8-only) families excluded, as in `evaluate.py`.
- Each heavier rate has **fewer attack windows**: low-rate attacks drop below the
  sampling floor and leave no sampled packets. That thinning is expected and is
  itself part of the robustness story.

## Fidelity to the paper (Fig. 5)

| Rate | paper (full) | here | paper (no_chao1) | here |
|---|---|---|---|---|
| 1:10,000 | 0.985 | **0.985** | 0.985 | **0.985** |
| 1:20,000 | 0.979 | **0.979** | 0.979 | **0.979** |
| 1:40,000 | 0.973 | 0.972 | 0.969 | **0.969** |
| 1:80,000 | 0.977 | **0.977** | 0.976 | **0.976** |

(The 0.972-vs-0.973 at 1:40,000 is a one-window rounding difference: the paper
also drops a short post-scenario *grace* window per subnet that needs the attack
manifest; omitting it here shifts F1 by ≤0.001 and never changes the message.)

## Reading the result

F1 stays ~0.97–0.99 as sampling goes from 1:10k to 1:80k — detection degrades
gracefully, not catastrophically. The Chao1 estimate neither helps nor hurts at
the ensemble level; its payoff is victim-count accuracy (see `../detection_floor`).

## Run

```bash
cd sampling_robustness
../../venv/bin/python sampling_robustness.py      # uses sampling_predictions.csv
../../venv/bin/python figure.py                   # draws Fig5_F1_vs_Sampling.png/.svg
```

## Note on the data

Only `subnet_24` is sensitive; it is mapped through the same prefix-preserving
Crypto-PAn secret as `../../exports_anon`. No raw IPs, flows, or customer identities
are present, so the table is safe to share.
