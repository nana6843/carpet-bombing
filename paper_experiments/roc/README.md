# roc — detection vs false-alarm curves (E1 & E8)

The paper's ROC-style figure: detection (window recall) traced against false
alarms per day as each detector's threshold slides. Two panels in one readable
file.

## Files

| File | What it is |
|------|------------|
| `roc.py` | Draws `Fig_detection_vs_fa.{png,svg}` and prints a recall@FA table. |
| `roc_known.csv` | **Public-safe** per-window scores + labels for E1 (no subnet at all). |
| `roc_unseen.csv` | **Public-safe** per-window scores + labels for E8, 4 seeds (no subnet). |
| `make_roc_data.py` | The one-off prep from the production runs (local only; not for reviewers). |

## Panels

- **(a) Known attacks (E1)** — `full`, `B5`, `B3`, `B2`, `B1`. The ensemble and
  the B5 ML baseline hug the top-left (recall ≈ 0.99 at ≤ 5 false alarms/day);
  B3 (entropy) is mid; B2 (/24 volume) and B1 (per-host) are near the floor — the
  visual form of "a per-host threshold is hopeless against carpet bombing".
- **(b) Unseen mimicry (E8)** — `full` vs `full_bw`, mean over the four seeds
  (shaded band = ±1 SD across seeds). The CUSUM and the `full_bw+CUSUM` hybrid are
  gated stream detectors, not freely sweepable scores, so they appear as operating
  points (markers): the hybrid reaches recall ≈ 0.71 at ≈ 13 false alarms/day.

## Note on scores vs operating points

`full`, `B5`, `B3`, `B2`, `B1`, `full_bw` are continuous scores → full sweep
curves (via `sklearn.roc_curve`; false alarms/day = FPR × negatives ÷ test days).
`CUSUM` and the hybrid depend on CUSUM's label-gated statistic, which does not
sweep cleanly, so they are shown as single operating points. Operating points for
E8 are computed per seed and averaged (pooling seeds would inflate false
alarms/day by the number of seeds).

## Run

```bash
cd roc
../../venv/bin/python roc.py              # uses roc_known.csv + roc_unseen.csv
```

## Note on the data

The ROC tables carry only per-window scores and the ground-truth label — **no
subnet or IP-derived field at all** — so they are safe to share.
