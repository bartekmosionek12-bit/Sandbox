# Before / after: after (0.3.0) vs lookalike (0.4.0)

| tool | detection before | detection after | FP before | FP after | FP UNVERIFIABLE before | FP UNVERIFIABLE after | median s before | median s after |
|---|---|---|---|---|---|---|---|---|
| safeloadai | 53/53 (1.0) | 53/53 (1.0) | 2/85 (0.0235) | 2/85 (0.0235) | 2 | 2 | 0.391 | 0.3962 |

## safeloadai per format

| format | detection before | detection after | FP before | FP after | FP UNVERIFIABLE before | FP UNVERIFIABLE after | median s before | median s after |
|---|---|---|---|---|---|---|---|---|
| h5 | 4/4 (1.0) | 4/4 (1.0) | 2/16 (0.125) | 2/16 (0.125) | 2 | 2 | 0.6188 | 1.2255 |
| joblib | - | - | 0/17 (0.0) | 0/17 (0.0) | 0 | 0 | 0.4018 | 0.4026 |
| keras | 13/13 (1.0) | 13/13 (1.0) | 0/19 (0.0) | 0/19 (0.0) | 0 | 0 | 0.056 | 0.3866 |
| pickle | 32/32 (1.0) | 32/32 (1.0) | 0/33 (0.0) | 0/33 (0.0) | 0 | 0 | 0.4009 | 0.3926 |
| torch | 4/4 (1.0) | 4/4 (1.0) | - | - | - | - | 0.1883 | 0.1594 |

## Verdict changes (0)

None.

