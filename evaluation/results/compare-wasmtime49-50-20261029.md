# Before / after: wasmtime49 (0.10.0) vs wasmtime50 (0.10.0)

| tool | detection before | detection after | FP before | FP after | FP UNVERIFIABLE before | FP UNVERIFIABLE after | median s before | median s after |
|---|---|---|---|---|---|---|---|---|
| safeloadai | 66/66 (1.0) | 66/66 (1.0) | 1/70 (0.0143) | 1/70 (0.0143) | 1 | 1 | 1.3027 | 1.3475 |
| safeloadai without known-file list | 66/66 (1.0) | 66/66 (1.0) | 1/70 (0.0143) | 1/70 (0.0143) | 1 | 1 | 1.3027 | 1.3475 |
| safeloadai validate-boosters | 66/66 (1.0) | 66/66 (1.0) | 1/70 (0.0143) | 1/70 (0.0143) | 1 | 1 | 1.3027 | 1.3475 |
| safeloadai upper bound | 63/66 (0.9545) | 63/66 (0.9545) | 0/70 (0.0) | 0/70 (0.0) | 0 | 0 | 1.3027 | 1.3475 |

## safeloadai per format

| format | detection before | detection after | FP before | FP after | FP UNVERIFIABLE before | FP UNVERIFIABLE after | median s before | median s after |
|---|---|---|---|---|---|---|---|---|
| h5 | 5/5 (1.0) | 5/5 (1.0) | 1/9 (0.1111) | 1/9 (0.1111) | 1 | 1 | 2.1972 | 1.6659 |
| joblib | 1/1 (1.0) | 1/1 (1.0) | 0/18 (0.0) | 0/18 (0.0) | 0 | 0 | 1.3533 | 1.4677 |
| keras | 16/16 (1.0) | 16/16 (1.0) | 0/9 (0.0) | 0/9 (0.0) | 0 | 0 | 1.1976 | 1.182 |
| pickle | 39/39 (1.0) | 39/39 (1.0) | 0/33 (0.0) | 0/33 (0.0) | 0 | 0 | 1.3294 | 1.3659 |
| torch | 5/5 (1.0) | 5/5 (1.0) | 0/1 (0.0) | 0/1 (0.0) | 0 | 0 | 1.2732 | 1.2307 |

## Verdict changes (0)

None.

