# Before / after: before (0.3.0) vs after (0.3.0)

| tool | detection before | detection after | FP before | FP after | FP UNVERIFIABLE before | FP UNVERIFIABLE after | median s before | median s after |
|---|---|---|---|---|---|---|---|---|
| safeloadai | 53/53 (1.0) | 53/53 (1.0) | 23/85 (0.2706) | 2/85 (0.0235) | - | 2 | 0.4085 | 0.391 |

## safeloadai per format

| format | detection before | detection after | FP before | FP after | FP UNVERIFIABLE before | FP UNVERIFIABLE after | median s before | median s after |
|---|---|---|---|---|---|---|---|---|
| h5 | 4/4 (1.0) | 4/4 (1.0) | 3/16 (0.1875) | 2/16 (0.125) | - | 2 | 0.616 | 0.6188 |
| joblib | - | - | 8/17 (0.4706) | 0/17 (0.0) | - | 0 | 0.4151 | 0.4018 |
| keras | 13/13 (1.0) | 13/13 (1.0) | 4/19 (0.2105) | 0/19 (0.0) | - | 0 | 0.0504 | 0.056 |
| pickle | 32/32 (1.0) | 32/32 (1.0) | 8/33 (0.2424) | 0/33 (0.0) | - | 0 | 0.4192 | 0.4009 |
| torch | 4/4 (1.0) | 4/4 (1.0) | - | - | - | - | 0.2466 | 0.1883 |

## Verdict changes (21)

| file | label | before | after |
|---|---|---|---|
| sk_column_transformer.joblib | benign | SUSPICIOUS | CLEAN |
| sk_column_transformer.pkl | benign | SUSPICIOUS | CLEAN |
| sk_gbr.joblib | benign | SUSPICIOUS | CLEAN |
| sk_gbr.pkl | benign | SUSPICIOUS | CLEAN |
| sk_hgb.joblib | benign | SUSPICIOUS | CLEAN |
| sk_hgb.pkl | benign | SUSPICIOUS | CLEAN |
| sk_label_encoder.joblib | benign | SUSPICIOUS | CLEAN |
| sk_label_encoder.pkl | benign | SUSPICIOUS | CLEAN |
| sk_mlp.joblib | benign | SUSPICIOUS | CLEAN |
| sk_mlp.pkl | benign | SUSPICIOUS | CLEAN |
| sk_ridge.joblib | benign | SUSPICIOUS | CLEAN |
| sk_ridge.pkl | benign | SUSPICIOUS | CLEAN |
| sk_sgd.joblib | benign | SUSPICIOUS | CLEAN |
| sk_sgd.pkl | benign | SUSPICIOUS | CLEAN |
| sk_tfidf.joblib | benign | SUSPICIOUS | CLEAN |
| sk_tfidf.pkl | benign | SUSPICIOUS | CLEAN |
| k2_convnext_tiny.keras | benign | SUSPICIOUS | CLEAN |
| k2_mobilenet_v3_small.h5 | benign | SUSPICIOUS | CLEAN |
| k2_mobilenet_v3_small.keras | benign | SUSPICIOUS | CLEAN |
| k3_convnext_tiny.keras | benign | SUSPICIOUS | CLEAN |
| k3_mobilenet_v3_small.keras | benign | SUSPICIOUS | CLEAN |
