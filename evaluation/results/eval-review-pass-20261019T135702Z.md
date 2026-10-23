# Evaluation review-pass (20261019T135702Z)

safeloadai 0.4.0, Python 3.13.16, Linux x86_64. 943 files.

| tool | detected / malicious | false positives / benign | of which UNVERIFIABLE | errors | unsupported | skipped | median s | p95 s |
|---|---|---|---|---|---|---|---|---|
| safeloadai | 0 / 0 | 360 / 943 | 266 | 0 | 0 | 0 | 0.4921 | 1.3895 |

A detailed per-format comparison is withheld until coordinated disclosure with the affected projects is complete.

"of which UNVERIFIABLE": false positives whose every reason is UNVERIFIABLE, so a user could accept them, item by item, for that one file. They still count as false positives. Malicious files that are UNVERIFIABLE only: 0 (an override would let these through, which is why it names every item).

## Per format

| format | tool | detected / malicious | FP / benign | FP UNVERIFIABLE | FP rate | median s |
|---|---|---|---|---|---|---|
| h5 | safeloadai | 0 / 0 | 19 / 150 | 14 | 0.1267 | 0.596 |
| joblib | safeloadai | 0 / 0 | 48 / 86 | 42 | 0.5581 | 0.4662 |
| keras | safeloadai | 0 / 0 | 57 / 140 | 43 | 0.4071 | 0.0193 |
| pickle | safeloadai | 0 / 0 | 72 / 130 | 64 | 0.5538 | 0.4967 |
| torch | safeloadai | 0 / 0 | 164 / 437 | 103 | 0.3753 | 0.546 |

## Per group

Groups: `lab` and `mutations` are generated marker payloads; `hf-malicious` are Hub files the Hub's scanners flag, labelled from that evidence; `hf-tune` and `hf-heldout` are the two halves of the benign Hub corpus, split by repo. The allowlist review looked only at `hf-tune`; the headline false-positive rate is `hf-heldout`. FP MALICIOUS / RISKY / UNVERIFIABLE split safeloadai's false positives by category.

### hf-tune: total

| set | tool | detected / malicious | FP / benign | FP rate | FP MALICIOUS | FP RISKY | FP UNVERIFIABLE | errors | median s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| all | safeloadai | 0 / 0 | 171 / 435 | 0.3931 | 6 | 30 | 135 | 0 | 0.5053 | 1.4165 |

### hf-tune: per format

| format | tool | detected / malicious | FP / benign | FP rate | FP MALICIOUS | FP RISKY | FP UNVERIFIABLE | errors | median s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| h5 | safeloadai | 0 / 0 | 7 / 63 | 0.1111 | 1 | 1 | 5 | 0 | 0.6358 | 1.0971 |
| joblib | safeloadai | 0 / 0 | 26 / 48 | 0.5417 | 0 | 2 | 24 | 0 | 0.4691 | 1.6041 |
| keras | safeloadai | 0 / 0 | 28 / 65 | 0.4308 | 1 | 5 | 22 | 0 | 0.0219 | 0.4409 |
| pickle | safeloadai | 0 / 0 | 44 / 75 | 0.5867 | 2 | 3 | 39 | 0 | 0.5199 | 0.9976 |
| torch | safeloadai | 0 / 0 | 66 / 184 | 0.3587 | 2 | 19 | 45 | 0 | 0.5817 | 1.6033 |

### hf-tune: per library

| library | tool | detected / malicious | FP / benign | FP rate | FP MALICIOUS | FP RISKY | FP UNVERIFIABLE | errors | median s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| h5 | safeloadai | 0 / 0 | 7 / 63 | 0.1111 | 1 | 1 | 5 | 0 | 0.6358 | 1.0971 |
| keras | safeloadai | 0 / 0 | 28 / 65 | 0.4308 | 1 | 5 | 22 | 0 | 0.0219 | 0.4409 |
| pandas | safeloadai | 0 / 0 | 9 / 9 | 1.0 | 0 | 0 | 9 | 0 | 0.4404 | 0.5201 |
| sklearn | safeloadai | 0 / 0 | 42 / 86 | 0.4884 | 2 | 5 | 35 | 0 | 0.5132 | 1.5527 |
| sklearn_gbdt | safeloadai | 0 / 0 | 19 / 28 | 0.6786 | 0 | 0 | 19 | 0 | 0.4938 | 0.9732 |
| torch_sentence_transformers | safeloadai | 0 / 0 | 12 / 26 | 0.4615 | 0 | 9 | 3 | 0 | 0.4654 | 1.1129 |
| torch_timm | safeloadai | 0 / 0 | 0 / 31 | 0.0 | 0 | 0 | 0 | 0 | 0.7951 | 1.6033 |
| torch_training_args | safeloadai | 0 / 0 | 1 / 2 | 0.5 | 0 | 0 | 1 | 0 | 0.4504 | 0.5158 |
| torch_transformers | safeloadai | 0 / 0 | 26 / 98 | 0.2653 | 0 | 10 | 16 | 0 | 0.4786 | 1.0621 |
| torch_ultralytics | safeloadai | 0 / 0 | 27 / 27 | 1.0 | 2 | 0 | 25 | 0 | 1.2206 | 2.2667 |

### hf-heldout: total

| set | tool | detected / malicious | FP / benign | FP rate | FP MALICIOUS | FP RISKY | FP UNVERIFIABLE | errors | median s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| all | safeloadai | 0 / 0 | 189 / 508 | 0.372 | 11 | 47 | 131 | 0 | 0.4809 | 1.3668 |

### hf-heldout: per format

| format | tool | detected / malicious | FP / benign | FP rate | FP MALICIOUS | FP RISKY | FP UNVERIFIABLE | errors | median s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| h5 | safeloadai | 0 / 0 | 12 / 87 | 0.1379 | 2 | 1 | 9 | 0 | 0.5712 | 1.0262 |
| joblib | safeloadai | 0 / 0 | 22 / 38 | 0.5789 | 0 | 4 | 18 | 0 | 0.4633 | 2.6623 |
| keras | safeloadai | 0 / 0 | 29 / 75 | 0.3867 | 2 | 6 | 21 | 0 | 0.0171 | 0.5201 |
| pickle | safeloadai | 0 / 0 | 28 / 55 | 0.5091 | 2 | 1 | 25 | 0 | 0.4637 | 1.5969 |
| torch | safeloadai | 0 / 0 | 98 / 253 | 0.3874 | 5 | 35 | 58 | 0 | 0.5294 | 1.4702 |

### hf-heldout: per library

| library | tool | detected / malicious | FP / benign | FP rate | FP MALICIOUS | FP RISKY | FP UNVERIFIABLE | errors | median s | p95 s |
|---|---|---|---|---|---|---|---|---|---|---|
| h5 | safeloadai | 0 / 0 | 12 / 87 | 0.1379 | 2 | 1 | 9 | 0 | 0.5712 | 1.0262 |
| keras | safeloadai | 0 / 0 | 29 / 75 | 0.3867 | 2 | 6 | 21 | 0 | 0.0171 | 0.5201 |
| pandas | safeloadai | 0 / 0 | 7 / 7 | 1.0 | 1 | 0 | 6 | 0 | 0.4192 | 0.4704 |
| sklearn | safeloadai | 0 / 0 | 29 / 64 | 0.4531 | 1 | 5 | 23 | 0 | 0.4763 | 1.5969 |
| sklearn_gbdt | safeloadai | 0 / 0 | 14 / 22 | 0.6364 | 0 | 0 | 14 | 0 | 0.4601 | 0.723 |
| torch_sentence_transformers | safeloadai | 0 / 0 | 15 / 34 | 0.4412 | 0 | 15 | 0 | 0 | 0.4436 | 1.193 |
| torch_timm | safeloadai | 0 / 0 | 0 / 29 | 0.0 | 0 | 0 | 0 | 0 | 0.8238 | 1.3985 |
| torch_training_args | safeloadai | 0 / 0 | 3 / 5 | 0.6 | 0 | 0 | 3 | 0 | 0.4345 | 0.4676 |
| torch_transformers | safeloadai | 0 / 0 | 47 / 152 | 0.3092 | 0 | 20 | 27 | 0 | 0.4623 | 1.2317 |
| torch_ultralytics | safeloadai | 0 / 0 | 33 / 33 | 1.0 | 5 | 0 | 28 | 0 | 1.3573 | 1.9999 |

safeloadai layer contribution on malicious files: static only 0, emulation only 0, both 0, neither 0.

## safeloadai false positives

Allowlist entries the flagged benign files would need, over every group except `hf-heldout` (review each; none is added automatically):

| missing entry | files | examples |
|---|---|---|
| `torch.nn.modules.activation.SiLU` | 27 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Bingsu/adetailer/face_yolov8n.pt |
| `torch.nn.modules.batchnorm.BatchNorm2d` | 27 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Bingsu/adetailer/face_yolov8n.pt |
| `torch.nn.modules.container.ModuleList` | 27 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Bingsu/adetailer/face_yolov8n.pt |
| `torch.nn.modules.container.Sequential` | 27 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Bingsu/adetailer/face_yolov8n.pt |
| `torch.nn.modules.conv.Conv2d` | 27 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Bingsu/adetailer/face_yolov8n.pt |
| `torch.nn.modules.pooling.MaxPool2d` | 24 | Bingsu/adetailer/face_yolov8n.pt, Bingsu/adetailer/hand_yolov8n.pt, Hansung-Cho/yolov8-ppe-detection/best.pt |
| `torch.nn.modules.upsampling.Upsample` | 24 | Bingsu/adetailer/face_yolov8n.pt, Bingsu/adetailer/hand_yolov8n.pt, Hansung-Cho/yolov8-ppe-detection/best.pt |
| `ultralytics.nn.modules.conv.Conv` | 22 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Bingsu/adetailer/face_yolov8n.pt |
| `ultralytics.nn.modules.block.Bottleneck` | 21 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Bingsu/adetailer/face_yolov8n.pt |
| `ultralytics.nn.modules.conv.Concat` | 19 | Bingsu/adetailer/face_yolov8n.pt, Bingsu/adetailer/hand_yolov8n.pt, Hansung-Cho/yolov8-ppe-detection/best.pt |
| `ultralytics.nn.tasks.DetectionModel` | 19 | Bingsu/adetailer/face_yolov8n.pt, Bingsu/adetailer/hand_yolov8n.pt, Hansung-Cho/yolov8-ppe-detection/best.pt |
| `xgboost.core.Booster` | 19 | AAUBS/hotel-cancellation-model/model.joblib, BrianDsouzaAI/autotrain-tab-multi-92337144714/model.joblib, EnerTEF/Performance-Evaluation-of-Energy-Forecasts-Service/model.joblib |
| `ultralytics.nn.modules.block.SPPF` | 18 | Bingsu/adetailer/face_yolov8n.pt, Bingsu/adetailer/hand_yolov8n.pt, Hansung-Cho/yolov8-ppe-detection/best.pt |
| `accelerate.state.PartialState` | 17 | Arunavaonly/Bangla-twoclass-Sentiment-Analyzer/training_args.bin, ISxOdin/vit-base-oxford-iiit-pets/training_args.bin, JackFram/llama-68m/training_args.bin |
| `ultralytics.nn.modules.block.DFL` | 17 | Bingsu/adetailer/face_yolov8n.pt, Bingsu/adetailer/hand_yolov8n.pt, Hansung-Cho/yolov8-ppe-detection/best.pt |
| `ultralytics.nn.modules.head.Detect` | 16 | Bingsu/adetailer/face_yolov8n.pt, Bingsu/adetailer/hand_yolov8n.pt, Hansung-Cho/yolov8-ppe-detection/best.pt |
| `ultralytics.nn.modules.block.C2f` | 13 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Bingsu/adetailer/face_yolov8n.pt |
| `sklearn.preprocessing._encoders.OrdinalEncoder` | 12 | Fatihrizkia/autotrain-xauusdh4timestamp-100145147571/model.joblib, adgrowr/autotrain-negative-keywords-classifier-61622134846/model.joblib, aduzlo/zello-valid-trial-v3.2/valid_trial_v3_2.joblib |
| `torch.nn.modules.linear.Identity` | 11 | MykolaL/DelineateAnything/DelineateAnything-S.pt, RoyRud1902/yolo11n-text/best.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `dabl.preprocessing.EasyPreprocessor` | 11 | Fulccrum/trainii_ac94u-label-classification/clf.pkl, Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl |
| `pandas._libs.internals._unpickle_block` | 11 | Fulccrum/trainii_ac94u-label-classification/clf.pkl, Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl |
| `pandas.core.frame.DataFrame` | 11 | Fulccrum/trainii_ac94u-label-classification/clf.pkl, Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl |
| `pandas.core.internals.managers.BlockManager` | 11 | Fulccrum/trainii_ac94u-label-classification/clf.pkl, Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl |
| `pandas.core.internals.managers.SingleBlockManager` | 11 | Fulccrum/trainii_ac94u-label-classification/clf.pkl, Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl |
| `pandas.core.series.Series` | 11 | Fulccrum/trainii_ac94u-label-classification/clf.pkl, Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl |
| `xgboost.sklearn.XGBClassifier` | 11 | AAUBS/hotel-cancellation-model/model.joblib, BrianDsouzaAI/autotrain-tab-multi-92337144714/model.joblib, M-Ahmad-Abid/Diabetes_model/model.joblib |
| `dabl.models.SimpleClassifier` | 10 | Fulccrum/trainii_ac94u-label-classification/clf.pkl, Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl |
| `sklearn.model_selection._split.StratifiedKFold` | 10 | Ramos-Ramos/emb-gam-dino-resnet/model.pkl, Ramos-Ramos/emb-gam-dino/model.pkl, Ramos-Ramos/emb-gam-resnet/model.pkl |
| `ultralytics.nn.modules.conv.DWConv` | 9 | MykolaL/DelineateAnything/DelineateAnything-S.pt, RoyRud1902/yolo11n-text/best.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `sklearn.impute._base.MissingIndicator` | 9 | Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl, haizad/ames-housing-gbdt-predictor/model.pkl |
| `ultralytics.nn.modules.block.Attention` | 8 | MykolaL/DelineateAnything/DelineateAnything-S.pt, RoyRud1902/yolo11n-text/best.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `ultralytics.nn.modules.block.C2PSA` | 8 | MykolaL/DelineateAnything/DelineateAnything-S.pt, RoyRud1902/yolo11n-text/best.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `ultralytics.nn.modules.block.C3k` | 8 | MykolaL/DelineateAnything/DelineateAnything-S.pt, RoyRud1902/yolo11n-text/best.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `ultralytics.nn.modules.block.C3k2` | 8 | MykolaL/DelineateAnything/DelineateAnything-S.pt, RoyRud1902/yolo11n-text/best.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `ultralytics.nn.modules.block.PSABlock` | 8 | MykolaL/DelineateAnything/DelineateAnything-S.pt, RoyRud1902/yolo11n-text/best.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `xgboost.sklearn.XGBRegressor` | 8 | EnerTEF/Performance-Evaluation-of-Energy-Forecasts-Service/model.joblib, Fatihrizkia/autotrain-xauusdh4timestamp-100145147571/model.joblib, IMFAA/Magnet_Tc_predictor/Magnet_Tc_predictor.joblib |
| `xgboost.compat.XGBoostLabelEncoder` | 8 | BrianDsouzaAI/autotrain-tab-multi-92337144714/model.joblib, M-Ahmad-Abid/Diabetes_model/model.joblib, Wei-Meng/autotrain-diabetes-86722143226/model.joblib |
| `gymnasium.spaces.box.Box` | 8 | Destiny0621/a2c-PandaStack-v3/vec_normalize.pkl, Edgar404/a2c-PandaStackDense-v3/vec_normalize.pkl, Edgar404/td3-PandaStackDense-v3/vec_normalize.pkl |
| `gymnasium.spaces.dict.Dict` | 8 | Destiny0621/a2c-PandaStack-v3/vec_normalize.pkl, Edgar404/a2c-PandaStackDense-v3/vec_normalize.pkl, Edgar404/td3-PandaStackDense-v3/vec_normalize.pkl |
| `stable_baselines3.common.running_mean_std.RunningMeanStd` | 8 | Destiny0621/a2c-PandaStack-v3/vec_normalize.pkl, Edgar404/a2c-PandaStackDense-v3/vec_normalize.pkl, Edgar404/td3-PandaStackDense-v3/vec_normalize.pkl |
| `stable_baselines3.common.vec_env.vec_normalize.VecNormalize` | 8 | Destiny0621/a2c-PandaStack-v3/vec_normalize.pkl, Edgar404/a2c-PandaStackDense-v3/vec_normalize.pkl, Edgar404/td3-PandaStackDense-v3/vec_normalize.pkl |
| `pandas.core.dtypes.dtypes.CategoricalDtype` | 7 | Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl, maderix/titanic_traink4m62li8-survived-classification/clf.pkl |
| `numpy.ma.core.MaskedArray` | 7 | kushkul/rf_model_skops/rf_model.pkl, osanseviero/hf_hub_example-023f3150-3eae-45a4-bd3c-7a95639e10e0/skops-9053e41j.pkl, osanseviero/hf_hub_example-821defb0-1482-4d27-884d-4359bfad704f/skops-k4xq5xio.pkl |
| `numpy.ma.core._mareconstruct` | 7 | kushkul/rf_model_skops/rf_model.pkl, osanseviero/hf_hub_example-023f3150-3eae-45a4-bd3c-7a95639e10e0/skops-9053e41j.pkl, osanseviero/hf_hub_example-821defb0-1482-4d27-884d-4359bfad704f/skops-k4xq5xio.pkl |
| `sklearn.metrics._scorer._passthrough_scorer` | 7 | kushkul/rf_model_skops/rf_model.pkl, osanseviero/hf_hub_example-023f3150-3eae-45a4-bd3c-7a95639e10e0/skops-9053e41j.pkl, osanseviero/hf_hub_example-821defb0-1482-4d27-884d-4359bfad704f/skops-k4xq5xio.pkl |
| `transformers.trainer_pt_utils.AcceleratorConfig` | 6 | ISxOdin/vit-base-oxford-iiit-pets/training_args.bin, empero-ai/Qwen3.8-4B-Distill/training_args.bin, hotchpotch/japanese-reranker-cross-encoder-small-v1/training_args.bin |
| `sklearn.metrics._ranking.average_precision_score` | 6 | Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl, maderix/titanic_traink4m62li8-survived-classification/clf.pkl |
| `sklearn.metrics._scorer._ThresholdScorer` | 6 | Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl, cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl, maderix/titanic_traink4m62li8-survived-classification/clf.pkl |
| `sklearn.model_selection._search_successive_halving.HalvingGridSearchCV` | 6 | osanseviero/hf_hub_example-023f3150-3eae-45a4-bd3c-7a95639e10e0/skops-9053e41j.pkl, osanseviero/hf_hub_example-821defb0-1482-4d27-884d-4359bfad704f/skops-k4xq5xio.pkl, osanseviero/hf_hub_example-f7d1d7e5-f207-4eef-99bb-57408d604e2b/skops-texalxld.pkl |
| `ultralytics.nn.modules.Bottleneck` | 5 | MidnightRunner/Ultralytics/bbox/face_yolov8n.pt, MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.C2f` | 5 | MidnightRunner/Ultralytics/bbox/face_yolov8n.pt, MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.Concat` | 5 | MidnightRunner/Ultralytics/bbox/face_yolov8n.pt, MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.Conv` | 5 | MidnightRunner/Ultralytics/bbox/face_yolov8n.pt, MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.DFL` | 5 | MidnightRunner/Ultralytics/bbox/face_yolov8n.pt, MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.Detect` | 5 | MidnightRunner/Ultralytics/bbox/face_yolov8n.pt, MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.SPPF` | 5 | MidnightRunner/Ultralytics/bbox/face_yolov8n.pt, MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.yolo.utils.IterableSimpleNamespace` | 5 | MidnightRunner/Ultralytics/bbox/face_yolov8n.pt, MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `sklearn.preprocessing._data.MinMaxScaler` | 5 | TWLab/femtosecond-laser-hydrogel-etching-model/scaler_X.joblib, TWLab/femtosecond-laser-hydrogel-etching-model/scaler_y.joblib, jirkoru/TemporalRegressionV2/model.pkl |
| `torch.nn.modules.linear.Linear` | 4 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `transformers.trainer_utils.SaveStrategy` | 4 | ISxOdin/vit-base-oxford-iiit-pets/training_args.bin, empero-ai/Qwen3.8-4B-Distill/training_args.bin, hotchpotch/japanese-reranker-small-v2/training_args.bin |
| `sklearn._loss._loss.__pyx_unpickle_CyHalfBinomialLoss` | 4 | osanseviero/hf_hub_example-023f3150-3eae-45a4-bd3c-7a95639e10e0/skops-9053e41j.pkl, osanseviero/hf_hub_example-821defb0-1482-4d27-884d-4359bfad704f/skops-k4xq5xio.pkl, osanseviero/hf_hub_example-f7d1d7e5-f207-4eef-99bb-57408d604e2b/skops-texalxld.pkl |
| `sklearn.linear_model._logistic.LogisticRegressionCV` | 4 | Ramos-Ramos/emb-gam-dino-resnet/model.pkl, Ramos-Ramos/emb-gam-dino/model.pkl, Ramos-Ramos/emb-gam-resnet/model.pkl |
| `keras.layers.TFSMLayer` | 4 | hzhongresearch/yamnetp_ahead_ds/yamnetp_ahead_ds_random.keras, hzhongresearch/yamnetp_ahead_ds/yamnetp_ahead_ds_unfreeze_last.keras, niobures/YAMNet/yamnetp_ahead_ds/yamnetp_ahead_ds_random.keras |
| `torch.nn.modules.conv.ConvTranspose2d` | 3 | MykolaL/DelineateAnything/DelineateAnything-S.pt, Ultralytics/YOLO11/yolo11n-seg.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.tasks.SegmentationModel` | 3 | MykolaL/DelineateAnything/DelineateAnything-S.pt, Ultralytics/YOLO11/yolo11n-seg.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `torch.nn.modules.dropout.Dropout` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `torch.nn.modules.pooling.AdaptiveAvgPool2d` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `torchvision.transforms.functional.InterpolationMode` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `torchvision.transforms.transforms.CenterCrop` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `torchvision.transforms.transforms.Compose` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `torchvision.transforms.transforms.Normalize` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `torchvision.transforms.transforms.Resize` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `torchvision.transforms.transforms.ToTensor` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `ultralytics.nn.modules.head.Classify` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `ultralytics.nn.tasks.ClassificationModel` | 3 | Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt, Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt, Ultralytics/YOLO26/yolo26n-cls.pt |
| `sklearn.compose._column_transformer.make_column_selector` | 3 | haizad/ames-housing-gbdt-predictor/model.pkl, haizad/ames-housing-random-forest-predictor/model.pkl, scikit-learn/Fish-Weight/example.pkl |
| `__builtin__.getattr` | 2 | Ultralytics/YOLO11/yolo11n-seg.pt, keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.block.Proto` | 2 | MykolaL/DelineateAnything/DelineateAnything-S.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `ultralytics.nn.modules.head.Segment` | 2 | MykolaL/DelineateAnything/DelineateAnything-S.pt, Ultralytics/YOLO11/yolo11n-seg.pt |
| `torch.nn.modules.loss.BCEWithLogitsLoss` | 2 | MykolaL/DelineateAnything/DelineateAnything-S.pt, leoxs22/manga-panel-detector-yolo26n/manga_panel_detector_fp32.pt |
| `ultralytics.utils.IterableSimpleNamespace` | 2 | MykolaL/DelineateAnything/DelineateAnything-S.pt, leoxs22/manga-panel-detector-yolo26n/manga_panel_detector_fp32.pt |
| `ultralytics.utils.loss.BboxLoss` | 2 | MykolaL/DelineateAnything/DelineateAnything-S.pt, leoxs22/manga-panel-detector-yolo26n/manga_panel_detector_fp32.pt |
| `ultralytics.utils.tal.TaskAlignedAssigner` | 2 | MykolaL/DelineateAnything/DelineateAnything-S.pt, leoxs22/manga-panel-detector-yolo26n/manga_panel_detector_fp32.pt |
| `ultralytics.nn.modules.head.Pose` | 2 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolo11n_640.pt, mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `ultralytics.nn.tasks.PoseModel` | 2 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolo11n_640.pt, mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `yart.arguments.RankerTrainingArguments` | 2 | hotchpotch/japanese-reranker-small-v2/training_args.bin, hotchpotch/japanese-reranker-xsmall-v2/training_args.bin |
| `sklearn.ensemble._hist_gradient_boosting.loss.BinaryCrossEntropy` | 2 | vendorabc/modelhubexample/skops-3voi5107.pkl, vendorabc/modeltest/skops-v5dfi0sh.pkl |
| `sklearn.tree._classes.ExtraTreeRegressor` | 2 | IMFAA/Magnet_Tc_predictor/Magnet_Tc_predictor.joblib, sklearn-docs/anomaly-detection/isolation_forest.pkl |
| `sklearn.preprocessing._function_transformer.FunctionTransformer` | 2 | Alassea/middle-dutch-NER_text-classification/middle_dutch_text-classification.pkl, aduzlo/zello-valid-trial-v3.2/valid_trial_v3_2.joblib |
| `builtins.object` | 2 | haizad/ames-housing-gbdt-predictor/model.pkl, haizad/ames-housing-random-forest-predictor/model.pkl |
| `numpy.number` | 2 | haizad/ames-housing-gbdt-predictor/model.pkl, haizad/ames-housing-random-forest-predictor/model.pkl |
| `builtins.binary_focal_loss` | 2 | Blagoja/ecg-ptbxl-classification/ecg_cnn_final.keras, Steenslid/ecg-ptbxl-classification/ecg_cnn_final.keras |
| `keras.layers.Lambda.eval` | 2 | ScanMe/test-models/eval_lambda.h5, ScanMe/test-models/eval_lambda.keras |
| `Custom>GraphConvLayer.registered_name` | 2 | DaneshSelwal/Classification-DIAS-65Bands/spatialgcn/models/SpatialGCN_best.keras, DaneshSelwal/Classification-DIAS-65Bands/spatialgcn/models/SpatialGCN_final.keras |
| `None.GraphConvLayer` | 2 | DaneshSelwal/Classification-DIAS-65Bands/spatialgcn/models/SpatialGCN_best.keras, DaneshSelwal/Classification-DIAS-65Bands/spatialgcn/models/SpatialGCN_final.keras |
| `None.FocalLoss` | 2 | Neural-Network-Project/ECG-Disease-Classifier/checkpoints/checkpoint_epoch_10.keras, Neural-Network-Project/ECG-Disease-Classifier/checkpoints/checkpoint_epoch_11.keras |
| `builtins.mae_metric` | 2 | manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed17/stage4_best.keras, manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed43/stage4_best.keras |
| `builtins.psnr_metric` | 2 | manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed17/stage4_best.keras, manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed43/stage4_best.keras |
| `builtins.ssim_metric` | 2 | manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed17/stage4_best.keras, manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed43/stage4_best.keras |
| `builtins.stage4_loss_without_none` | 2 | manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed17/stage4_best.keras, manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed43/stage4_best.keras |
| `eca_ldnet.callbacks.WarmupCosineDecay` | 2 | manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed17/stage4_best.keras, manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed43/stage4_best.keras |
| `eca_ldnet.layers.PhysicsCorrectionLayer` | 2 | manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed17/stage4_best.keras, manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed43/stage4_best.keras |
| `builtins._loss` | 2 | abulhawa/industrial-component-anomaly-detection-models/keras_cae/1311f434dab3/model.keras, abulhawa/industrial-component-anomaly-detection-models/keras_cae/4142578a023d/model.keras |
| `Custom>CoordConv2D.registered_name` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `Custom>F1Score.registered_name` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `Custom>FastNormalize.registered_name` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `Custom>FillNaNs.registered_name` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `None.FastNormalize` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `None.FillNaNs` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `None.WarmUpCosine` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.metrics.keras.metrics.BinaryAccuracy` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.metrics.keras.metrics.F1Score` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.metrics.keras.metrics.FalseNegatives` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.metrics.keras.metrics.FalsePositives` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.metrics.keras.metrics.Precision` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.metrics.keras.metrics.Recall` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.metrics.keras.metrics.TrueNegatives` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.metrics.keras.metrics.TruePositives` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `tornet.models.keras.layers.CoordConv2D` | 2 | Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras, Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras |
| `None.BackbonePreprocess` | 2 | GimhanSathsara843/cataract-classifier/artifacts/best_finetune.keras, GimhanSathsara843/cataract-classifier/artifacts/best_head.keras |
| `None.ChannelPool` | 2 | GimhanSathsara843/cataract-classifier/artifacts/best_finetune.keras, GimhanSathsara843/cataract-classifier/artifacts/best_head.keras |
| `cataract>BackbonePreprocess.registered_name` | 2 | GimhanSathsara843/cataract-classifier/artifacts/best_finetune.keras, GimhanSathsara843/cataract-classifier/artifacts/best_head.keras |
| `cataract>ChannelPool.registered_name` | 2 | GimhanSathsara843/cataract-classifier/artifacts/best_finetune.keras, GimhanSathsara843/cataract-classifier/artifacts/best_head.keras |
| `keras.metrics.R2Score` | 2 | Organic-Battery-Predictor/property-predictor-model/MTML_fold_3.keras, Organic-Battery-Predictor/property-predictor-model/MetaLearner.keras |
| `loss/metric.cost_sensitive_loss` | 2 | sergiok777/roboadvisor-emociones/modelo_1.h5, sergiok777/roboadvisor-emociones/modelo_7.h5 |
| `loss/metric.auc` | 2 | kovidritesh/scene-dataset/shoe_cnn/best_model.h5, kovidritesh/scene-dataset/shoe_cnn/shoe_cnn_20260503_142829.h5 |
| `trl.trainer.sft_config.SFTConfig` | 1 | empero-ai/Qwen3.8-4B-Distill/training_args.bin |
| `argparse.Namespace` | 1 | Davlan/xlm-roberta-base-ner-hrl/training_args.bin |
| `transformers.trainer_utils.EvaluationStrategy` | 1 | yiyanghkust/finbert-esg/training_args.bin |
| `accelerate.utils.dataclasses.DeepSpeedPlugin` | 1 | zhiqiulin/clip-flant5-xl/training_args.bin |
| `llava.train.train.TrainingArguments` | 1 | zhiqiulin/clip-flant5-xl/training_args.bin |
| `transformers.deepspeed.HfDeepSpeedConfig` | 1 | zhiqiulin/clip-flant5-xl/training_args.bin |
| `transformers.deepspeed.HfTrainerDeepSpeedConfig` | 1 | zhiqiulin/clip-flant5-xl/training_args.bin |
| `ultralytics.utils.loss.DFLoss` | 1 | MykolaL/DelineateAnything/DelineateAnything-S.pt |
| `ultralytics.utils.loss.v8SegmentationLoss` | 1 | MykolaL/DelineateAnything/DelineateAnything-S.pt |
| `ultralytics.utils.loss.E2ELoss` | 1 | leoxs22/manga-panel-detector-yolo26n/manga_panel_detector_fp32.pt |
| `ultralytics.utils.loss.v8DetectionLoss` | 1 | leoxs22/manga-panel-detector-yolo26n/manga_panel_detector_fp32.pt |
| `ultralytics.nn.modules.Proto` | 1 | keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.Segment` | 1 | keremberke/yolov8m-building-segmentation/best.pt |
| `ultralytics.nn.modules.block.AConv` | 1 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `ultralytics.nn.modules.block.ELAN1` | 1 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `ultralytics.nn.modules.block.RepBottleneck` | 1 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `ultralytics.nn.modules.block.RepCSP` | 1 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `ultralytics.nn.modules.block.RepNCSPELAN4` | 1 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `ultralytics.nn.modules.block.SPPELAN` | 1 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `ultralytics.nn.modules.conv.RepConv` | 1 | mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt |
| `__main__.MyPipeline` | 1 | scikit-learn-examples/example/sklearn_model.joblib |
| `__main__.SVC` | 1 | nateraw/iris-svc/sklearn_model.joblib |
| `imodels.tree.figs.FIGSClassifier` | 1 | imodels/figs-compas-recidivism/sklearn_model.joblib |
| `imodels.tree.figs.Node` | 1 | imodels/figs-compas-recidivism/sklearn_model.joblib |
| `autogluon.common.features.feature_metadata.FeatureMetadata` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.core.data.cleaner.CleanerDummy` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.core.data.label_cleaner.LabelCleanerBinary` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.core.metrics._ClassScorer` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.core.models.ensemble.stacker_ensemble_model.StackerEnsembleModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.core.models.ensemble.weighted_ensemble_model.WeightedEnsembleModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.core.models.greedy_ensemble.greedy_weighted_ensemble_model.GreedyWeightedEnsembleModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.features.generators.astype.AsTypeFeatureGenerator` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.features.generators.auto_ml_pipeline.AutoMLPipelineFeatureGenerator` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.features.generators.drop_duplicates.DropDuplicatesFeatureGenerator` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.features.generators.drop_unique.DropUniqueFeatureGenerator` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.features.generators.fillna.FillNaFeatureGenerator` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.features.generators.identity.IdentityFeatureGenerator` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.learner.default_learner.DefaultLearner` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.models.fastainn.tabular_nn_fastai.NNFastAiTabularModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.models.lgb.lgb_model.LGBModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.models.rf.rf_model.RFModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.models.tabular_nn.torch.tabular_nn_torch.TabularNeuralNetTorchModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.models.xgboost.xgboost_model.XGBoostModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.models.xt.xt_model.XTModel` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.predictor.predictor.TabularPredictor` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `autogluon.tabular.trainer.auto_trainer.AutoTrainer` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `networkx.classes.digraph.DiGraph` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `networkx.classes.reportviews.NodeView` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `sklearn.metrics._classification.f1_score` | 1 | kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl |
| `_loss.CyHalfBinomialLoss` | 1 | imshriya/mlforge-cicd-test-model/sgd_classifier.pkl |
| `dabl.models.SimpleRegressor` | 1 | srg/outhimar_64-Close-regression/clf.pkl |
| `sklearn.model_selection._search.RandomizedSearchCV` | 1 | kushkul/rf_model_skops/rf_model.pkl |
| `sklearn.ensemble._gb_losses.LeastSquaresError` | 1 | scikit-learn/Fish-Weight/example.pkl |
| `sklearn.ensemble._forest.ExtraTreesRegressor` | 1 | IMFAA/Magnet_Tc_predictor/Magnet_Tc_predictor.joblib |
| `sklearn.ensemble._voting.VotingRegressor` | 1 | IMFAA/Magnet_Tc_predictor/Magnet_Tc_predictor.joblib |
| `sklearn.ensemble._weight_boosting.AdaBoostRegressor` | 1 | IMFAA/Magnet_Tc_predictor/Magnet_Tc_predictor.joblib |
| `sklearn.utils.Bunch` | 1 | IMFAA/Magnet_Tc_predictor/Magnet_Tc_predictor.joblib |
| `sklearn.naive_bayes.ComplementNB` | 1 | Ozziey/poet-type-model/Pickle_HME_Model.pkl |
| `numpy.int64` | 1 | Alassea/middle-dutch-NER_text-classification/middle_dutch_text-classification.pkl |
| `sklearn.feature_extraction.text.CountVectorizer` | 1 | Alassea/middle-dutch-NER_text-classification/middle_dutch_text-classification.pkl |
| `sklearn.linear_model._passive_aggressive.PassiveAggressiveClassifier` | 1 | Alassea/middle-dutch-NER_text-classification/middle_dutch_text-classification.pkl |
| `train_huggingface_pipeline.revert_data` | 1 | Alassea/middle-dutch-NER_text-classification/middle_dutch_text-classification.pkl |
| `daal4py._daal4py._rebuild` | 1 | BenjaminB/knn-example-intelex-c035ccff-d23b-4e02-97bd-14cf3cb0bde5/model-optimized.pkl |
| `daal4py._daal4py.kdtree_knn_classification_model` | 1 | BenjaminB/knn-example-intelex-c035ccff-d23b-4e02-97bd-14cf3cb0bde5/model-optimized.pkl |
| `onedal.neighbors.neighbors.KNeighborsClassifier` | 1 | BenjaminB/knn-example-intelex-c035ccff-d23b-4e02-97bd-14cf3cb0bde5/model-optimized.pkl |
| `sklearnex.neighbors.knn_classification.KNeighborsClassifier` | 1 | BenjaminB/knn-example-intelex-c035ccff-d23b-4e02-97bd-14cf3cb0bde5/model-optimized.pkl |
| `sklearn.ensemble._iforest.IsolationForest` | 1 | sklearn-docs/anomaly-detection/isolation_forest.pkl |
| `sklearn._loss._loss.__pyx_unpickle_CyHalfSquaredError` | 1 | haizad/ames-housing-gbdt-predictor/model.pkl |
| `sklearn.ensemble._hist_gradient_boosting.gradient_boosting.HistGradientBoostingRegressor` | 1 | haizad/ames-housing-gbdt-predictor/model.pkl |
| `sklearn.linear_model._sgd_fast.ModifiedHuber` | 1 | Jayabalambika/MCI/sgd_model.pkl |
| `sklearn.metrics._dist_metrics.ManhattanDistance64` | 1 | sulpha/BDM_Preject_model/model.pkl |
| `sklearn.neighbors._regression.KNeighborsRegressor` | 1 | sulpha/BDM_Preject_model/model.pkl |
| `sklearn.compose._column_transformer._RemainderColsList` | 1 | AAUBS/hotel-cancellation-model/model.joblib |
| `pandas.io.pickle.read_pickle` | 1 | security-finder-1/017-picklescan-bypass-pandas-read-pickle-ace/017_poc_picklescan_bypass_pandas_read_pickle_nested_ACE.joblib |
| `keras_self_attention.seq_self_attention.SeqSelfAttention` | 1 | Reynier/moe-wordlist-dga-models/models/labin/LABin_best_model_2025-05-30_15_26_47.keras |
| `keras_self_attention.seq_weighted_attention.SeqWeightedAttention` | 1 | Reynier/moe-wordlist-dga-models/models/labin/LABin_best_model_2025-05-30_15_26_47.keras |
| `builtins.bbox_ciou_loss` | 1 | hugocornellier/cat-face-landmarks/keras/localizer_224.keras |
| `builtins.bbox_iou_metric` | 1 | hugocornellier/cat-face-landmarks/keras/localizer_224.keras |
| `keras.optimizers.legacy.Adam` | 1 | hugocornellier/cat-face-landmarks/keras/localizer_224.keras |
| `CatFLW>SoftArgmax2D.registered_name` | 1 | hugocornellier/cat-face-landmarks/keras/landmarks_mobilenetv3l_384.keras |
| `CatFLW>WarmupSchedule.registered_name` | 1 | hugocornellier/cat-face-landmarks/keras/landmarks_mobilenetv3l_384.keras |
| `None.SoftArgmax2D` | 1 | hugocornellier/cat-face-landmarks/keras/landmarks_mobilenetv3l_384.keras |
| `None.WarmupSchedule` | 1 | hugocornellier/cat-face-landmarks/keras/landmarks_mobilenetv3l_384.keras |
| `builtins.landmark_nme` | 1 | hugocornellier/cat-face-landmarks/keras/landmarks_mobilenetv3l_384.keras |
| `builtins.landmark_nme_iod` | 1 | hugocornellier/cat-face-landmarks/keras/landmarks_mobilenetv3l_384.keras |
| `keras.metrics.RootMeanSquaredError` | 1 | Organic-Battery-Predictor/property-predictor-model/MTML_fold_3.keras |
| `keras.src.applications.mobilenet_v2.<Lambda globals>` | 1 | qwertymaninwork/Plant_Disease_Detection_System/mobilenetv2_plant.h5 |
| `None.TrigConv2D` | 1 | RChhipa/brain-breast/trig_model.h5 |

False positives without a missing entry (first reason):

- 19 x [static] SUSPICIOUS: unrecognised file format
- 2 x [static] SUSPICIOUS: file extension '.keras' does not match its content (detected: pickle)
- 2 x [static] SUSPICIOUS: file extension '.keras' does not match its content (detected: h5)
- 1 x [static] SUSPICIOUS: <undecided>.<walk limit> is passed as a value at 2260440 (BUILD); it may only be called directly
- 1 x [static] SUSPICIOUS: <undecided>.<walk limit> is passed as a value at 3729005 (BUILD); it may only be called directly
- 1 x [static] SUSPICIOUS: <undecided>.<walk limit> is passed as a value at 4825347 (BUILD); it may only be called directly

## Files

| file | group | label | expected | safeloadai |  |
|---|---|---|---|---|
| sentence-transformers/all-MiniLM-L6-v2/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/all-MiniLM-L6-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| cross-encoder/ms-marco-MiniLM-L6-v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| cross-encoder/ms-marco-MiniLM-L6-v2/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| timm/mobilenetv3_small_100.lamb_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| ibm-granite/granite-embedding-small-english-r2/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| cross-encoder/ms-marco-MiniLM-L4-v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| cross-encoder/ms-marco-MiniLM-L4-v2/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| prithivMLmods/Gender-Classifier-Mini/checkpoint-157/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| prithivMLmods/Gender-Classifier-Mini/checkpoint-314/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| BAAI/bge-small-zh-v1.5/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| w11wo/indonesian-roberta-base-posp-tagger/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| facebook/dinov2-small/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/all-distilroberta-v1/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/all-MiniLM-L12-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| E-MIMIC/inclusively-reformulation-it5/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/vit_small_patch14_dinov2.lvd142m/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/resnet18.a1_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| cross-encoder/ms-marco-MiniLM-L12-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| timm/tf_efficientnetv2_s.in21k_ft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| Falconsai/nsfw_image_detection/falconsai_yolov9_nsfw_model_quantized.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Arunavaonly/Bangla-twoclass-Sentiment-Analyzer/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| timm/resnet50.a1_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| airesearch/wav2vec2-large-xlsr-53-th/scaler.pt | hf-heldout | benign | CLEAN | CLEAN |
| airesearch/wav2vec2-large-xlsr-53-th/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| gigant/romanian-wav2vec2/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-MiniLM-L6-v2/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-MiniLM-L6-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| kingabzpro/wav2vec2-large-xls-r-300m-Urdu/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| kingabzpro/wav2vec2-large-xls-r-300m-Urdu/language_model/5gram.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| HuggingFaceTB/SmolLM2-135M-Instruct/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| prithivida/parrot_paraphraser_on_T5/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| comodoro/wav2vec2-xls-r-300m-cs-250/rng_state.pth | hf-heldout | benign | CLEAN | CLEAN |
| Khalsuu/filipino-wav2vec2-l-xls-r-300m-official/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| imvladikon/wav2vec2-xls-r-300m-hebrew/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| NbAiLab/nb-wav2vec2-1b-bokmaal-v2/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| classla/wav2vec2-xls-r-parlaspeech-hr/scaler.pt | hf-tune | benign | CLEAN | CLEAN |
| classla/wav2vec2-xls-r-parlaspeech-hr/scheduler.pt | hf-tune | benign | CLEAN | CLEAN |
| 0bserverx/Qwen3.8-27B-Heretic-Abliterated-Uncensored-GGUF/xet_speed_test.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| 0bserverx/Qwen3.8-27B-Heretic-Abliterated-Uncensored-GGUF/xet_test_100mb.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| peft-internal-testing/tiny-clip-text-2/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| saattrupdan/wav2vec2-xls-r-300m-ftspeech/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| kresnik/wav2vec2-large-xlsr-korean/scaler.pt | hf-heldout | benign | CLEAN | CLEAN |
| kresnik/wav2vec2-large-xlsr-korean/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers-testing/stsb-bert-tiny-safetensors/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| albert/albert-base-v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| prajjwal1/bert-tiny/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sshleifer/tiny-gpt2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| NbAiLab/nb-wav2vec2-1b-nynorsk/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| amunchet/rorshark-vit-base/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| arijitx/wav2vec2-xls-r-300m-bengali/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/resnet34.a1_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/efficientnet_b0.ra_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| hubertsiuzdak/snac_24khz/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| eddiegulay/wav2vec2-large-xlsr-mvc-swahili/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| circulus/canvers-en2ko-v1/scaler.pt | hf-heldout | benign | CLEAN | CLEAN |
| circulus/canvers-en2ko-v1/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| circulus/canvers-ko2en-v1/scaler.pt | hf-tune | benign | CLEAN | CLEAN |
| circulus/canvers-ko2en-v1/scheduler.pt | hf-tune | benign | CLEAN | CLEAN |
| protectai/deberta-v3-base-prompt-injection-v2/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| facebook/esm2_t6_8M_UR50D/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-albert-small-v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-albert-small-v2/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/multi-qa-MiniLM-L6-cos-v1/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/multi-qa-MiniLM-L6-cos-v1/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| infinitejoy/wav2vec2-large-xls-r-300m-welsh/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| rhasspy/faster-whisper-tiny-int8/model.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| gagan3012/wav2vec2-xlsr-nepali/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| gagan3012/wav2vec2-xlsr-nepali/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| Babelscape/wikineural-multilingual-ner/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-MiniLM-L3-v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-MiniLM-L3-v2/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| microsoft/resnet-18/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| kredor/punctuate-all/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| EleutherAI/pythia-14m/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/repvgg_a0.rvgg_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| j-hartmann/emotion-english-distilroberta-base/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| m3hrdadfi/wav2vec2-large-xlsr-lithuanian/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| huawei-noah/TinyBERT_General_4L_312D/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| lxyuan/distilbert-base-multilingual-cased-sentiments-student/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| openbmb/MiniCPM-o-4_5/assets/token2wav/hift.pt | hf-tune | benign | CLEAN | CLEAN |
| segment-any-text/sat-3l-sm/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| alefiury/wav2vec2-large-xlsr-53-gender-recognition-librispeech/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| MilaNLProc/xlm-emo-t/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| julien-c/dummy-unknown/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| oliverguhr/german-sentiment-bert/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| cross-encoder/ms-marco-TinyBERT-L2-v2/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| cross-encoder/ms-marco-TinyBERT-L2-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| mattmdjaga/segformer_b2_clothes/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| mattmdjaga/segformer_b2_clothes/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| trl-internal-testing/tiny-random-LlamaForCausalLM/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| DrishtiSharma/wav2vec2-large-xls-r-300m-bg-d2/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| nvidia/LocateAnything-3B/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| E-MIMIC/inclusively-classification/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| SpideyDLK/wav2vec2-large-xls-r-300m-sinhala-low-LR-part1/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| microsoft/deberta-large-mnli/bpe_encoder.bin | hf-heldout | benign | CLEAN | CLEAN |
| kingabzpro/wav2vec2-large-xlsr-53-punjabi/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| kingabzpro/wav2vec2-large-xlsr-53-punjabi/language_model/3gram.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| gagan3012/wav2vec2-xlsr-khmer/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| gagan3012/wav2vec2-xlsr-khmer/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/vit_small_patch16_224.augreg_in21k_ft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| amoghsgopadi/wav2vec2-large-xlsr-kn/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| rhasspy/faster-whisper-base-int8/model.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| hustvl/vitmatte-small-composition-1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| zenosai/MonkeyOCRv2-B-Parsing/preprocessor1.pth | hf-tune | benign | CLEAN | CLEAN |
| OrdalieTech/Solon-embeddings-large-0.1/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| nvidia/segformer-b0-finetuned-ade-512-512/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/vit_small_patch14_reg4_dinov2.lvd142m/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| microsoft/resnet-50/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| hkunlp/instructor-large/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| Qwen/Qwen2.5-Omni-7B/spk_dict.pt | hf-tune | benign | CLEAN | CLEAN |
| facebook/mms-1b-all/adapter.kyg.bin | hf-heldout | benign | CLEAN | CLEAN |
| facebook/mms-1b-all/adapter.hnn.bin | hf-heldout | benign | CLEAN | CLEAN |
| cointegrated/rubert-tiny2/tinybert-ru-labse-adapter-v2.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| timm/vit_small_patch16_dinov3.lvd1689m/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| oliverguhr/fullstop-punctuation-multilang-large/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| typeform/distilbert-base-uncased-mnli/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| infinitejoy/wav2vec2-large-xls-r-300m-armenian/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| google/bert_uncased_L-2_H-128_A-2/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| tristayqc/my_zh_CN_asr_cv13_model/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| cross-encoder/nli-MiniLM2-L6-H768/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/msmarco-MiniLM-L6-v3/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/msmarco-MiniLM-L6-v3/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| stefan-it/wav2vec2-large-xlsr-53-basque/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| jimregan/wav2vec2-large-xlsr-latvian-cv/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| TaylorAI/bge-micro-v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| empero-ai/Qwen3.8-4B-Distill/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| HuggingFaceTB/SmolLM2-1.7B-Instruct/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| mrm8488/distilroberta-finetuned-financial-news-sentiment-analysis/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| HuggingFaceTB/SmolLM2-360M-Instruct/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| nijatzeynalov/wav2vec2-large-mms-1b-azerbaijani-common_voice15.0/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| timm/resnet18.a3_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/msmarco-distilbert-base-tas-b/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| DeepChem/ChemBERTa-77M-MTR/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| DeepChem/ChemBERTa-77M-MTR/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| roneneldan/TinyStories-1M/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| DeepChem/ChemBERTa-77M-MLM/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| DeepChem/ChemBERTa-77M-MLM/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| microsoft/deberta-xlarge-mnli/bpe_encoder.bin | hf-heldout | benign | CLEAN | CLEAN |
| ybelkada/tiny-random-T5ForConditionalGeneration-calibrated/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| GuardrailsAI/prompt-saturation-attack-detector/prompt_saturation_v3_1_final.pth | hf-heldout | benign | CLEAN | SUSPICIOUS |
| prajjwal1/bert-mini/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| classla/wav2vec2-xls-r-juznevesti-sr/scaler.pt | hf-heldout | benign | CLEAN | CLEAN |
| classla/wav2vec2-xls-r-juznevesti-sr/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| timm/densenet201.tv_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| gchhablani/wav2vec2-large-xlsr-gu/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| prithivMLmods/Common-Voice-Gender-Detection/checkpoint-3272/scaler.pt | hf-heldout | benign | CLEAN | CLEAN |
| prithivMLmods/Common-Voice-Gender-Detection/checkpoint-3272/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| Davlan/bert-base-multilingual-cased-ner-hrl/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| google/electra-small-discriminator/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/multi-qa-MiniLM-L6-dot-v1/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/multi-qa-MiniLM-L6-dot-v1/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| kykim/albert-kor-base/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| HadrianSecurity/subwiz/model_v2.pt | hf-heldout | benign | CLEAN | CLEAN |
| HadrianSecurity/subwiz/model.pt | hf-heldout | benign | CLEAN | CLEAN |
| dbdmg/wav2vec2-xls-r-300m-italian/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| Alimzhan/wav2vec2-large-xls-r-300m-albanian-colab/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Davlan/xlm-roberta-base-ner-hrl/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| Qwen/Qwen2.5-Omni-3B/spk_dict.pt | hf-tune | benign | CLEAN | CLEAN |
| timm/edgenext_small.usi_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| ihanif/wav2vec2-xls-r-300m-pashto/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/tf_mobilenetv3_large_minimal_100.in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/vit_tiny_patch16_224.augreg_in21k_ft_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| primeline/whisper-large-v3-turbo-german/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ISxOdin/vit-base-oxford-iiit-pets/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| nreimers/TinyBERT_L-4_H-312_v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/resnet50.fb_swsl_ig1b_ft_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| iiiorg/piiranha-v1-detect-personal-information/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| timm/regnety_032.ra_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| monologg/koelectra-small-v2-distilled-korquad-384/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| dslim/distilbert-NER/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/msmarco-MiniLM-L12-cos-v5/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| patrickvonplaten/t5-tiny-random/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| dima806/man_woman_face_image_detection/checkpoint-1326/scheduler.pt | hf-tune | benign | CLEAN | CLEAN |
| dima806/man_woman_face_image_detection/checkpoint-28722/scheduler.pt | hf-tune | benign | CLEAN | CLEAN |
| timm/mobilenetv4_conv_small.e2400_r224_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| HuggingFaceM4/tiny-random-LlamaForCausalLM/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| MoritzLaurer/deberta-v3-large-zeroshot-v2.0/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| timm/convnextv2_pico.fcmae_ft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| MaxJeblick/llama2-0b-unit-test/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| facebook/deit-tiny-patch16-224/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/deit_tiny_patch16_224.fb_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/distilbert-base-nli-stsb-mean-tokens/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| timm/resnet34d.ra2_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| segment-any-text/sat-12l-sm/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ales/wav2vec2-cv-be/scaler.pt | hf-tune | benign | CLEAN | CLEAN |
| ales/wav2vec2-cv-be/scheduler.pt | hf-tune | benign | CLEAN | CLEAN |
| vasista22/whisper-tamil-small/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/test_resnet.r160_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| HuggingFaceH4/tiny-random-LlamaForCausalLM/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| microsoft/BiomedVLP-CXR-BERT-specialized/biovil_image_resnet50_proj_size_128.pt | hf-heldout | benign | CLEAN | CLEAN |
| StephanAkkerman/FinTwitBERT-sentiment/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| j-hartmann/sentiment-roberta-large-english-3-classes/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Davlan/distilbert-base-multilingual-cased-ner-hrl/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| timm/resnet50d.ra2_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| defog/sqlcoder-7b-2/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| lfcc/bert-portuguese-ner/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/densenet121.ra_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| routellm/bert_gpt4_augmented/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| routellm/bert_gpt4_augmented/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| microsoft/layoutlm-base-uncased/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| christian-phu/bert-finetuned-japanese-sentiment/scheduler.pt | hf-tune | benign | CLEAN | CLEAN |
| christian-phu/bert-finetuned-japanese-sentiment/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| yiyanghkust/finbert-esg/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| BAAI/bge-small-zh/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/mobilenetv3_large_100.ra_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| facebook/dino-vits16/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| ibm-granite/granite-embedding-97m-multilingual-r2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/paraphrase-MiniLM-L12-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| faisalq/bert-base-arapoembert/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| MoritzLaurer/bge-m3-zeroshot-v2.0/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| XiaomiMiMo/MiMo-V2.6-Flash-RL/dflash/mask_embedding.pt | hf-tune | benign | CLEAN | CLEAN |
| XiaomiMiMo/MiMo-V2.6-Pro-RL/dflash/mask_embedding.pt | hf-tune | benign | CLEAN | CLEAN |
| Maykeye/TinyLLama-v0/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| Maykeye/TinyLLama-v0/backup/step-1-10300.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/efficientnet_b3.ra2_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/tf_mobilenetv3_small_minimal_100.in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| cross-encoder/stsb-distilroberta-base/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| google/bert_uncased_L-4_H-256_A-4/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| fabiochiu/t5-base-tag-generation/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| CAMeL-Lab/bert-base-arabic-camelbert-mix-sentiment/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| cross-encoder/ms-marco-MiniLM-L2-v2/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| cross-encoder/ms-marco-MiniLM-L2-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| vumichien/wav2vec2-large-xlsr-japanese-hiragana/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| qandos0/SentimentArEng/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| optimum-intel-internal-testing/tiny-random-vit/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/convnext_nano.in12k_ft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| huggingface/autoformer-tourism-monthly/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| zhiqiulin/clip-flant5-xl/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| JackFram/llama-68m/scheduler.pt | hf-tune | benign | CLEAN | CLEAN |
| JackFram/llama-68m/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| vikp/surya_det3/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| language-and-voice-lab/wav2vec2-large-xlsr-53-icelandic-ep30-967h/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/distilbert-base-nli-mean-tokens/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| NovaSearch/stella_en_400M_v5/2_Dense_256/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| NovaSearch/stella_en_400M_v5/2_Dense_768/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/densenet121.tv_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| liuhaotian/llava-v1.5-7b/mm_projector.bin | hf-tune | benign | CLEAN | CLEAN |
| CAMeL-Lab/bert-base-arabic-camelbert-da-sentiment/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| nvidia/mit-b0/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| facebook/encodec_24khz/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| ggml-org/stories15M_MOE/moe_shakespeare15M/checkpoint-400/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| ggml-org/stories15M_MOE/moe_shakespeare15M/checkpoint-500/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| AdamCodd/tinybert-emotion-balanced/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| AdamCodd/tinybert-emotion-balanced/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| Elron/bleurt-tiny-512/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| Organika/sdxl-detector/checkpoint-801/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| Organika/sdxl-detector/checkpoint-801/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| hustvl/yolos-tiny/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| ACE-Step/Ace-Step1.5/acestep-v15-turbo/silence_latent.pt | hf-tune | benign | CLEAN | CLEAN |
| prithivMLmods/Gender-Classifier-Mini/checkpoint-157/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| prithivMLmods/Gender-Classifier-Mini/checkpoint-314/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| airesearch/wav2vec2-large-xlsr-53-th/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| classla/wav2vec2-xls-r-parlaspeech-hr/training_args.bin | hf-tune | benign | CLEAN | CLEAN |
| kresnik/wav2vec2-large-xlsr-korean/training_args.bin | hf-heldout | benign | CLEAN | CLEAN |
| circulus/canvers-en2ko-v1/training_args.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| circulus/canvers-ko2en-v1/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| Bingsu/adetailer/face_yolov8n.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Bingsu/adetailer/hand_yolov8n.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Bingsu/yolo-world-mirror/yolov8s-worldv2.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Bingsu/yolo-world-mirror/yolov8s-world.pt | hf-heldout | benign | CLEAN | MALICIOUS |
| keremberke/yolov8m-table-extraction/best.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Anzhc/Anzhcs_YOLOs/Anzhcs Anime Score CLS v1.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Anzhc/Anzhcs_YOLOs/Anzhc Face seg 640 v4 y11n.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| morsetechlab/yolov11-license-plate-detection/license-plate-finetune-v1n.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| morsetechlab/yolov11-license-plate-detection/license-plate-finetune-v1s.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ultralytics/YOLO11/yolo11n.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ultralytics/YOLO11/yolo11n-seg.pt | hf-tune | benign | CLEAN | MALICIOUS |
| Ultralytics/YOLO26/yolo26n.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ultralytics/YOLO26/yolo26n-cls.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ultralytics/YOLOv8/yolov8n.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ultralytics/YOLOv8/yolov8s.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Koushim/yolov8-license-plate-detection/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Piero2411/YOLOV8s-Barcode-Detection/YOLOV8s_Barcode_Detection.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| esapzoi/litter-detection-yolov8/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| MykolaL/DelineateAnything/DelineateAnything-S.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| RoyRud1902/yolo11n-text/best.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8n.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Anzhc/Race-Classification-FairFace-YOLOv8/Race-CLS-FairFace_yolov8s.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| jameslahm/yoloe/yoloe-11s-seg-coco-pe.pt | hf-heldout | benign | CLEAN | MALICIOUS |
| jameslahm/yoloe/yoloe-11s-seg-coco.pt | hf-heldout | benign | CLEAN | MALICIOUS |
| MidnightRunner/Ultralytics/bbox/face_yolov8n.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| MidnightRunner/Ultralytics/bbox/face_yolov8n_v2.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| arnabdhar/YOLOv8-nano-aadhar-card/model.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ShadowB/Manga109-panel-balloon-text-yolov26-segmentation/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ShadowB/Manga109-panel-balloon-text-yolov26-segmentation/last.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| foduucom/stockmarket-pattern-detection-yolov8/model.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| luxdelux7/ForbiddenVision_Models/ForbiddenVision_face_detect_v1.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| melihuzunoglu/human-fall-detection/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| finloop/yolov8s-seg-solar-panels/best.pt | hf-heldout | benign | CLEAN | MALICIOUS |
| finloop/yolov8s-seg-solar-panels/train/weights/best.pt | hf-heldout | benign | CLEAN | MALICIOUS |
| rabahdev/fire-smoke-yolov8n/best.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| rabahdev/fire-smoke-yolov8n/last.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ultralytics/YOLOv5/yolov5n.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ultralytics/YOLOv5/yolov5n6.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Moszer777/pcb-aoi-yolo-rmutt/t6_fpic_n/weights/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Moszer777/pcb-aoi-yolo-rmutt/t6_fpic_n/weights/last.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Subh775/Threat-Detection-YOLOv8n/weights/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Subh775/Threat-Detection-YOLOv8n/weights/last.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| huyvux3005/manga109-segmentation-bubble/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| huyvux3005/manga109-segmentation-bubble/last.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Runware/adetailer/face_yolov8n.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Runware/adetailer/hand_yolov8n.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| leoxs22/manga-panel-detector-yolo26n/manga_panel_detector_fp32.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| NAKSTStudio/yolov8m-chess-piece-detection/best.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| honi05/chess-piece-yolo/yolo_pico/best.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| honi05/chess-piece-yolo/yolov8n/best.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| keremberke/yolov8m-building-segmentation/best.pt | hf-tune | benign | CLEAN | MALICIOUS |
| keremberke/yolov8m-hard-hat-detection/best.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| Jeremy341/MIRA-AI/mira_exp013.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Jeremy341/MIRA-AI/mira_exp014.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| keremberke/yolov8n-hard-hat-detection/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Hansung-Cho/yolov8-ppe-detection/best.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolov9t_640.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| mehmetkeremturkcan/UrbanOmniDetect/checkpoints/urbanomnidetect_yolo11n_640.pt | hf-tune | benign | CLEAN | SUSPICIOUS |
| keremberke/yolov8m-protective-equipment-detection/best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| anonimkaq4/manga-page-element-segmentation/snapshots/yolo11m_1024_b2/manga-yolo11m-seg-validation-best.pt | hf-heldout | benign | CLEAN | SUSPICIOUS |
| timm/resnest14d.gluon_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/rexnet_150.nav_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/efficientnet_b2.ra_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/tf_efficientnet_b0.ns_jft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/mobilenetv2_100.ra_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/resnet50_gn.a1h_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/deit_small_patch16_224.fb_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/repvit_m1.dist_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/densenetblur121d.ra_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/fastvit_t8.apple_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/levit_256.fb_dist_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/convnext_pico.d1_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/mobilevit_s.cvnets_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/vit_small_patch16_224.dino/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/hrnet_w18.ms_aug_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/vit_tiny_patch16_224.augreg_in21k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/mobilenetv4_conv_small_050.e3000_r224_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/convnext_atto.d2_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/resnet50.tv_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/vit_small_patch16_384.augreg_in21k_ft_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/tf_efficientnetv2_b0.in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/efficientnet_b4.ra2_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/regnety_002.pycls_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/tf_efficientnet_b3.ns_jft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/convnextv2_nano.fcmae_ft_in22k_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/tf_efficientnet_b4.ns_jft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/inception_v3.tv_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/resnet34.tv_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/resnet18d.ra2_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/resnext50_32x4d.a1h_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/mobilenetv4_conv_medium.e500_r256_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/efficientnetv2_rw_t.ra2_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/resnet18.tv_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/ghostnet_100.in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/convnextv2_nano.fcmae_ft_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/mobilenetv4_conv_medium.e250_r384_in12k_ft_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/regnety_016.tv2_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/vit_small_patch16_224.augreg_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/mobilenetv3_small_075.lamb_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/tf_efficientnet_lite1.in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/tf_efficientnet_lite0.in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/edgenext_xx_small.in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/maxvit_nano_rw_256.sw_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/convnextv2_atto.fcmae_ft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/eva02_tiny_patch14_224.mim_in22k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/mobilenetv3_small_050.lamb_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/regnetx_002.pycls_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/efficientnet_b1.ra4_e3600_r240_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/resnet10t.c3_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/pvt_v2_b2.in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/tiny_vit_5m_224.in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/mobilenetv4_conv_small.e1200_r224_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/convnext_femto.d1_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/hgnetv2_b4.ssld_stage1_in22k_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/regnety_008.pycls_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/mobilevitv2_050.cvnets_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/densenet169.tv_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/mobilevit_xxs.cvnets_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| timm/tf_efficientnet_b2.ns_jft_in1k/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| timm/inception_v3.tf_adv_in1k/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| BAAI/bge-m3/sparse_linear.pt | hf-heldout | benign | CLEAN | CLEAN |
| BAAI/bge-m3/colbert_linear.pt | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/distiluse-base-multilingual-cased-v1/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| jinaai/jina-embeddings-v2-small-en/pytorch_model.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| thenlper/gte-small/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| thenlper/gte-small/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| intfloat/e5-small-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/distiluse-base-multilingual-cased-v2/2_Dense/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/LaBSE/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| TencentBAC/Conan-embedding-v1/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/sentence-t5-base/2_Dense/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| avsolatorio/GIST-all-MiniLM-L6-v2/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/clip-ViT-B-32-multilingual-v1/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/msmarco-distilbert-base-v4/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/gtr-t5-base/2_Dense/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/multi-qa-distilbert-dot-v1/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/msmarco-distilbert-cos-v5/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ibm-granite/granite-embedding-30m-english/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-distilroberta-base-v1/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| opensearch-project/opensearch-neural-sparse-encoding-doc-v2-mini/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| IEITYuan/Yuan-embedding-2.0-zh/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/gtr-t5-large/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| hotchpotch/japanese-reranker-cross-encoder-small-v1/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| billatsectorflow/stella_en_400M_v5/2_Dense_256/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| billatsectorflow/stella_en_400M_v5/2_Dense_768/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| vidore/colpali-v1.2/checkpoint-18000/scheduler.pt | hf-heldout | benign | CLEAN | CLEAN |
| hotchpotch/japanese-reranker-xsmall-v2/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/multi-qa-distilbert-cos-v1/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| optimum-intel-internal-testing/stsb-bert-tiny-safetensors/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| mixedbread-ai/mxbai-embed-xsmall-v1/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| mixedbread-ai/mxbai-embed-xsmall-v1/openvino/openvino_model.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| cross-encoder/nli-distilroberta-base/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| sentence-transformers-testing/stsb-bert-tiny-openvino/openvino/openvino_model.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/msmarco-distilbert-dot-v5/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| optimum-intel-internal-testing/all-MiniLM-L6-v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| optimum-intel-internal-testing/all-MiniLM-L6-v2/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| cross-encoder/ms-marco-TinyBERT-L6/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| jinaai/jina-reranker-v1-turbo-en/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-TinyBERT-L6-v2/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| cross-encoder/ms-marco-TinyBERT-L2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| cross-encoder/ms-marco-TinyBERT-L2/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| hotchpotch/japanese-reranker-small-v2/training_args.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/distiluse-base-multilingual-cased/2_Dense/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| hkunlp/instructor-base/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/sentence-t5-large/2_Dense/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| sentence-transformers/paraphrase-distilroberta-base-v2/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| cross-encoder/ettin-reranker-17m-v1/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| cross-encoder/ettin-reranker-17m-v1/openvino/openvino_model.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| TaylorAI/bge-micro/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| dguzh/geo-all-MiniLM-L6-v2/pytorch_model.bin | hf-tune | benign | CLEAN | CLEAN |
| cross-encoder/stsb-TinyBERT-L4/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| cross-encoder/stsb-TinyBERT-L4/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| NovaSearch/stella_en_1.5B_v5/2_Dense_256/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| NovaSearch/stella_en_1.5B_v5/2_Dense_768/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| cross-encoder/ettin-reranker-68m-v1/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| Vsevolod/company-names-similarity-sentence-transformer/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| TaylorAI/gte-tiny/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| cross-encoder/ettin-reranker-32m-v1/openvino/openvino_model_qint8_quantized.bin | hf-tune | benign | CLEAN | SUSPICIOUS |
| sentence-transformers/msmarco-MiniLM-L6-cos-v5/pytorch_model.bin | hf-heldout | benign | CLEAN | CLEAN |
| sentence-transformers/msmarco-MiniLM-L6-cos-v5/openvino/openvino_model_qint8_quantized.bin | hf-heldout | benign | CLEAN | SUSPICIOUS |
| OKTAYBBS/DataScientst-models/time_series/walmart_recent.pkl | hf-tune | benign | CLEAN | CLEAN |
| OKTAYBBS/DataScientst-models/time_series/stock_recent.pkl | hf-tune | benign | CLEAN | CLEAN |
| julien-c/wine-quality/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| julien-c/skops-digits/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| vvmnnnkv/wine-quality/model.pkl | hf-heldout | benign | CLEAN | CLEAN |
| vvmnnnkv/wine-quality/model_w_features.pkl | hf-heldout | benign | CLEAN | CLEAN |
| scikit-learn-examples/example/sklearn_model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| prabinpanta0/Patient-Readmission-Prediction/model_Logistic_Regression.pkl | hf-tune | benign | CLEAN | CLEAN |
| prabinpanta0/Patient-Readmission-Prediction/model_crossval_logistic_regression.pkl | hf-tune | benign | CLEAN | CLEAN |
| BenjaminB/plain-sklearn/sklearn_model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| AWeirdDev/human-disease-prediction/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| rawqubit/ClassicML-Prompt-Injection-Detector/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| kiselyovd/cardio-risk-rf/sklearn_model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| kiselyovd/cardio-risk-rf/cardio_risk_lgbm.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| AgentsSci/EMNLP_Cost-Aware-Protocol-Routing/router_metadata_only/model.joblib | hf-tune | benign | CLEAN | CLEAN |
| AgentsSci/EMNLP_Cost-Aware-Protocol-Routing/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| nateraw/iris-svc/sklearn_model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| sborhade/expense_forecaster/model/expense_forecaster_model.pkl | hf-tune | benign | CLEAN | CLEAN |
| DineshKumar1329/Sentiment_Analysis/vectorizer_model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| DineshKumar1329/Sentiment_Analysis/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| danupurnomo/dummy-titanic/final_pipeline.pkl | hf-heldout | benign | CLEAN | CLEAN |
| danupurnomo/dummy-titanic/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| nateraw/custom-sklearn-pipe-objects/sklearn_transformer.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| nateraw/custom-sklearn-pipe-objects/sklearn_model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| osanseviero/wine-quality/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| TasnimMer/callcenter-tfidf/tfidf_svm_model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| risingodegua/wine-quality-model/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| nwhite-systems/nwhite-ai-operations-intent-classifier/model.joblib | hf-tune | benign | CLEAN | CLEAN |
| nwhite-systems/nwhite-ai-operations-intent-classifier/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| imodels/figs-compas-recidivism/sklearn_model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| Yu-Lieng/predict1/loan_decision_tree.joblib | hf-heldout | benign | CLEAN | CLEAN |
| waghelad/dgvj-work/risk_classifier.joblib | hf-heldout | benign | CLEAN | CLEAN |
| kevinkyi/Homework2_Classical_ML/autogluon_predictor.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| wlaminack/testingmodel/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| imshriya/mlforge-cicd-test-model/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| imshriya/mlforge-cicd-test-model/sgd_classifier.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| GodfreyOwino/AgriAdvisor/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| delineiro/soflexpoc/vectorizer.pkl | hf-heldout | benign | CLEAN | CLEAN |
| delineiro/soflexpoc/model.pkl | hf-heldout | benign | CLEAN | CLEAN |
| carineRam/wine_model/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| ai-mitra/prompt-injection-detector/classifier.joblib | hf-tune | benign | CLEAN | CLEAN |
| ai-mitra/prompt-injection-detector/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| emresvd/u202/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| thuggingface/multi-nb-tfidf-model/multi-nb-tfidf-model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Dilipk/flask-classification-model/classification_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| mmx86/hf_heart/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| mohammed781234712/amazon-books-sentiment/label_encoder.pkl | hf-tune | benign | CLEAN | CLEAN |
| mohammed781234712/amazon-books-sentiment/model.pkl | hf-tune | benign | CLEAN | CLEAN |
| AbhishekS2005/mlforge-test-model/linear_regression.joblib | hf-heldout | benign | CLEAN | CLEAN |
| AbhishekS2005/mlforge-test-model/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| pfizer-project-team/binary-segA-vs-segBC/sklearn_model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| imshriya/mlforge-test-model/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| 2gether330/diabetes-rf-regressor/sklearn_model.joblib | hf-tune | benign | CLEAN | CLEAN |
| osanseviero/tips/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| osanseviero/tipsuhtxfu-sex-classification/clf.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| maderix/titanic_traink4m62li8-survived-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| merve/breast_cancernb8gjv4n-diagnosis-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| srg/outhimar_64-Close-regression/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| luizapzbn/titanicht_mp88q-Survived-classification/clf.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| cacauvicosa/heart1ohr2x9e-target-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Fulccrum/trainii_ac94u-label-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| sahilrajpal121/train5a1e8w7-label-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| ieborhan/irisg444_4c0-Species-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| osanseviero/hf_hub_example-f7d1d7e5-f207-4eef-99bb-57408d604e2b/skops-texalxld.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| osanseviero/hf_hub_example-821defb0-1482-4d27-884d-4359bfad704f/skops-k4xq5xio.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| osanseviero/hf_hub_example-023f3150-3eae-45a4-bd3c-7a95639e10e0/skops-9053e41j.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| scikit-learn/skops-blog-example/example.pkl | hf-heldout | benign | CLEAN | CLEAN |
| scikit-learn/tabular-playground/model.pkl | hf-heldout | benign | CLEAN | CLEAN |
| demo-org/tabular-playground/model.pkl | hf-heldout | benign | CLEAN | CLEAN |
| merve/20newsgroups/model.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| vendorabc/modelhubexample/skops-3voi5107.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| vendorabc/modeltest/skops-v5dfi0sh.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| vendorabc/tabular-playground/model.pkl | hf-tune | benign | CLEAN | CLEAN |
| freddyaboulton/tabular-playground/model.pkl | hf-tune | benign | CLEAN | CLEAN |
| merve/test-code-generation/example.pkl | hf-heldout | benign | CLEAN | CLEAN |
| rajistics/MAPIE-TS-Electricity/skops-0t38e5rm.pkl | hf-heldout | benign | CLEAN | CLEAN |
| rajistics/MAPIE-TS-Electricity/skops-nxorv9li.pkl | hf-heldout | benign | CLEAN | CLEAN |
| kushkul/rf_model_skops/rf_model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| scikit-learn/Fish-Weight/example.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| rajistics/my-awesome-churn-model/example.pkl | hf-heldout | benign | CLEAN | CLEAN |
| rajistics/churn-model/churn.pkl | hf-tune | benign | CLEAN | CLEAN |
| tehnlulz/pruned_datavq__ydnj-is_phishing-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ramos-Ramos/emb-gam-dino/model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| ayyuce/my_solar_model/solar.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| robertbogdon/model_tuning_mindallee8kmcfjz-labels-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| robertbogdon/model_tuning_mindalleeu83oz7r-labels-classification/clf.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| robertbogdon/model_tuning_mindalle9_jsy6zj-labels-classification/clf.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ramos-Ramos/emb-gam-resnet/model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ramos-Ramos/emb-gam-vit/model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| svnfs/rfc/rfc.pkl | hf-tune | benign | CLEAN | CLEAN |
| Testys/diabetespmxrsn1x-diabetes-classification/clf.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| svnfs/rfc-alias/rfc.pkl | hf-tune | benign | CLEAN | CLEAN |
| rajistics/churn-model1/churn.pkl | hf-tune | benign | CLEAN | CLEAN |
| merve/model-broken-config/model.pkl | hf-heldout | benign | CLEAN | CLEAN |
| Ramos-Ramos/emb-gam-dino-resnet/model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| aliosmankaya/structured_arr_model_1_dim/structured_arr_model_1_dim.joblib | hf-heldout | benign | CLEAN | CLEAN |
| IMFAA/Magnet_Tc_predictor/Magnet_Tc_predictor.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| aliosmankaya/reg_arr_model_2_dim/reg_arr_model_2_dim.joblib | hf-tune | benign | CLEAN | CLEAN |
| aliosmankaya/reg_arr_model_1_dim/reg_arr_model_1_dim.joblib | hf-heldout | benign | CLEAN | CLEAN |
| scikit-learn/cancer-prediction-trees/model.pkl | hf-tune | benign | CLEAN | CLEAN |
| Annabel/my-awesome-model/example.pkl | hf-tune | benign | CLEAN | CLEAN |
| dvgodoy/sklearn-mpg/linreg.pkl | hf-tune | benign | CLEAN | CLEAN |
| scikit-learn/blog-example/model.pkl | hf-tune | benign | CLEAN | CLEAN |
| Ramos-Ramos/emb-gam-vicreg-resnet/model.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| moro23/ml-generation-failure-prediction/model.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Alassea/middle-dutch-NER_passAgg/middle_dutch_passAgg.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Chibundum/skops_sklearn/logreg_1_0_model.pkl | hf-tune | benign | CLEAN | CLEAN |
| jirkoru/TemporalRegression/model.pkl | hf-heldout | benign | CLEAN | CLEAN |
| y1450/hf_hub_example-ff7aeda4-022b-47d2-bf00-0c241bc195f7/skops-bo_9fb88.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| merve/my-awesome-model-blog/example.pkl | hf-tune | benign | CLEAN | CLEAN |
| Ozziey/poet-type-model/Pickle_HME_Model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ozziey/poet-age-model/Pickle_HME_Model_AGE.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ozziey/poet-age-model/Pickle_HME_Model.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| mahrukhw/DecisissionTreeClassifier/example.pkl | hf-tune | benign | CLEAN | CLEAN |
| Alassea/middle-dutch-NER_passAgg_2/model.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Alassea/middle-dutch-NER_text-classification/middle_dutch_text-classification.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| merve/xgboost-example/model.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| scikit-learn/xgboost-example/model.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| mklomo/rf-churn-model/rf_model.pkl | hf-heldout | benign | CLEAN | CLEAN |
| jirkoru/TemporalRegressionV2/model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| achiachi/accentcombinedlenous8ktq9-accent-classification/clf.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ahuber/knn-example-stock-067ecda5-11f2-4788-818f-707c3dd673e7/model-stock.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ahuber/knn-example-intelex-067ecda5-11f2-4788-818f-707c3dd673e7/model-optimized.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Kluuking/Airlinesuiztcxpg-Delay-classification/clf.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| BenjaminB/knn-example-intelex-c035ccff-d23b-4e02-97bd-14cf3cb0bde5/model-optimized.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| tuva/turu/model/language_classifier.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| agucci/my-model/example.pkl | hf-tune | benign | CLEAN | CLEAN |
| jeveuxaider/jva-organization-report/skops-4dusypwz.pkl | hf-heldout | benign | CLEAN | CLEAN |
| sklearn-docs/anomaly-detection/isolation_forest.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| hbui/Drought_Vulnerability_Assessment/final_model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| robingenz/huggingface-iris-inference-test/model.pkl | hf-tune | benign | CLEAN | CLEAN |
| harshiv/prediction/random_forest_model.pkl | hf-tune | benign | CLEAN | CLEAN |
| harshiv/placement/rf_hacathon_fullstk.pkl | hf-tune | benign | CLEAN | CLEAN |
| harshiv/placement/rf_hacathon_mkt.pkl | hf-tune | benign | CLEAN | CLEAN |
| harshiv/placementrep/rf_hacathon_fullstk.pkl | hf-heldout | benign | CLEAN | CLEAN |
| harshiv/placementrep/rf_hacathon_mkt.pkl | hf-heldout | benign | CLEAN | CLEAN |
| haizad/ames-housing-lasso-predictor/model.pkl | hf-heldout | benign | CLEAN | MALICIOUS |
| haizad/ames-housing-gbdt-predictor/model.pkl | hf-tune | benign | CLEAN | MALICIOUS |
| haizad/ames-housing-random-forest-predictor/model.pkl | hf-tune | benign | CLEAN | MALICIOUS |
| d2i-pti-iu/iris_test/iris_svm.joblib | hf-tune | benign | CLEAN | CLEAN |
| Amusa/private1/text_classifier.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ahmadswaid/sklearn-mpg/linreg.pkl | hf-heldout | benign | CLEAN | CLEAN |
| aduzlo/zello-valid-trial-v3.2/valid_trial_v3_2.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| Jayabalambika/MCI/sgd_model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| jrosenzw/autotrain-diabetes-detection-2-74371139581/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| runMark/tttttxxx/sklearn_model.joblib | hf-heldout | benign | CLEAN | CLEAN |
| dgergherherherhererher/dfsgs/model.pkl | hf-tune | benign | CLEAN | CLEAN |
| sulpha/student_academic_success/model.pkl | hf-heldout | benign | CLEAN | CLEAN |
| sulpha/student_academic_success_1/model1.pkl | hf-tune | benign | CLEAN | CLEAN |
| sulpha/BDM_Preject_model/model.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| shalev396/california-housing/scaler.joblib | hf-tune | benign | CLEAN | CLEAN |
| jeffliulab/card-calibration-v1/xgboost_v1.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| jeffliulab/card-calibration-v1/random_forest_v1.pkl | hf-heldout | benign | CLEAN | CLEAN |
| FinancialReports/jina-v3-financial-classifier/label_decoder_final_v1.pkl | hf-heldout | benign | CLEAN | CLEAN |
| AAUBS/hotel-cancellation-model/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| PROJECTS254/BAYESIAN_OPTIMIZED_GRU_XGBOOST_FOR_FLOOD_PREDICTION/scaler.pkl | hf-heldout | benign | CLEAN | CLEAN |
| PROJECTS254/BAYESIAN_OPTIMIZED_GRU_XGBOOST_FOR_FLOOD_PREDICTION/scaler_X.pkl | hf-heldout | benign | CLEAN | CLEAN |
| lvizcaya/forex-eurusd-direction/scaler.joblib | hf-tune | benign | CLEAN | CLEAN |
| lvizcaya/forex-eurusd-direction/xgb_model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| FreekyMeeky/autotrain-tm-pricepredictor-98386147082/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ketong3906/autotrain-iris_truncated-64451135750/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| muhalwan/california_housing_price_predictor/scaler.joblib | hf-tune | benign | CLEAN | CLEAN |
| muhalwan/california_housing_price_predictor/xgb_model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| bibekbehera/autotrain-numeric_prediction-40376105019/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| XaviArmengol/autotrain-titanic-54879128171/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| jrosenzw/autotrain-diabetes-detection-74053139456/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| EnerTEF/Performance-Evaluation-of-Energy-Forecasts-Service/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| ahmemahmoud/ics-ot-smartgrid-ndr/label_encoder.pkl | hf-tune | benign | CLEAN | CLEAN |
| ahmemahmoud/ics-ot-smartgrid-ndr/xgb_features.pkl | hf-tune | benign | CLEAN | CLEAN |
| vyver7952/autotrain-foreign-exchange-idr-usd-50442120505/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| wangdy/autotrain-goddy3-40913105966/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| desertdev/autotrain-imdb-sentiment-analysis-44994113085/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| harithapliyal/autotrain-tatanic-survival-f1-83/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| th1enq/xgboost_checkpoint/xgboost_url.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| th1enq/xgboost_checkpoint/xgboost_html.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| TWLab/femtosecond-laser-hydrogel-etching-model/scaler_y.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| TWLab/femtosecond-laser-hydrogel-etching-model/scaler_X.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| Kluuking/autotrain-flight-delay-3621096840/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| M-Ahmad-Abid/Diabetes_model/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| GodfreyOwino/NPK_prediction_model2/label_encoder.pkl | hf-heldout | benign | CLEAN | CLEAN |
| reesu/wine_quality/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| grahamfleming/autotrain-petfinder-demo-87059143318/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| BrianDsouzaAI/autotrain-tab-multi-92337144714/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| willadamskeane/autotrain-over-under-96986146760/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| ArkMaster123/grantpilot-classifier-v2/label_encoders.pkl | hf-tune | benign | CLEAN | CLEAN |
| ArkMaster123/grantpilot-classifier-v2/scaler.pkl | hf-tune | benign | CLEAN | CLEAN |
| kochetkovIT/autotrain-ironhack-49741119788/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| reachosen/autotrain-palv1-76806140361/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| Wei-Meng/autotrain-diabetes-86722143226/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| nicoler229/p2/target_encoders.joblib | hf-heldout | benign | CLEAN | CLEAN |
| nicoler229/p2/model.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| NoahMeissner/CuisineClassifier/region_classifier/label_encoder.joblib | hf-tune | benign | CLEAN | CLEAN |
| NoahMeissner/CuisineClassifier/cuisine_classifier/label_encoder.joblib | hf-tune | benign | CLEAN | CLEAN |
| atekrugis/intent-router-v11-modernbert/model_head.pkl | hf-heldout | benign | CLEAN | CLEAN |
| atekrugis/intent-router-v11-modernbert/v11_forest_head.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| mitalidaduria/payment-fraud-xgboost/feature_pipeline.pkl | hf-heldout | benign | CLEAN | CLEAN |
| mitalidaduria/payment-fraud-xgboost/model.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| vabadeh213/autotrain-titanic-744222727/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| adgrowr/autotrain-negative-keywords-classifier-61622134846/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| Fatihrizkia/autotrain-xauusdh4timestamp-100145147571/model.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| chencliu/tqc-PandaSlide-v3/vec_normalize.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Mriganka1999/PandaSlideDense-v3usingSAC-PandaSlideDense-v3/vec_normalize.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Mriganka1999/PandaSlideDense-v3usingA2C-PandaSlideDense-v3/vec_normalize.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Hevagog/ppo-PandaSlide-v3/vec_normalize.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Hevagog/sac-PandaSlide-v3/vec_normalize.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Edgar404/a2c-PandaStackDense-v3/vec_normalize.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Edgar404/td3-PandaStackDense-v3/vec_normalize.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Mriganka1999/PandaSlideDense-v3usingTD3-PandaSlideDense-v3/vec_normalize.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| laojohn/a2c-PandaStackDense-v3/vec_normalize.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Hevagog/tqc-PandaSlide-v3/vec_normalize.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| Mriganka1999/PandaSlideDense-v3usingPPO-PandaSlideDense-v3/vec_normalize.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Mriganka1999/PandaSlideDense-v3usingDDPG-PandaSlideDense-v3/vec_normalize.pkl | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Destiny0621/a2c-PandaStack-v3/vec_normalize.pkl | hf-tune | benign | CLEAN | SUSPICIOUS |
| etwithin/aws_sdk_pandas-ace-poc/malicious.pkl | hf-heldout | benign | CLEAN | MALICIOUS |
| security-finder/poc_picklescan_bypass_pandas_read_pickle_nested_ACE.joblib/017_poc_picklescan_bypass_pandas_read_pickle_nested_ACE.joblib | hf-heldout | benign | CLEAN | SUSPICIOUS |
| security-finder-1/017-picklescan-bypass-pandas-read-pickle-ace/017_poc_picklescan_bypass_pandas_read_pickle_nested_ACE.joblib | hf-tune | benign | CLEAN | SUSPICIOUS |
| Hephaestus-vn/huntr-ml-new-findings/FINDING_KERAS_DECOMPBOMB.keras | hf-tune | benign | CLEAN | CLEAN |
| Steenslid/ecg-ptbxl-classification/ecg_cnn_final.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Steenslid/ecg-ptbxl-classification/ecg_model.keras | hf-tune | benign | CLEAN | CLEAN |
| ScanMe/test-models/eval_lambda.keras | hf-tune | benign | CLEAN | MALICIOUS |
| Jdbbd/Universal-Model-V29-Full/xd_universal.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| gone321/test_1/model_epoch_1.keras | hf-tune | benign | CLEAN | CLEAN |
| tornet-ml/tornado_detector_baseline_v1/tornado_detector_baseline.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| StockCast/seperate/models/00DS30/lstm_00DS30_seq60_nahead1.keras | hf-tune | benign | CLEAN | CLEAN |
| StockCast/seperate/models/00DSES/lstm_00DSES_seq60_nahead1.keras | hf-tune | benign | CLEAN | CLEAN |
| StockCast/gru/models/SINOBANGLA/gru_SINOBANGLA_seq60_nahead1.keras | hf-heldout | benign | CLEAN | CLEAN |
| StockCast/gru/models/GQBALLPEN/gru_GQBALLPEN_seq60_nahead1.keras | hf-heldout | benign | CLEAN | CLEAN |
| Genereux-akotenou/genomics-tf-prediction/MetaClassifier/META_k2.keras | hf-tune | benign | CLEAN | CLEAN |
| Genereux-akotenou/genomics-tf-prediction/MetaClassifier/META_k3.keras | hf-tune | benign | CLEAN | CLEAN |
| gaurangdave/mnist_cnn/experiment_3_03_0.96.keras | hf-tune | benign | CLEAN | CLEAN |
| gaurangdave/mnist_cnn/experiment_3_04_0.96.keras | hf-tune | benign | CLEAN | CLEAN |
| DaneshSelwal/Classification-DIAS-65Bands/spatialgcn/models/SpatialGCN_best.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| DaneshSelwal/Classification-DIAS-65Bands/spatialgcn/models/SpatialGCN_final.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Neural-Network-Project/ECG-Disease-Classifier/checkpoints/checkpoint_epoch_10.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Neural-Network-Project/ECG-Disease-Classifier/checkpoints/checkpoint_epoch_11.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| hzhongresearch/yamnetp_ahead_ds/yamnetp_ahead_ds_unfreeze_last.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| hzhongresearch/yamnetp_ahead_ds/yamnetp_ahead_ds_random.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Jeremy341/MIRA-AI/models/classifier/mira_classifier_transfer.keras | hf-heldout | benign | CLEAN | CLEAN |
| Jeremy341/MIRA-AI/models/classifier/mira_classifier_tuned.keras | hf-heldout | benign | CLEAN | CLEAN |
| Blagoja/ecg-ptbxl-classification/ecg_cnn_final.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Blagoja/ecg-ptbxl-classification/ecg_model.keras | hf-tune | benign | CLEAN | CLEAN |
| manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed17/stage4_best.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| manpreet28111995/eca-ldnet/reviewer_test_package/models/ablations/no_attention/seed43/stage4_best.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| hellothisisaswin/ecg-ptbxl-classification/ecg_cnn_final.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| hellothisisaswin/ecg-ptbxl-classification/ecg_model.keras | hf-heldout | benign | CLEAN | CLEAN |
| Amarsai01/vehicle-damage-detection-models/mobilenetv2.keras | hf-tune | benign | CLEAN | CLEAN |
| Datadragon110/freshwater-salmon-analysis-step3/models/p3_mnv3s_a1_224_g0.keras | hf-heldout | benign | CLEAN | CLEAN |
| Datadragon110/freshwater-salmon-analysis-step3/models/mnv3small_g0.keras | hf-heldout | benign | CLEAN | CLEAN |
| alltrue-ai/christina-model-1000-small-files/large_test_model_1000_files/checkpoints/checkpoint-00001.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| alltrue-ai/christina-model-1000-small-files/large_test_model_1000_files/checkpoints/checkpoint-00002.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Datadragon110/freshwater-quantization-models/models/salmon_mnv3small_r0_f0.keras | hf-tune | benign | CLEAN | CLEAN |
| Datadragon110/freshwater-quantization-models/models/salmon_mnv3small_r0_f1.keras | hf-tune | benign | CLEAN | CLEAN |
| wiki-virus/hyperspectral-image-classification-using-modern-architectures-and-frameworks/best_relationnet_cnn_attention_mamba_module.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| wiki-virus/hyperspectral-image-classification-using-modern-architectures-and-frameworks/best_relationnet_cnn_attention_module.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| CaxtonEmeraldS/CholesterolConcentrationPredictor/selu/seed_2/model_1.keras | hf-heldout | benign | CLEAN | CLEAN |
| CaxtonEmeraldS/CholesterolConcentrationPredictor/selu/seed_3/model_1.keras | hf-heldout | benign | CLEAN | CLEAN |
| ZOROD/Boiler_Tube_Early_leak_detection/autoencoder_best.keras | hf-heldout | benign | CLEAN | CLEAN |
| ZOROD/Boiler_Tube_Early_leak_detection/lstm_best.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| mertkayacs/xdfdet/baseline.keras | hf-tune | benign | CLEAN | CLEAN |
| mertkayacs/xdfdet/aug-standard.keras | hf-tune | benign | CLEAN | CLEAN |
| keeprich/forex-transformer-trading-pre-prod/runs/EUR_USD/20251224_073608/model.keras | hf-heldout | benign | CLEAN | CLEAN |
| keeprich/forex-transformer-trading-pre-prod/runs/GBP_USD/20251224_074608/model.keras | hf-heldout | benign | CLEAN | CLEAN |
| rn-12-19/plant-disease-model-v5/phase1_epoch_001.keras | hf-heldout | benign | CLEAN | CLEAN |
| rn-12-19/plant-disease-model-v5/phase1_epoch_002.keras | hf-heldout | benign | CLEAN | CLEAN |
| vamsi03UNH/NLP-mid-term/english_model001.keras | hf-tune | benign | CLEAN | CLEAN |
| vamsi03UNH/NLP-mid-term/english_model002.keras | hf-tune | benign | CLEAN | CLEAN |
| sujals1238/DAISEE/1D_InceptionNet_individual.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| sujals1238/DAISEE/1D_InceptionNet_bag1.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| tanganke/clip-vit-base-patch32_emnist_letters/emnist_model.keras | hf-tune | benign | CLEAN | CLEAN |
| JabaleNurAdnan/CS_Checkpoints_Dataset/UNSW_NB15__Transformer__FedProx__iid/model.keras | hf-tune | benign | CLEAN | CLEAN |
| JabaleNurAdnan/CS_Checkpoints_Dataset/CICIDS2017__Transformer__FedAvg__iid/model.keras | hf-tune | benign | CLEAN | CLEAN |
| Ambiq/compressionkit-ecg-8x-v1.0/encoder.keras | hf-heldout | benign | CLEAN | CLEAN |
| Ambiq/compressionkit-ecg-8x-v1.0/decoder.keras | hf-heldout | benign | CLEAN | CLEAN |
| abdellasizay/CNN-fourrages/PIPELINE_FAF_PRESENCE_INTENSITE_VERT/Pipeline_FAF_presence_vert_2026-08-31_00h31m06s/modele_presence_absence_FAF.keras | hf-tune | benign | CLEAN | CLEAN |
| abdellasizay/CNN-fourrages/PRESENCE_ABSENCE_FAF/FAF_presence_absence_2026-08-30_17h49m30s/best_model.keras | hf-tune | benign | CLEAN | CLEAN |
| Datadragon110/freshwater-salmon-analysis-step5/models/p3_mnv2_a0.5_160_g0.keras | hf-tune | benign | CLEAN | CLEAN |
| Datadragon110/freshwater-salmon-analysis-step5/models/p3_mnv2_a0.5_160_g1.keras | hf-tune | benign | CLEAN | CLEAN |
| manudaza/retinal-triage-efficientnetb0/efficientnetb0_finetuned_patched.keras | hf-heldout | benign | CLEAN | CLEAN |
| gnouhmal/price-lstm-models/ACB/model.keras | hf-heldout | benign | CLEAN | CLEAN |
| gnouhmal/price-lstm-models/VC3/model.keras | hf-heldout | benign | CLEAN | CLEAN |
| niobures/YAMNet/yamnetp_ahead_ds/yamnetp_ahead_ds_unfreeze_last.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| niobures/YAMNet/yamnetp_ahead_ds/yamnetp_ahead_ds_random.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| RAVITEJA311/sentiment-analysis-models/gru/model_final.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| RAVITEJA311/sentiment-analysis-models/gru/best.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| lugan/SynTTS-Commands-Media-Benchmarks/SynTTS-Commands-Benchmarks/MicroCNN/best_micro_cnn_micro_english.keras | hf-heldout | benign | CLEAN | CLEAN |
| lugan/SynTTS-Commands-Media-Benchmarks/SynTTS-Commands-Benchmarks/MicroCNN/best_micro_cnn_chinese.keras | hf-heldout | benign | CLEAN | CLEAN |
| Devil-Assassin/iVision/complexity_estimation/complexity_estimation_v1.keras | hf-tune | benign | CLEAN | CLEAN |
| Devil-Assassin/iVision/complexity_estimation/complexity_estimation_v3.keras | hf-tune | benign | CLEAN | CLEAN |
| hugocornellier/dog-face-landmarks/keras/localizer_224.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| hugocornellier/dog-face-landmarks/keras/landmarks_mobilenetv3l_384.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| afzal2003/knee-oa-kl-grading/exp1_augmentation.keras | hf-heldout | benign | CLEAN | CLEAN |
| afzal2003/knee-oa-kl-grading/exp3_aug_wider.keras | hf-heldout | benign | CLEAN | CLEAN |
| Jommarn/animal-classification-keras/model_epoch_1.keras | hf-heldout | benign | CLEAN | CLEAN |
| Jommarn/animal-classification-keras/model_epoch_10.keras | hf-heldout | benign | CLEAN | CLEAN |
| Viraine/fruit-ckpts/mobilenet_phase1.keras | hf-heldout | benign | CLEAN | CLEAN |
| Viraine/fruit-ckpts/phase1_best.keras | hf-heldout | benign | CLEAN | CLEAN |
| Diveshj/indian_Grain_Classification/best_LE-CBAM_MobileNetV3Large.keras | hf-tune | benign | CLEAN | CLEAN |
| Diveshj/indian_Grain_Classification/best_MobileNetV3Large.keras | hf-tune | benign | CLEAN | CLEAN |
| abulhawa/industrial-component-anomaly-detection-models/keras_cae/1311f434dab3/model.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| abulhawa/industrial-component-anomaly-detection-models/keras_cae/4142578a023d/model.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ace6868/stock-price-prediction-lstm/keras_model.keras | hf-heldout | benign | CLEAN | CLEAN |
| Ace6868/stock-price-prediction-lstm/AXISBANK.keras | hf-heldout | benign | CLEAN | CLEAN |
| Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold1seed98TH4545.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Higgs32/tornet-ml-higgins/past_models/WRN_PReLU_fold2seed97TH4141.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Reynier/moe-wordlist-dga-models/models/labin/LABin_best_model_2025-05-30_15_26_47.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| rohityadav483/crypto-models/BTC.keras | hf-heldout | benign | CLEAN | CLEAN |
| rohityadav483/crypto-models/BNB.keras | hf-heldout | benign | CLEAN | CLEAN |
| GimhanSathsara843/cataract-classifier/artifacts/best_head.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| GimhanSathsara843/cataract-classifier/artifacts/best_finetune.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Sa3m/CorroVision-AI/best_ResNet50.keras | hf-heldout | benign | CLEAN | CLEAN |
| tulayaka/test-x3/dikkat_patlar.keras | hf-heldout | benign | CLEAN | MALICIOUS |
| tulayaka/test-x3/px.keras | hf-heldout | benign | CLEAN | MALICIOUS |
| FarhanKO/heart-disease-prediction/Custom_CNN_best.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| FarhanKO/heart-disease-prediction/EfficientNetB0_best.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| hugocornellier/cat-face-landmarks/keras/localizer_224.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| hugocornellier/cat-face-landmarks/keras/landmarks_mobilenetv3l_384.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| AmimulBmeIU/BTdiagAI-Alzheimer-models/DenseNet121_CLAHE.keras | hf-heldout | benign | CLEAN | CLEAN |
| IHasFarms/MaliciousModel/custom.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| BrunoBarreto/sdss_dr12_stars_regression/ablations/single_teff/model.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| BrunoBarreto/sdss_dr12_stars_regression/ablations/no_residual_no_layernorm/model.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| klcn16-phishing/KLCN16-LSTM-Phishing-Detection/model_lstm_fasttext.keras | hf-heldout | benign | CLEAN | CLEAN |
| klcn16-phishing/KLCN16-LSTM-Phishing-Detection/model_lstm_glove.keras | hf-heldout | benign | CLEAN | CLEAN |
| cosuleabianca/eea-pm25/lstm_residual/lstm_residual_h1.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| cosuleabianca/eea-pm25/lstm_residual/lstm_residual_h12.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| FarhanKO/kidney-disease-prediction/Custom_CNN_best.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| FarhanKO/kidney-disease-prediction/EfficientNetV2B0_best.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| hemsinath/apex-ai-brain-models/brain_nn.keras | hf-heldout | benign | CLEAN | CLEAN |
| OKTAYBBS/DataScientst-models/deep_learning/fer_model.keras | hf-tune | benign | CLEAN | CLEAN |
| OKTAYBBS/DataScientst-models/deep_learning/pneumonia_model.keras | hf-tune | benign | CLEAN | CLEAN |
| Ritvik19/SudokuNet/ffn__64x2.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ritvik19/SudokuNet/ffn__64x4.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| FarhanKO/lung-disease-prediction/EfficientNetB0_best.keras | hf-heldout | benign | CLEAN | CLEAN |
| FarhanKO/lung-disease-prediction/DenseNet121_best.keras | hf-heldout | benign | CLEAN | CLEAN |
| ericyoc/the_applied_ai_universe_coding_guide/models/lstm_sine.keras | hf-tune | benign | CLEAN | CLEAN |
| ericyoc/the_applied_ai_universe_coding_guide/models/cnn_mnist.keras | hf-tune | benign | CLEAN | CLEAN |
| Nefflymicn/PlantVillage-plant-disease-detection/plant_disease_efficientnet.keras | hf-tune | benign | CLEAN | CLEAN |
| Ambiq/compressionkit-ecg-2x-v1.0/encoder.keras | hf-tune | benign | CLEAN | CLEAN |
| Ambiq/compressionkit-ecg-2x-v1.0/decoder.keras | hf-tune | benign | CLEAN | CLEAN |
| hsuyAAnmol/pcg-models/SSL_models/BiGRU_SSL_final.keras | hf-heldout | benign | CLEAN | CLEAN |
| hsuyAAnmol/pcg-models/BiGRU_PCG_final.keras | hf-heldout | benign | CLEAN | CLEAN |
| leangsuor/latin_to_khmer_transliteration_model/gru_v3_bs64_ed128_ld512/checkpoints/best_encoder_model.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| leangsuor/latin_to_khmer_transliteration_model/gru_v3_bs64_ed128_ld512/checkpoints/encoder_model.01-0.65.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ritberger/cloudsen12-unet-cloud-detection/TFM_Models/Annex_E_UNet_Light_CloudSEN12_7band/runs_v1_1/sym_bce/best.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ritberger/cloudsen12-unet-cloud-detection/TFM_Models/Annex_E_UNet_Light_CloudSEN12_7band/runs_v4/sym_bce/best.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| RohithKoripelli/indian-bank-stock-models-advanced/HDFCBANK/best_model.keras | hf-heldout | benign | CLEAN | CLEAN |
| RohithKoripelli/indian-bank-stock-models-advanced/ICICIBANK/best_model.keras | hf-heldout | benign | CLEAN | CLEAN |
| athifatharmn/keras-duplicate-weights-backdoor-poc/models/image_backdoor_duplicate_weights_trigger.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| athifatharmn/keras-duplicate-weights-backdoor-poc/cnn_image_backdoor_duplicate_weights_trigger.keras | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Ambiq/compressionkit-ppg-4x-v1.0/encoder.keras | hf-tune | benign | CLEAN | CLEAN |
| Ambiq/compressionkit-ppg-4x-v1.0/decoder.keras | hf-tune | benign | CLEAN | CLEAN |
| Ambiq/compressionkit-ppg-2x-v1.0/encoder.keras | hf-heldout | benign | CLEAN | CLEAN |
| Ambiq/compressionkit-ppg-2x-v1.0/decoder.keras | hf-heldout | benign | CLEAN | CLEAN |
| Senu-12/fruit-freshness-classifier/mobilenet/mobilenet_model.keras | hf-heldout | benign | CLEAN | CLEAN |
| Organic-Battery-Predictor/property-predictor-model/MetaLearner.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Organic-Battery-Predictor/property-predictor-model/MTML_fold_3.keras | hf-tune | benign | CLEAN | SUSPICIOUS |
| Wilso0n/detcut-ia-modelo/modelo_eureka_5_0.keras | hf-heldout | benign | CLEAN | CLEAN |
| ScanMe/test-models/eval_lambda.h5 | hf-tune | benign | CLEAN | MALICIOUS |
| jonyyd/howest-hf-ai/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Hiradinho/howest-hf-ai/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| gaurangdave/mnist_cnn/exp_no_data_augmentation_functional.h5 | hf-tune | benign | CLEAN | CLEAN |
| gaurangdave/mnist_cnn/exp_model_version_1.h5 | hf-tune | benign | CLEAN | CLEAN |
| wiki-virus/hyperspectral-image-classification-using-modern-architectures-and-frameworks/my_model.h5 | hf-tune | benign | CLEAN | CLEAN |
| wiki-virus/hyperspectral-image-classification-using-modern-architectures-and-frameworks/best_maml_cnn_weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| rohityadav483/crypto-models/BTC.h5 | hf-heldout | benign | CLEAN | CLEAN |
| rohityadav483/crypto-models/ADA.h5 | hf-heldout | benign | CLEAN | CLEAN |
| IHasFarms/MaliciousModel/unsafe_model.h5 | hf-heldout | benign | CLEAN | MALICIOUS |
| BrunoBarreto/sdss_dr12_stars_regression/ablations/single_teff/best.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| BrunoBarreto/sdss_dr12_stars_regression/ablations/no_residual_no_layernorm/best.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| hemsinath/apex-ai-brain-models/brain_patchtst.h5 | hf-heldout | benign | CLEAN | CLEAN |
| leangsuor/latin_to_khmer_transliteration_model/gru_v3_bs64_ed128_ld512/checkpoints/best_weights.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| leangsuor/latin_to_khmer_transliteration_model/gru_v3_bs64_ed128_ld512/checkpoints/weights.01-0.65.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/mobilenetv4_conv_small_e2400_r224_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| Austin207/voice-fan-controller-model/pretrain/dscnn_fan_advinv_max.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Austin207/voice-fan-controller-model/pretrain/dscnn_fan_scv2.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/mit_b1_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/dfine-small/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/res2net50_48w_2s_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| maia2000/mobilenet-food-binary/model.h5 | hf-heldout | benign | CLEAN | CLEAN |
| SynthAIzer/gender-classification/gender_classification_model.h5 | hf-tune | benign | CLEAN | CLEAN |
| Darshan764/waste-classification-v2/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/dinov2-small/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/convmixer_1024_20_ks9_p14_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/efficientdet_d0/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeahub/ultrapips-tusa/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/dino-resnet50/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/dinov3-vits16-pretrain-lvd1689m/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| onuion/onuion/onuion.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| onuion/onuion/onuion_10k.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| btehubsolutions/alertdrive-model/alertdrive_finetuned_model.h5 | hf-heldout | benign | CLEAN | CLEAN |
| alkhrzmy/ElasticNetLSTM-Sucorinvest-SaveRaja4/lstm_model.h5 | hf-tune | benign | CLEAN | CLEAN |
| Finisha-LLM/Musica2/musica2_weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/dfine-nano/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| qwertymaninwork/Plant_Disease_Detection_System/model.h5 | hf-tune | benign | CLEAN | CLEAN |
| qwertymaninwork/Plant_Disease_Detection_System/mobilenetv2_plant.h5 | hf-tune | benign | CLEAN | SUSPICIOUS |
| Ahyeonn/skinscan-models/project_dl_model_optimized_2.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Ahyeonn/skinscan-models/project_dl_model_mobilenetv2.h5 | hf-heldout | benign | CLEAN | CLEAN |
| kshitiz14/gesture_recogination/dog_emotion.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| kshitiz14/gesture_recogination/emotion_model.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/dino-vits8/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| WillNuyen228/auramask-marker/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| keras/densenet_121_imagenet/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| keras/densenet_121_imagenet/task.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/depth_anything_small/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| WillNuyen228/auramask-comic/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/dfine-medium/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| hadoozy/howest-ai-animal-classification/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| OpenLab-NLP/Experiments-and-others/intent_classifier.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| OpenLab-NLP/Experiments-and-others/InteractGPT.weights-2.h5 | hf-tune | benign | CLEAN | CLEAN |
| SkyYorker/best_weights/model_weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| SkyYorker/best_weights/model_weights.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| Diveshj/thyroid_models/thyroid_cancer_model.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| shifa-ds/brain-breast/cnn+tranformer.h5 | hf-heldout | benign | CLEAN | CLEAN |
| shifa-ds/brain-breast/baseline_cnn.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Delower/Affinity_PPI/weights_best.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Delower/Affinity_PPI/weights_last.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| RChhipa/brain-breast/trig_model.h5 | hf-tune | benign | CLEAN | SUSPICIOUS |
| RChhipa/brain-breast/baseline_cnn.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/inception_v3_gluon_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| hfscanner/model/lambda_attack.h5 | hf-heldout | benign | CLEAN | MALICIOUS |
| hfscanner/model/lambda_benign.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| saishshinde15/SentimentTensor/sentitensor.h5 | hf-heldout | benign | CLEAN | CLEAN |
| svercoutere/bpmn-compare-0.1.0/bpmn_compare_embedding_model.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| svercoutere/bpmn-compare-0.1.0/bpmn_compare_full_model.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| zeromodels/depth_anything_v2_metric_indoor_small/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| albvol/Cognitive-Security-BERT-Japanese/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| palra47906/Sound_Classification_Model_using_CNN_LSTM/Urbansound8K_CNN+LSTM_29102025.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| laventiliz/neokarir-jobmatch/best_weights_v4.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| laventiliz/neokarir-jobmatch/best_weights_v6.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/all-MiniLM-L6-v2/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/deit_small_distilled_patch16_224_fb_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/vit_small_patch32_224_augreg_in21k_ft_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| laramatt/mlops-2627/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| dmytroyolkin/mlops-lab1/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| alltrue-ai/christina-small-test-malicious-lambda-layer/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| srivarshini0306/brain-breast-cancer-classification/tumor_multiclass_model.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| srivarshini0306/brain-breast-cancer-classification/baseline_cnn.h5 | hf-heldout | benign | CLEAN | CLEAN |
| morefaat69/medical-ai-models/kidney_model1.h5 | hf-heldout | benign | CLEAN | CLEAN |
| morefaat69/medical-ai-models/skin_model.h5 | hf-heldout | benign | CLEAN | CLEAN |
| buildxsomnath/plantDiseaseDetection/plant_disease_model.h5 | hf-heldout | benign | CLEAN | CLEAN |
| miladansari/ProteinBERT_HL/tesst.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/mobilevitv2_100_deeplabv3/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/resmlp_12_224_fb_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| yettycz/checkboxes-detector-model/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| abdo1176/brain-model-test/model.h5 | hf-heldout | benign | CLEAN | CLEAN |
| abdo1176/brain-model-test/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Unearthed/artifact-classifier/weights.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/pit_s_distilled_224_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/res2next50_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/vit_small_patch16_384_augreg_in21k_ft_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/mit_b2_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/mobilevitv2_125_cvnets_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| vasantharan/Multimodal_Hate_Speech_Detection_in_Dravidian_languages/text_models/malayalam_text_model.h5 | hf-tune | benign | CLEAN | CLEAN |
| vasantharan/Multimodal_Hate_Speech_Detection_in_Dravidian_languages/text_models/telugu_text_model.h5 | hf-tune | benign | CLEAN | CLEAN |
| syeda-Rija20/image-detector/image_detector_finetuned.h5 | hf-tune | benign | CLEAN | CLEAN |
| syeda-Rija20/image-detector/image_detector_clean.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/convnextv2_nano_fcmae_ft_in22k_in1k_384/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Matteo25000/howest-hf-ai/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| rmdzav/sugarcane-models/cnn_best_model.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/mobilevit_xxs_deeplabv3/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/depth_anything_v2_small/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/deit3_small_patch16_224_fb_in22k_ft_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| febrifahmi/NoD/mnist_nod.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| febrifahmi/NoD/mnist_nod20.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/electra_small_generator/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| nirajandhakal/book-recommender/models/recommender.h5 | hf-heldout | benign | CLEAN | CLEAN |
| xaitalk/audionet-audiomnist/audionet_audiomnist.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/rtdetr-r18vd/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/mobilevitv2_150_deeplabv3/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/mobilenetv2_050_lamb_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/resnet50_gluon_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/tf_efficientnetv2_b0_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/mobilenetv4_conv_medium_e500_r256_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| anasrz/cora-node-gcn/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| YangYang-Research/web-attack-detection/model.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| zeromodels/mobilevitv2_075_cvnets_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| SevdanurGenc/Brain-MRI-Tumour/onegitimli/mobilenet_v2_0.35_128_no_top.h5 | hf-tune | benign | CLEAN | CLEAN |
| kimhyunwoo/gemma2-ko-dialogue-lora/korean_4_epoch1.lora.h5 | hf-heldout | benign | CLEAN | CLEAN |
| NightCoder007/emotion_resnet50_agfn/old_weights/best_resnet50.h5 | hf-heldout | benign | CLEAN | CLEAN |
| sergiok777/roboadvisor-emociones/modelo_1.h5 | hf-tune | benign | CLEAN | SUSPICIOUS |
| sergiok777/roboadvisor-emociones/modelo_7.h5 | hf-tune | benign | CLEAN | SUSPICIOUS |
| zeromodels/flexivit_small_1200ep_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/inception_next_atto_sail_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/mobilenetv3_large_100_ra4_e3600_r224_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/tf_efficientnet_lite0_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/mobilevit_xxs_cvnets_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/mobilevitv2_175_cvnets_in22k_ft_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/regnet-x-002/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| sumansangeet789/brain-tumor-mri-model/CustomCNN_tuned.h5 | hf-tune | benign | CLEAN | CLEAN |
| sumansangeet789/brain-tumor-mri-model/MobileNetV2_tuned.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/multi-qa-MiniLM-L6-cos-v1/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| ghozyreuski/SentimentAnalysisModel/ann_text_classifier.h5 | hf-heldout | benign | CLEAN | CLEAN |
| kovidritesh/scene-dataset/shoe_cnn/best_model.h5 | hf-tune | benign | CLEAN | SUSPICIOUS |
| kovidritesh/scene-dataset/shoe_cnn/shoe_cnn_20260503_142829.h5 | hf-tune | benign | CLEAN | SUSPICIOUS |
| Sudheer17/XRay-Classifier/model_xray.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Sudheer17/XRay-Classifier/model_pre.h5 | hf-heldout | benign | CLEAN | CLEAN |
| Mazharinmdr/brain-breast/trig_model.h5 | hf-heldout | benign | CLEAN | SUSPICIOUS |
| Mazharinmdr/brain-breast/baseline_cnn.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/deit3_small_patch16_384_fb_in22k_ft_in1k/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/densenet121_tv_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/inception_v3_tf_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/mobilenetv3_large_150d_ra4_e3600_r256_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/tf_efficientnetv2_s_in21k_ft_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/mobilevit_xs_cvnets_in1k/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeahub/openpros-inversion-net/model.weights.h5 | hf-heldout | benign | CLEAN | CLEAN |
| zeromodels/paraphrase-albert-small-v2/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
| zeromodels/paraphrase-MiniLM-L3-v2/model.weights.h5 | hf-tune | benign | CLEAN | CLEAN |
