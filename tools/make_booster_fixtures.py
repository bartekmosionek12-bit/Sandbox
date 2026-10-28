"""Write the small Booster payloads tests/test_boosters.py validates (dev only).

Trains tiny models with the real libraries and stores exactly the bytes each Booster's
``__getstate__`` puts in its pickle: xgboost ``handle`` (UBJSON serialization), lightgbm
``_handle`` (the text model) and CatBoost ``__model`` (CBM). Run it in a virtualenv with
xgboost, lightgbm, catboost and numpy installed:

    python tools/make_booster_fixtures.py tests/fixtures/boosters
"""
from __future__ import annotations

import os
import sys

import numpy as np


def main(out: str) -> None:
    import catboost
    import lightgbm
    import xgboost

    os.makedirs(out, exist_ok=True)
    rng = np.random.default_rng(0)
    x = rng.normal(size=(200, 4))
    y = (x[:, 0] + x[:, 1] > 0).astype(int)
    y3 = (x[:, 0] > 0).astype(int) + (x[:, 1] > 0).astype(int)

    def write(name: str, data) -> None:
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else bytes(data))

    dtrain = xgboost.DMatrix(x, label=y)
    write("xgb.ubj", xgboost.train({"max_depth": 3, "objective": "binary:logistic"}, dtrain, 5)
          .__getstate__()["handle"])
    write("xgb_dart.ubj", xgboost.train({"max_depth": 2, "booster": "dart", "objective": "binary:logistic"},
                                        dtrain, 3).__getstate__()["handle"])
    write("xgb_multi.ubj", xgboost.train({"max_depth": 2, "objective": "multi:softprob", "num_class": 3},
                                         xgboost.DMatrix(x, label=y3), 2).__getstate__()["handle"])
    xc = x.copy()
    xc[:, 3] = rng.integers(0, 5, size=200)
    import pandas as pd

    frame = pd.DataFrame(xc, columns=list("abcd"))
    frame["d"] = frame["d"].astype(int).astype("category")
    write("xgb_cat.ubj", xgboost.train({"max_depth": 3, "tree_method": "hist", "max_cat_to_onehot": 1},
                                       xgboost.DMatrix(frame, label=y, enable_categorical=True), 3)
          .__getstate__()["handle"])

    params = {"verbose": -1, "num_leaves": 7, "min_data_in_leaf": 5}
    write("lgb.txt", lightgbm.train({**params, "objective": "binary"}, lightgbm.Dataset(x, y), 5)
          .__getstate__()["_handle"])
    write("lgb_multi.txt", lightgbm.train({**params, "objective": "multiclass", "num_class": 3},
                                          lightgbm.Dataset(x, y3), 2).__getstate__()["_handle"])
    write("lgb_linear.txt", lightgbm.train({**params, "objective": "regression", "linear_tree": True},
                                           lightgbm.Dataset(x, x[:, 0] * 2.0), 3).__getstate__()["_handle"])
    xi = x.copy()
    xi[:, 3] = rng.integers(0, 6, size=200)
    write("lgb_cat.txt", lightgbm.train({**params, "objective": "binary", "min_data_per_group": 5,
                                         "cat_smooth": 1}, lightgbm.Dataset(xi, (xi[:, 3] > 2).astype(int),
                                                                            categorical_feature=[3]), 3)
          .__getstate__()["_handle"])

    model = catboost.CatBoostClassifier(iterations=5, depth=3, verbose=0, random_seed=0).fit(x, y)
    write("cb.cbm", model.__getstate__()["__model"])
    cats = [[str(int(v))] for v in rng.integers(0, 3, size=200)]
    xo = [list(map(float, row)) + c for row, c in zip(x, cats)]
    onehot = catboost.CatBoostClassifier(iterations=3, depth=2, verbose=0, random_seed=0, one_hot_max_size=10)
    write("cb_onehot.cbm", onehot.fit(xo, y, cat_features=[4]).__getstate__()["__model"])
    # a label the categorical feature decides, so the trees split on its CTR
    ctr = catboost.CatBoostClassifier(iterations=3, depth=2, verbose=0, random_seed=0, one_hot_max_size=1)
    write("cb_ctr.cbm", ctr.fit(xo, [int(c[0] == "1") for c in cats], cat_features=[4]).__getstate__()["__model"])
    print("versions:", xgboost.__version__, lightgbm.__version__, catboost.__version__)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/boosters")
